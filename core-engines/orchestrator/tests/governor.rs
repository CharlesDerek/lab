use orchestrator::{
    durable_capacity::{Decision, DurableCapacity},
    governor::{self as g, Class, Request, Resources},
};
use rusqlite::{Connection, TransactionBehavior};

fn capacity() -> Resources {
    Resources {
        cpu_millis: 4000,
        memory_mib: 8192,
        io_mib: 100,
        gpu_millis: 1000,
        tokens: 10000,
        power_watts: 200,
    }
}
fn request(id: &str) -> Request {
    Request {
        id: id.into(),
        pool: "node-a".into(),
        class: Class::Batch,
        resources: Resources {
            cpu_millis: 1000,
            memory_mib: 1000,
            ..Default::default()
        },
        expires_ms: 10000,
    }
}
fn open(path: &std::path::Path) -> Connection {
    let db = Connection::open(path).unwrap();
    db.busy_timeout(std::time::Duration::from_secs(5)).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL;PRAGMA foreign_keys=ON;")
        .unwrap();
    g::initialize(&db).unwrap();
    db
}
#[test]
fn reserved_essential_capacity_and_each_dimension_are_enforced() {
    let mut db = Connection::open_in_memory().unwrap();
    g::initialize(&db).unwrap();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::configure(
        &tx,
        "node-a",
        capacity(),
        Resources {
            cpu_millis: 1000,
            memory_mib: 1024,
            ..Default::default()
        },
    )
    .unwrap();
    let mut first = request("large");
    first.resources.cpu_millis = 3000;
    g::reserve(&tx, &first, 1).unwrap();
    assert!(g::reserve(&tx, &request("optional"), 1).is_err());
    let mut essential = request("collector");
    essential.class = Class::Essential;
    g::reserve(&tx, &essential, 1).unwrap();
    for resources in [
        Resources {
            cpu_millis: 1,
            ..Default::default()
        },
        Resources {
            memory_mib: 8193,
            ..Default::default()
        },
        Resources {
            io_mib: 101,
            ..Default::default()
        },
        Resources {
            gpu_millis: 1001,
            ..Default::default()
        },
        Resources {
            tokens: 10001,
            ..Default::default()
        },
        Resources {
            power_watts: 201,
            ..Default::default()
        },
    ] {
        let mut excess = request("overflow");
        excess.class = Class::Essential;
        excess.resources = resources;
        assert!(g::reserve(&tx, &excess, 1).is_err());
    }
    tx.commit().unwrap();
}
#[test]
fn expiry_fences_dispatch_without_reclaiming_live_worker_capacity() {
    let mut db = Connection::open_in_memory().unwrap();
    g::initialize(&db).unwrap();
    let mut first = request("worker");
    first.resources = capacity();
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::configure(&tx, "node-a", capacity(), Resources::default()).unwrap();
    let r = g::reserve(&tx, &first, 1).unwrap();
    assert_eq!(g::reserve(&tx, &first, 2).unwrap().generation, r.generation);
    assert!(g::authorize(&tx, &first.id, r.generation, 10001).is_err());
    let mut later = request("later");
    later.expires_ms = 20000;
    assert!(g::reserve(&tx, &later, 10001).is_err());
    assert!(g::release(&tx, &first.id, r.generation + 1).is_err());
    g::release(&tx, &first.id, r.generation).unwrap();
    assert!(g::reserve(&tx, &first, 2).is_err());
    assert!(g::reserve(&tx, &later, 10001).unwrap().generation > r.generation);
    tx.commit().unwrap();
}
#[test]
fn concurrent_process_connections_cannot_overcommit_and_restart_preserves_hold() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capacity.db");
    let mut db = open(&path);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::configure(&tx, "node-a", request("x").resources, Resources::default()).unwrap();
    tx.commit().unwrap();
    drop(db);
    let handles: Vec<_> = (0..4)
        .map(|i| {
            let path = path.clone();
            std::thread::spawn(move || {
                let mut db = open(&path);
                let tx = db
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let admitted = g::reserve(&tx, &request(&format!("worker-{i}")), 1).is_ok();
                tx.commit().unwrap();
                admitted
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .filter_map(|h| h.join().unwrap().then_some(()))
            .count(),
        1
    );
    let mut legacy = DurableCapacity::open(&path).unwrap();
    assert!(legacy.configure("node-a", 4).unwrap());
    let mut db = open(&path);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::hold(&tx, "node-a", "incident-1", 2).unwrap();
    tx.commit().unwrap();
    drop(db);
    assert_eq!(
        legacy
            .reserve_for_publication("legacy", "node-a", 1, 3, 1000)
            .unwrap(),
        Decision::Refused("security_placement_hold")
    );
    assert_eq!(g::pools(&open(&path)).unwrap()[0].holds, vec!["incident-1"]);
}

#[test]
fn scheduler_slots_share_governor_capacity_and_do_not_reclaim_unfinished_workers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let mut db = open(&path);
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    let cost = Resources {
        cpu_millis: 1000,
        memory_mib: 128,
        io_mib: 16,
        gpu_millis: 100,
        tokens: 1000,
        power_watts: 30,
    };
    g::configure(&tx, "rack", cost, Resources::default()).unwrap();
    tx.commit().unwrap();
    let mut scheduler = DurableCapacity::open(&path).unwrap();
    scheduler.configure("workers", 10).unwrap();
    scheduler.bind_budget("workers", "rack", cost).unwrap();
    let Decision::Granted(lease) = scheduler
        .reserve_for_publication("worker", "workers", 1, 1, 1000)
        .unwrap()
    else {
        panic!("admission refused")
    };
    assert!(scheduler
        .authorize("worker", "workers", lease.generation, 2)
        .unwrap());
    let payload = serde_json::from_str::<serde_json::Value>(
        &scheduler.pending_commands("workers", 2).unwrap()[0].payload,
    )
    .unwrap();
    assert!(payload["resource_reservation"]["generation"]
        .as_u64()
        .is_some());
    assert_eq!(
        scheduler.reserve("other", "workers", 1, 2, 1000).unwrap(),
        Decision::Refused("shared_resource_budget_held")
    );
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::hold(&tx, "rack", "incident", 3).unwrap();
    tx.commit().unwrap();
    assert!(scheduler.pending_commands("workers", 4).unwrap().is_empty());
    assert!(!scheduler
        .authorize("worker", "workers", lease.generation, 4)
        .unwrap());
    let tx = db
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .unwrap();
    g::clear_hold(&tx, "rack", "incident").unwrap();
    tx.commit().unwrap();
    assert_eq!(
        scheduler
            .reserve("worker", "workers", 1, 1002, 1000)
            .unwrap(),
        Decision::Refused("expired_worker_requires_completion")
    );
    assert_eq!(scheduler.active("workers", 1002).unwrap().len(), 1);
    assert!(!scheduler
        .authorize("worker", "workers", lease.generation, 1002)
        .unwrap());
    assert_eq!(
        scheduler
            .reserve("other", "workers", 1, 1002, 1000)
            .unwrap(),
        Decision::Refused("shared_resource_budget_held")
    );
    assert_eq!(
        scheduler
            .release("worker", "workers", lease.generation, 1002)
            .unwrap(),
        "released"
    );
    assert_eq!(g::pools(&db).unwrap()[0].used, Resources::default());
    assert!(matches!(
        scheduler
            .reserve("other", "workers", 1, 1003, 1000)
            .unwrap(),
        Decision::Granted(_)
    ));
}
