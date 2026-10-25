use athernex_siem::{
    engine::Engine,
    signals::{Signal, SignalKind},
};
use orchestrator::governor::{Class, Request, Resources};
const NOW: u64 = 1_800_000_000_000;
#[test]
fn essential_detection_remains_admitted_under_batch_pressure_and_jobs_release_measured_capacity() {
    let mut e = Engine::memory().unwrap();
    let capacity = Resources {
        cpu_millis: 2000,
        memory_mib: 512,
        io_mib: 256,
        ..Default::default()
    };
    let essential = Resources {
        cpu_millis: 1000,
        memory_mib: 128,
        io_mib: 64,
        ..Default::default()
    };
    e.configure_pool("rack", capacity, essential, NOW).unwrap();
    e.configure_background_pool("rack", NOW).unwrap();
    let token = e.create_source("fixture", "api", "", NOW).unwrap().unwrap();
    let cost = Resources {
        cpu_millis: 1000,
        memory_mib: 256,
        io_mib: 128,
        ..Default::default()
    };
    let lease = e
        .reserve_resources(
            &Request {
                id: "batch".into(),
                pool: "rack".into(),
                class: Class::Batch,
                resources: cost,
                expires_ms: NOW + 60000,
            },
            NOW,
        )
        .unwrap();
    assert!(
        e.compact_signals(NOW).is_err(),
        "optional work must wait for its admission budget"
    );
    let mut samples = Vec::new();
    for n in 0..30 {
        let at = NOW + n * 2;
        let principal = format!("user-{n}");
        let signal = |id: String, kind, time| Signal {
            id,
            time_ms: time,
            principal: principal.clone(),
            kind,
            namespace: "test".into(),
            object: "workload".into(),
            object_uid: None,
            source_ip: None,
            user_agent: Some("metadata".repeat(100)),
        };
        let started = std::time::Instant::now();
        e.ingest_signals(
            "fixture",
            &token,
            &[
                signal(format!("s{n}"), SignalKind::SecretRead, at),
                signal(format!("e{n}"), SignalKind::WorkloadExec, at + 1),
            ],
            at + 1,
        )
        .unwrap();
        samples.push(started.elapsed().as_micros());
    }
    assert_eq!(
        e.findings()
            .unwrap()
            .iter()
            .filter(|f| f.rule == "EK-002")
            .count(),
        30
    );
    e.release_resources("batch", lease.generation, NOW + 100)
        .unwrap();
    e.compact_signals(NOW + 101).unwrap();
    let measurements = e.background_measurements().unwrap();
    assert_eq!(measurements.len(), 1);
    assert_eq!(measurements[0]["succeeded"], true);
    assert_eq!(e.resource_pools().unwrap()[0].used, Resources::default());
    samples.sort();
    eprintln!(
        "contended essential detection: median={}us p95={}us max={}us; compaction={}",
        samples[15], samples[28], samples[29], measurements[0]
    );
}
