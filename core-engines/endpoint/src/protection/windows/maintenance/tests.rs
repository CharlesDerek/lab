use super::*;
use std::io::Write;

#[test]
fn maintenance_excludes_first_start_and_each_native_worker_without_a_policy_toggle() {
    let root = tempfile::tempdir().unwrap();
    let endpoint =
        Directory::create_under(&root.path().canonicalize().unwrap(), "private").unwrap();
    let guard = quiescent(endpoint.path()).unwrap();
    let protection = endpoint.directory("protection").unwrap();
    assert!(!protection.path().join("windows").exists());
    assert!(protection.lock("supervisor.lock").is_err());
    assert!(quiescent(endpoint.path()).is_err());
    // Pinned ancestry prevents replacing the namespace to obtain another lock.
    assert!(std::fs::rename(protection.path(), protection.path().with_file_name("moved")).is_err());
    drop(guard);
    let state = protection.directory("windows").unwrap();
    for leaf in ["supervisor.lock", "client.lock", "scratch-worker.lock"] {
        let lease = state.lock(leaf).unwrap();
        assert!(
            quiescent(endpoint.path()).is_err(),
            "live {leaf} must exclude maintenance"
        );
        drop(lease);
        drop(quiescent(endpoint.path()).unwrap());
    }
    let guard = quiescent(endpoint.path()).unwrap();
    for leaf in ["supervisor.lock", "client.lock", "scratch-worker.lock"] {
        assert!(state.lock(leaf).is_err(), "maintenance must retain {leaf}");
    }
    drop(guard);
    drop(quiescent(endpoint.path()).unwrap());
}

#[test]
fn maintenance_preserves_every_unrecovered_namespace_and_tolerates_retired_health() {
    let root = tempfile::tempdir().unwrap();
    let endpoint =
        Directory::create_under(&root.path().canonicalize().unwrap(), "private").unwrap();
    let state = endpoint
        .directory("protection")
        .unwrap()
        .directory("windows")
        .unwrap();
    for leaf in [
        "network",
        "scratch-journal",
        "scratch-runtime",
        "scratch-health",
        "workspaces",
        "runtime",
    ] {
        let directory = state.directory(leaf).unwrap();
        let mut partial = directory.create("interrupted").unwrap();
        partial.write_all(b"retain original evidence").unwrap();
        partial.sync_all().unwrap();
        drop(partial);
        let error = quiescent(endpoint.path()).err().unwrap().to_string();
        assert!(error.contains("still requires recovery"), "{leaf}: {error}");
        assert_eq!(
            std::fs::read(directory.path().join("interrupted")).unwrap(),
            b"retain original evidence"
        );
        directory.remove("interrupted").unwrap();
        drop(quiescent(endpoint.path()).unwrap());
    }
    state
        .write_json("client-health.json", &serde_json::json!({"old":true}))
        .unwrap();
    // An old health snapshot carries no restart/cleanup authority. Worker leases
    // and the retired ownership journals establish maintenance exclusion.
    drop(quiescent(endpoint.path()).unwrap());
    assert!(state.path().join("client-health.json").exists());
}
