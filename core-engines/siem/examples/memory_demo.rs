//! Deterministic full lifecycle; no live endpoint, credentials, sleeps, or external service.
use athernex_siem::{
    engine::{Engine, LabResult},
    memory::{hex, DAY},
    model::*,
};
fn fact(time: u64, severity: u8, key: &str) -> InputEvent {
    InputEvent {
        time_ms: time,
        source: "offline-endpoint".into(),
        subject: "alice".into(),
        object: "203.0.113.8".into(),
        kind: Kind::Network,
        outcome: Outcome::Observe,
        severity,
        bytes: 1024,
        trace: 42,
        idempotency_key: key.into(),
        context: None,
    }
}
fn main() -> LabResult<()> {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("demo.db");
    let start = 1_800_000_000_000;
    let mut engine = Engine::open(&path)?;
    engine.ingest(&[fact(start, 1, "historical")], start)?;
    let id = engine.events()?[0].event.id;
    let hash = hex(&engine.evidence_hash(id)?);
    println!(
        "INGEST: event {id}, timestamp {start}, hot events {}",
        engine.events()?.len()
    );
    engine.tick(start + 2 * DAY)?;
    assert!(engine.events()?.is_empty());
    println!("DEMOTION at 48 hours: hot=0, persistent SHA-256={hash}");
    drop(engine);
    let mut engine = Engine::open(&path)?;
    println!("RESTART: reference and verified local evidence survived; original endpoint offline");
    engine.ingest(
        &[fact(start + 5 * DAY, 5, "new-detection")],
        start + 5 * DAY,
    )?;
    let state = engine.memory_state()?;
    assert!(state.context.iter().any(|c| c.evidence.event.id == id));
    println!(
        "CORRELATION and AUTOMATIC PROMOTION:\n{}",
        serde_json::to_string_pretty(&state)?
    );
    engine.tick(start + 5 * DAY + state.config.context_ms)?;
    assert!(engine.memory_state()?.context.is_empty());
    assert_eq!(engine.reconstruct(id)?.event.time_ms, start);
    println!("CACHE EXPIRATION: context=0; historical evidence still verifies, original timestamp unchanged");
    Ok(())
}
