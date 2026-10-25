//! Repeatable synthetic throughput and storage accounting; reports payload and physical costs separately.
use athernex_siem::{
    codec,
    engine::{Engine, LabResult},
    memory::DAY,
    model::*,
};
use std::time::Instant;
fn main() -> LabResult<()> {
    let count = std::env::args()
        .nth(1)
        .map(|v| v.parse())
        .transpose()?
        .unwrap_or(2000usize)
        .clamp(256, 8000);
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("bench.db");
    let mut e = Engine::open(&path)?;
    let now = 1_800_000_000_000;
    let mut input_json = 0;
    let start = Instant::now();
    for base in (0..count).step_by(256) {
        let batch = (base..(base + 256).min(count))
            .map(|n| InputEvent {
                time_ms: now + n as u64,
                source: "fixture-host".into(),
                subject: "alice".into(),
                object: "203.0.113.5".into(),
                kind: Kind::Network,
                outcome: Outcome::Observe,
                severity: 1,
                bytes: 4096,
                trace: 0,
                idempotency_key: format!("event-{n}"),
                context: None,
            })
            .collect::<Vec<_>>();
        input_json += serde_json::to_vec(&batch)?.len();
        e.ingest(&batch, now + count as u64)?;
    }
    let ingest_ms = start.elapsed().as_secs_f64() * 1000.0;
    e.flush(now + count as u64)?;
    let events = e.events()?;
    let raw: usize = events
        .iter()
        .map(|e| serde_json::to_vec(&e.event).unwrap().len())
        .sum();
    let compact: usize = events.iter().map(|e| codec::encode(&e.event).len()).sum();
    let archive = e.retention()?.archive_bytes;
    let storage = e.snapshot()?;
    let state = e.memory_state()?;
    let start = Instant::now();
    for n in 0..1000 {
        let id = events[n % events.len()].event.id;
        e.reconstruct(id)?;
    }
    let lookup_us = start.elapsed().as_secs_f64() * 1_000_000.0 / 1000.0;
    e.tick(now + 5 * DAY)?;
    let trigger = InputEvent {
        time_ms: now + 5 * DAY,
        source: "fixture-host".into(),
        subject: "alice".into(),
        object: "203.0.113.5".into(),
        kind: Kind::Network,
        outcome: Outcome::Observe,
        severity: 5,
        bytes: 30_000_000,
        trace: 0,
        idempotency_key: "alert".into(),
        context: None,
    };
    let start = Instant::now();
    e.ingest(&[trigger], now + 5 * DAY)?;
    let correlation_ms = start.elapsed().as_secs_f64() * 1000.0;
    println!(
        "{}",
        serde_json::to_string_pretty(
            &serde_json::json!({"events":count,"input_json_bytes":input_json,"ingest_ms":ingest_ms,"events_per_second":count as f64/(ingest_ms/1000.0),"aef1_payload_bytes":compact,"normalized_event_json_bytes":raw,"aef1_reduction_percent":100.0*(1.0-compact as f64/raw as f64),"legacy_archive_bytes":archive,"cas_compressed_payload_bytes":state.object_bytes,"cas_objects":state.objects,"physical_database_bytes":storage.database_bytes,"wal_bytes":storage.wal_bytes,"hot_accounted_bytes":state.hot_bytes,"verified_reconstruction_mean_us":lookup_us,"five_day_correlation_ms":correlation_ms,"promoted_context_events":e.memory_state()?.context.len(),"max_candidates":state.config.max_candidates,"lookup_note":"SQLite B-tree lookup O(log N); bounded query/cache memory. Total references and relationships O(N)."})
        )?
    );
    Ok(())
}
