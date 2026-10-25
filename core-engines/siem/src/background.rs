//! Shared admission for expensive optional storage work and bounded measurements.
use crate::{
    engine::{Engine, LabResult},
    gateway::secret,
};
use orchestrator::governor::{self, Class, Request, Resources};
use rusqlite::{params, OptionalExtension, Transaction, TransactionBehavior};
use serde::Serialize;
#[derive(Serialize)]
pub struct Measurement {
    pub id: String,
    pub kind: String,
    pub elapsed_us: u64,
    pub cpu_ticks: Option<u64>,
    pub read_bytes: Option<u64>,
    pub write_bytes: Option<u64>,
    pub peak_rss_kib: Option<u64>,
    pub succeeded: bool,
}
#[derive(Default)]
struct Counters {
    cpu: Option<u64>,
    read: Option<u64>,
    write: Option<u64>,
    rss: Option<u64>,
}
fn counters() -> Counters {
    #[cfg(target_os = "linux")]
    {
        fn read(path: &str) -> String {
            use std::io::Read;
            let mut value = String::new();
            if let Ok(file) = std::fs::File::open(path) {
                let _ = file.take(16384).read_to_string(&mut value);
            }
            value
        }
        let stat = read("/proc/self/stat");
        let values: Vec<_> = stat
            .rsplit_once(')')
            .map(|(_, s)| s.split_whitespace().collect())
            .unwrap_or_default();
        let cpu = values
            .get(11)
            .and_then(|v| v.parse::<u64>().ok())
            .zip(values.get(12).and_then(|v| v.parse::<u64>().ok()))
            .map(|(a, b)| a.saturating_add(b));
        fn field(text: &str, name: &str) -> Option<u64> {
            text.lines().find_map(|line| {
                line.strip_prefix(name)
                    .and_then(|s| s.split_whitespace().next()?.parse().ok())
            })
        }
        let io = read("/proc/self/io");
        let status = read("/proc/self/status");
        Counters {
            cpu,
            read: field(&io, "read_bytes:"),
            write: field(&io, "write_bytes:"),
            rss: field(&status, "VmHWM:"),
        }
    }
    #[cfg(not(target_os = "linux"))]
    Counters::default()
}
impl Engine {
    pub(crate) fn reserve_essential_work(
        &self,
        kind: &str,
        now: u64,
    ) -> LabResult<Option<(String, u64)>> {
        let pool: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM metadata WHERE key='background_pool'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(pool) = pool else {
            return Ok(None);
        };
        let id = format!("essential:{kind}:{}", secret()?);
        let lease = governor::reserve(
            &self.connection,
            &Request {
                id: id.clone(),
                pool,
                class: Class::Essential,
                resources: Resources {
                    cpu_millis: 250,
                    memory_mib: 64,
                    io_mib: 8,
                    ..Default::default()
                },
                expires_ms: now.saturating_add(60000),
            },
            now,
        )?;
        Ok(Some((id, lease.generation)))
    }
    pub(crate) fn complete_essential_work(&self, lease: Option<(String, u64)>) -> LabResult<()> {
        if let Some((id, generation)) = lease {
            governor::release(&self.connection, &id, generation)?;
            // These leases never leave their ingestion transaction or execute
            // asynchronously; no worker can later replay their private identity.
            self.connection.execute(
                "DELETE FROM resource_reservations WHERE id=?1 AND generation=?2",
                params![id, generation],
            )?;
        }
        Ok(())
    }
    pub(crate) fn init_background(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS background_measurements(id TEXT PRIMARY KEY,payload TEXT NOT NULL,created_ms INTEGER NOT NULL);")?;
        Ok(())
    }
    pub fn configure_background_pool(&self, pool: &str, now: u64) -> LabResult<()> {
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM resource_pools WHERE name=?1)",
            [pool],
            |r| r.get(0),
        )?;
        if !exists {
            return Err("Register the background resource pool first".into());
        }
        tx.execute("INSERT INTO metadata VALUES('background_pool',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[pool])?;
        self.audit("capacity.background_pool", pool, now)?;
        tx.commit()?;
        Ok(())
    }
    pub(crate) fn with_background_budget<T>(
        &self,
        kind: &str,
        cost: Resources,
        now: u64,
        work: impl FnOnce() -> LabResult<T>,
    ) -> LabResult<T> {
        self.with_job_budget(kind, Class::Batch, cost, now, work)
    }
    pub(crate) fn with_job_budget<T>(
        &self,
        kind: &str,
        class: Class,
        cost: Resources,
        now: u64,
        work: impl FnOnce() -> LabResult<T>,
    ) -> LabResult<T> {
        let pool: Option<String> = self
            .connection
            .query_row(
                "SELECT value FROM metadata WHERE key='background_pool'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        let Some(pool) = pool else {
            return work();
        };
        let id = format!("background:{kind}:{}", secret()?);
        let lease = self.reserve_resources(
            &Request {
                id: id.clone(),
                pool,
                class,
                resources: cost,
                expires_ms: now.saturating_add(60000).min(i64::MAX as u64),
            },
            now,
        )?;
        let before = counters();
        let started = std::time::Instant::now();
        let result = work();
        let elapsed_us = started.elapsed().as_micros().min(u64::MAX as u128) as u64;
        let after = counters();
        let diff = |a: Option<u64>, b: Option<u64>| a.zip(b).map(|(a, b)| b.saturating_sub(a));
        let record = Measurement {
            id: id.clone(),
            kind: kind.into(),
            elapsed_us,
            cpu_ticks: diff(before.cpu, after.cpu),
            read_bytes: diff(before.read, after.read),
            write_bytes: diff(before.write, after.write),
            peak_rss_kib: after.rss,
            succeeded: result.is_ok(),
        };
        let tx = Transaction::new_unchecked(&self.connection, TransactionBehavior::Immediate)?;
        governor::release(&tx, &id, lease.generation)?;
        let payload = serde_json::to_string(&record)?;
        tx.execute(
            "INSERT INTO background_measurements VALUES(?1,?2,?3)",
            params![id, payload, now],
        )?;
        tx.execute("DELETE FROM background_measurements WHERE id NOT IN(SELECT id FROM background_measurements ORDER BY rowid DESC LIMIT 256)",[])?;
        self.audit("capacity.background_finished", &payload, now)?;
        tx.commit()?;
        result
    }
    pub fn background_measurements(&self) -> LabResult<Vec<serde_json::Value>> {
        let raw = self
            .connection
            .prepare("SELECT payload FROM background_measurements ORDER BY rowid DESC LIMIT 256")?
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        raw.iter().map(|s| Ok(serde_json::from_str(s)?)).collect()
    }
}
