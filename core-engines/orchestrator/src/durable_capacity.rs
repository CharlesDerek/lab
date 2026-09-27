use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    pub owner: String,
    pub resource: String,
    pub slots: u32,
    pub generation: i64,
    pub created_ms: i64,
    pub expires_ms: i64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Granted(Lease),
    Duplicate(Lease),
    Refused(&'static str),
}

pub struct DurableCapacity {
    connection: Connection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingCommand {
    pub owner: String,
    pub resource: String,
    pub generation: i64,
    pub expires_ms: i64,
    pub payload: String,
}

impl DurableCapacity {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(std::time::Duration::from_secs(5))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
             CREATE TABLE IF NOT EXISTS resources (name TEXT PRIMARY KEY, slots INTEGER NOT NULL CHECK(slots > 0), generation INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS leases (owner TEXT NOT NULL, resource TEXT NOT NULL, slots INTEGER NOT NULL, generation INTEGER NOT NULL, created_ms INTEGER NOT NULL, expires_ms INTEGER NOT NULL, active INTEGER NOT NULL, PRIMARY KEY(owner, resource, generation));
             CREATE INDEX IF NOT EXISTS active_leases ON leases(resource, active, expires_ms);
             CREATE TABLE IF NOT EXISTS command_outbox (owner TEXT NOT NULL, resource TEXT NOT NULL, generation INTEGER NOT NULL, expires_ms INTEGER NOT NULL, payload TEXT NOT NULL, delivered INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(owner, resource, generation));",
        )?;
        Ok(Self { connection })
    }

    pub fn configure(&mut self, resource: &str, slots: u32) -> rusqlite::Result<bool> {
        if !safe_label(resource) || slots == 0 {
            return Ok(false);
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO resources(name, slots) VALUES (?1, ?2)",
            params![resource, slots],
        )?;
        let existing: u32 = tx.query_row(
            "SELECT slots FROM resources WHERE name=?1",
            [resource],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(existing == slots)
    }

    pub fn reserve(
        &mut self,
        owner: &str,
        resource: &str,
        slots: u32,
        now_ms: i64,
        ttl_ms: i64,
    ) -> rusqlite::Result<Decision> {
        self.reserve_inner(owner, resource, slots, now_ms, ttl_ms, false)
    }

    /// Commit admission and its command intent in the same SQLite transaction.
    pub fn reserve_for_publication(
        &mut self,
        owner: &str,
        resource: &str,
        slots: u32,
        now_ms: i64,
        ttl_ms: i64,
    ) -> rusqlite::Result<Decision> {
        self.reserve_inner(owner, resource, slots, now_ms, ttl_ms, true)
    }

    fn reserve_inner(
        &mut self,
        owner: &str,
        resource: &str,
        slots: u32,
        now_ms: i64,
        ttl_ms: i64,
        enqueue: bool,
    ) -> rusqlite::Result<Decision> {
        if !safe_label(owner)
            || !safe_label(resource)
            || slots == 0
            || ttl_ms <= 0
            || now_ms.checked_add(ttl_ms).is_none()
        {
            return Ok(Decision::Refused("invalid_request"));
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let capacity: Option<u32> = tx
            .query_row(
                "SELECT slots FROM resources WHERE name=?1",
                [resource],
                |r| r.get(0),
            )
            .optional()?;
        let Some(capacity) = capacity else {
            return Ok(Decision::Refused("unknown_resource"));
        };
        tx.execute(
            "UPDATE leases SET active=0 WHERE resource=?1 AND active=1 AND expires_ms<=?2",
            params![resource, now_ms],
        )?;
        let existing = tx.query_row("SELECT owner, resource, slots, generation, created_ms, expires_ms FROM leases WHERE owner=?1 AND resource=?2 AND active=1", params![owner, resource], parse_lease).optional()?;
        if let Some(lease) = existing {
            if enqueue && lease.slots == slots {
                enqueue_command(&tx, &lease)?;
            }
            let decision = if lease.slots == slots {
                Decision::Duplicate(lease)
            } else {
                Decision::Refused("conflicting_reservation")
            };
            tx.commit()?;
            return Ok(decision);
        }
        let used: u32 = tx.query_row(
            "SELECT COALESCE(SUM(slots),0) FROM leases WHERE resource=?1 AND active=1",
            [resource],
            |r| r.get(0),
        )?;
        if slots > capacity.saturating_sub(used) {
            tx.commit()?;
            return Ok(Decision::Refused("insufficient_capacity"));
        }
        let generation: i64 = tx.query_row(
            "SELECT generation FROM resources WHERE name=?1",
            [resource],
            |r| r.get(0),
        )?;
        let Some(next) = generation.checked_add(1) else {
            tx.commit()?;
            return Ok(Decision::Refused("generation_exhausted"));
        };
        tx.execute(
            "UPDATE resources SET generation=?2 WHERE name=?1",
            params![resource, next],
        )?;
        let lease = Lease {
            owner: owner.to_owned(),
            resource: resource.to_owned(),
            slots,
            generation: next,
            created_ms: now_ms,
            expires_ms: now_ms + ttl_ms,
        };
        tx.execute("INSERT INTO leases(owner,resource,slots,generation,created_ms,expires_ms,active) VALUES (?1,?2,?3,?4,?5,?6,1)", params![owner, resource, slots, next, now_ms, lease.expires_ms])?;
        if enqueue {
            enqueue_command(&tx, &lease)?;
        }
        tx.commit()?;
        Ok(Decision::Granted(lease))
    }

    pub fn pending_commands(
        &mut self,
        resource: &str,
        now_ms: i64,
    ) -> rusqlite::Result<Vec<PendingCommand>> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "UPDATE command_outbox SET delivered=2 WHERE delivered=0 AND expires_ms<=?1",
            [now_ms],
        )?;
        let result = {
            let mut stmt = tx.prepare("SELECT o.owner,o.resource,o.generation,o.expires_ms,o.payload FROM command_outbox o JOIN leases l ON l.owner=o.owner AND l.resource=o.resource AND l.generation=o.generation WHERE o.delivered=0 AND l.active=1 AND o.resource=?1 ORDER BY o.generation LIMIT 100")?;
            let rows = stmt.query_map([resource], |r| {
                Ok(PendingCommand {
                    owner: r.get(0)?,
                    resource: r.get(1)?,
                    generation: r.get(2)?,
                    expires_ms: r.get(3)?,
                    payload: r.get(4)?,
                })
            })?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        tx.commit()?;
        Ok(result)
    }

    pub fn mark_delivered(&mut self, command: &PendingCommand) -> rusqlite::Result<bool> {
        Ok(self.connection.execute("UPDATE command_outbox SET delivered=1 WHERE owner=?1 AND resource=?2 AND generation=?3 AND delivered=0", params![command.owner,command.resource,command.generation])? == 1)
    }

    pub fn release(
        &mut self,
        owner: &str,
        resource: &str,
        generation: i64,
        now_ms: i64,
    ) -> rusqlite::Result<&'static str> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: Option<(i64, i64)> = tx.query_row("SELECT generation, expires_ms FROM leases WHERE owner=?1 AND resource=?2 AND active=1", params![owner, resource], |r| Ok((r.get(0)?, r.get(1)?))).optional()?;
        let decision = match current {
            Some((actual, _)) if actual != generation => "stale_generation",
            Some((_, expiry)) if expiry <= now_ms => "expired_lease",
            Some(_) => {
                tx.execute(
                    "UPDATE leases SET active=0 WHERE owner=?1 AND resource=?2 AND generation=?3",
                    params![owner, resource, generation],
                )?;
                tx.execute("UPDATE command_outbox SET delivered=2 WHERE owner=?1 AND resource=?2 AND generation=?3 AND delivered=0", params![owner,resource,generation])?;
                "released"
            }
            None => "already_released",
        };
        tx.commit()?;
        Ok(decision)
    }

    pub fn active(&self, resource: &str, now_ms: i64) -> rusqlite::Result<Vec<Lease>> {
        let mut stmt = self.connection.prepare("SELECT owner,resource,slots,generation,created_ms,expires_ms FROM leases WHERE resource=?1 AND active=1 AND expires_ms>?2 ORDER BY generation")?;
        let result = stmt
            .query_map(params![resource, now_ms], parse_lease)?
            .collect();
        result
    }
}

fn enqueue_command(tx: &rusqlite::Transaction<'_>, lease: &Lease) -> rusqlite::Result<()> {
    let payload = serde_json::json!({"schema_version":"athernex.capacity.command.v1","owner":lease.owner,"resource":lease.resource,"slots":lease.slots,"fencing_token":lease.generation,"lease_expires_at_epoch_ms":lease.expires_ms}).to_string();
    tx.execute("INSERT OR IGNORE INTO command_outbox(owner,resource,generation,expires_ms,payload) VALUES (?1,?2,?3,?4,?5)", params![lease.owner,lease.resource,lease.generation,lease.expires_ms,payload])?;
    Ok(())
}

fn safe_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 96
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn parse_lease(row: &rusqlite::Row<'_>) -> rusqlite::Result<Lease> {
    Ok(Lease {
        owner: row.get(0)?,
        resource: row.get(1)?,
        slots: row.get(2)?,
        generation: row.get(3)?,
        created_ms: row.get(4)?,
        expires_ms: row.get(5)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn restart_replay_and_stale_release() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.db");
        let mut first = DurableCapacity::open(&path).unwrap();
        assert!(first.configure("local", 2).unwrap());
        let Decision::Granted(old) = first.reserve("job", "local", 2, 100, 100).unwrap() else {
            panic!()
        };
        drop(first);
        let mut second = DurableCapacity::open(&path).unwrap();
        assert_eq!(
            second.reserve("job", "local", 2, 150, 100).unwrap(),
            Decision::Duplicate(old.clone())
        );
        assert_eq!(
            second.reserve("other", "local", 1, 150, 100).unwrap(),
            Decision::Refused("insufficient_capacity")
        );
        let Decision::Granted(new) = second.reserve("job", "local", 2, 201, 100).unwrap() else {
            panic!()
        };
        assert!(new.generation > old.generation);
        assert_eq!(
            second.release("job", "local", old.generation, 202).unwrap(),
            "stale_generation"
        );
        assert_eq!(
            second.release("job", "local", new.generation, 302).unwrap(),
            "expired_lease"
        );
        assert_eq!(
            second.release("job", "local", new.generation, 250).unwrap(),
            "released"
        );
        assert_eq!(
            second.release("job", "local", new.generation, 250).unwrap(),
            "already_released"
        );
    }

    #[test]
    fn two_connections_share_capacity_and_generations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.db");
        let mut a = DurableCapacity::open(&path).unwrap();
        let mut b = DurableCapacity::open(&path).unwrap();
        a.configure("local", 1).unwrap();
        assert!(matches!(
            a.reserve("a", "local", 1, 10, 100).unwrap(),
            Decision::Granted(_)
        ));
        assert_eq!(
            b.reserve("b", "local", 1, 10, 100).unwrap(),
            Decision::Refused("insufficient_capacity")
        );
        assert_eq!(b.active("local", 10).unwrap().len(), 1);
    }

    #[test]
    fn outbox_survives_restart_and_replay_without_duplicate_command() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.db");
        let mut first = DurableCapacity::open(&path).unwrap();
        first.configure("local", 1).unwrap();
        let Decision::Granted(lease) = first
            .reserve_for_publication("run_1", "local", 1, 100, 1000)
            .unwrap()
        else {
            panic!()
        };
        drop(first);
        let mut recovered = DurableCapacity::open(&path).unwrap();
        assert!(matches!(
            recovered
                .reserve_for_publication("run_1", "local", 1, 150, 1000)
                .unwrap(),
            Decision::Duplicate(_)
        ));
        let pending = recovered.pending_commands("local", 150).unwrap();
        assert_eq!(pending.len(), 1);
        assert!(pending[0]
            .payload
            .contains(&format!("\"fencing_token\":{}", lease.generation)));
        assert!(recovered.mark_delivered(&pending[0]).unwrap());
        assert!(!recovered.mark_delivered(&pending[0]).unwrap());
        assert!(recovered.pending_commands("local", 200).unwrap().is_empty());
    }

    #[test]
    fn released_or_expired_command_is_not_published() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("capacity.db");
        let mut ledger = DurableCapacity::open(&path).unwrap();
        ledger.configure("local", 1).unwrap();
        let Decision::Granted(lease) = ledger
            .reserve_for_publication("run_1", "local", 1, 100, 100)
            .unwrap()
        else {
            panic!()
        };
        assert_eq!(
            ledger
                .release("run_1", "local", lease.generation, 150)
                .unwrap(),
            "released"
        );
        assert!(ledger.pending_commands("local", 150).unwrap().is_empty());
        ledger
            .reserve_for_publication("run_2", "local", 1, 200, 100)
            .unwrap();
        assert!(ledger.pending_commands("local", 301).unwrap().is_empty());
    }
}
