//! Transactional admission shared by security responses and workload scheduling.
//! Reservations are admission contracts, not OS resource limits. Executors must
//! enforce deadlines and stop work before releasing its reservation.
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};

pub type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Resources {
    pub cpu_millis: u64,
    pub memory_mib: u64,
    pub io_mib: u64,
    pub gpu_millis: u64,
    pub tokens: u64,
    pub power_watts: u64,
}
impl Resources {
    fn values(self) -> [u64; 6] {
        [
            self.cpu_millis,
            self.memory_mib,
            self.io_mib,
            self.gpu_millis,
            self.tokens,
            self.power_watts,
        ]
    }
    pub(crate) fn valid(self) -> bool {
        self.values().iter().all(|v| *v <= 1_000_000_000)
    }
    fn fits(self, other: Self) -> bool {
        self.values()
            .iter()
            .zip(other.values())
            .all(|(a, b)| *a <= b)
    }
    fn add(&mut self, other: Self) {
        self.cpu_millis += other.cpu_millis;
        self.memory_mib += other.memory_mib;
        self.io_mib += other.io_mib;
        self.gpu_millis += other.gpu_millis;
        self.tokens += other.tokens;
        self.power_watts += other.power_watts;
    }
    fn subtract(self, other: Self) -> Self {
        Self {
            cpu_millis: self.cpu_millis.saturating_sub(other.cpu_millis),
            memory_mib: self.memory_mib.saturating_sub(other.memory_mib),
            io_mib: self.io_mib.saturating_sub(other.io_mib),
            gpu_millis: self.gpu_millis.saturating_sub(other.gpu_millis),
            tokens: self.tokens.saturating_sub(other.tokens),
            power_watts: self.power_watts.saturating_sub(other.power_watts),
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Class {
    Essential,
    Response,
    Batch,
    Model,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub id: String,
    pub pool: String,
    pub class: Class,
    pub resources: Resources,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reservation {
    pub request: Request,
    pub generation: u64,
    pub state: String,
}
#[derive(Serialize)]
pub struct Pool {
    pub name: String,
    pub capacity: Resources,
    pub essential_reserve: Resources,
    pub used: Resources,
    pub holds: Vec<String>,
}
pub fn label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}
pub fn initialize(db: &Connection) -> Result<()> {
    db.execute_batch("CREATE TABLE IF NOT EXISTS resource_pools(name TEXT PRIMARY KEY,capacity TEXT NOT NULL,reserve TEXT NOT NULL,generation INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS resource_reservations(id TEXT PRIMARY KEY,pool TEXT NOT NULL REFERENCES resource_pools(name),request TEXT NOT NULL,generation INTEGER NOT NULL,expires_ms INTEGER NOT NULL,state TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS resource_active ON resource_reservations(pool,state,expires_ms);
      CREATE TABLE IF NOT EXISTS placement_holds(pool TEXT NOT NULL,incident TEXT NOT NULL,created_ms INTEGER NOT NULL,PRIMARY KEY(pool,incident));")?;
    Ok(())
}
fn transaction(db: &Connection) -> Result<()> {
    if db.is_autocommit() {
        return Err("Admission mutation requires an immediate transaction".into());
    }
    Ok(())
}
pub fn configure(
    db: &Connection,
    pool: &str,
    capacity: Resources,
    reserve: Resources,
) -> Result<()> {
    transaction(db)?;
    if !label(pool)
        || !capacity.valid()
        || capacity == Resources::default()
        || !reserve.fits(capacity)
    {
        return Err("Invalid resource pool".into());
    }
    let count: u64 = db.query_row("SELECT count(*) FROM resource_pools", [], |r| r.get(0))?;
    if count >= 256 {
        return Err("Resource pool capacity reached".into());
    }
    db.execute(
        "INSERT OR IGNORE INTO resource_pools(name,capacity,reserve) VALUES(?1,?2,?3)",
        params![
            pool,
            serde_json::to_string(&capacity)?,
            serde_json::to_string(&reserve)?
        ],
    )?;
    let (a, b): (String, String) = db.query_row(
        "SELECT capacity,reserve FROM resource_pools WHERE name=?1",
        [pool],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if serde_json::from_str::<Resources>(&a)? != capacity
        || serde_json::from_str::<Resources>(&b)? != reserve
    {
        return Err("Pool configuration conflicts with its existing contract".into());
    }
    Ok(())
}
pub fn held(db: &Connection, pool: &str) -> Result<bool> {
    Ok(db.query_row(
        "SELECT EXISTS(SELECT 1 FROM placement_holds WHERE pool=?1)",
        [pool],
        |r| r.get(0),
    )?)
}
pub fn hold(db: &Connection, pool: &str, incident: &str, now: u64) -> Result<()> {
    transaction(db)?;
    if !label(pool) || !label(incident) || now > i64::MAX as u64 {
        return Err("Invalid placement hold".into());
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM resource_pools WHERE name=?1)",
        [pool],
        |r| r.get(0),
    )?;
    if !exists {
        return Err("Unknown affected resource pool".into());
    }
    let count: u64 = db.query_row("SELECT count(*) FROM placement_holds", [], |r| r.get(0))?;
    if count >= 4096 {
        return Err("Placement hold capacity reached".into());
    }
    db.execute(
        "INSERT OR IGNORE INTO placement_holds VALUES(?1,?2,?3)",
        params![pool, incident, now],
    )?;
    Ok(())
}
pub fn clear_hold(db: &Connection, pool: &str, incident: &str) -> Result<()> {
    transaction(db)?;
    db.execute(
        "DELETE FROM placement_holds WHERE pool=?1 AND incident=?2",
        params![pool, incident],
    )?;
    Ok(())
}
pub fn lookup(db: &Connection, id: &str) -> Result<Option<Reservation>> {
    let row: Option<(String, u64, String)> = db
        .query_row(
            "SELECT request,generation,state FROM resource_reservations WHERE id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    row.map(|(raw, generation, state)| {
        Ok(Reservation {
            request: serde_json::from_str(&raw)?,
            generation,
            state,
        })
    })
    .transpose()
}
pub fn reserve(db: &Connection, request: &Request, now: u64) -> Result<Reservation> {
    transaction(db)?;
    if !label(&request.id)
        || !label(&request.pool)
        || !request.resources.valid()
        || request.resources == Resources::default()
        || now > i64::MAX as u64
        || request.expires_ms <= now
        || request.expires_ms > now.saturating_add(3_600_000).min(i64::MAX as u64)
    {
        return Err("Invalid resource reservation or deadline".into());
    }
    if held(db, &request.pool)? {
        return Err("Placement held by an unresolved incident".into());
    }
    if let Some(previous) = lookup(db, &request.id)? {
        if previous.request != *request || previous.state != "active" {
            return Err("Reservation identity conflicts or is terminal".into());
        }
        return Ok(previous);
    }
    let count: u64 = db.query_row("SELECT count(*) FROM resource_reservations", [], |r| {
        r.get(0)
    })?;
    if count >= 16384 {
        return Err("Reservation history capacity reached; export and rotate the ledger".into());
    }
    let (capacity, reserve, generation): (String, String, u64) = db.query_row(
        "SELECT capacity,reserve,generation FROM resource_pools WHERE name=?1",
        [&request.pool],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    let capacity: Resources = serde_json::from_str(&capacity)?;
    let protected: Resources = serde_json::from_str(&reserve)?;
    // Expiry prevents dispatch but never silently frees resources still owned by
    // a worker. Explicit completion/cancellation acknowledgement releases them.
    let mut total = Resources::default();
    let mut optional = Resources::default();
    let rows = db
        .prepare("SELECT request FROM resource_reservations WHERE pool=?1 AND state='active'")?
        .query_map([&request.pool], |r| r.get::<_, String>(0))?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for row in rows {
        let other: Request = serde_json::from_str(&row)?;
        total.add(other.resources);
        if other.class != Class::Essential {
            optional.add(other.resources);
        }
    }
    total.add(request.resources);
    if !total.fits(capacity) {
        return Err("Insufficient shared resource capacity".into());
    }
    if request.class != Class::Essential {
        optional.add(request.resources);
        if !optional.fits(capacity.subtract(protected)) {
            return Err("Essential collection reserve is protected".into());
        }
    }
    let generation = generation
        .checked_add(1)
        .filter(|g| *g <= i64::MAX as u64)
        .ok_or("Generation exhausted")?;
    db.execute(
        "UPDATE resource_pools SET generation=?2 WHERE name=?1",
        params![request.pool, generation],
    )?;
    db.execute(
        "INSERT INTO resource_reservations VALUES(?1,?2,?3,?4,?5,'active')",
        params![
            request.id,
            request.pool,
            serde_json::to_string(request)?,
            generation,
            request.expires_ms
        ],
    )?;
    Ok(Reservation {
        request: request.clone(),
        generation,
        state: "active".into(),
    })
}
pub fn authorize(db: &Connection, id: &str, generation: u64, now: u64) -> Result<Reservation> {
    let r = lookup(db, id)?.ok_or("Unknown reservation")?;
    if r.generation != generation
        || r.state != "active"
        || r.request.expires_ms <= now
        || held(db, &r.request.pool)?
    {
        return Err("Expired, fenced or held reservation".into());
    }
    Ok(r)
}
pub fn release(db: &Connection, id: &str, generation: u64) -> Result<()> {
    transaction(db)?;
    let r = lookup(db, id)?.ok_or("Unknown reservation")?;
    if r.generation != generation {
        return Err("Stale reservation generation".into());
    }
    db.execute(
        "UPDATE resource_reservations SET state='released' WHERE id=?1 AND generation=?2",
        params![id, generation],
    )?;
    Ok(())
}
pub fn pools(db: &Connection) -> Result<Vec<Pool>> {
    let rows = db
        .prepare("SELECT name,capacity,reserve FROM resource_pools ORDER BY name")?
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    rows.into_iter()
        .map(|(name, a, b)| {
            let mut used = Resources::default();
            for row in db
                .prepare(
                    "SELECT request FROM resource_reservations WHERE pool=?1 AND state='active'",
                )?
                .query_map([&name], |r| r.get::<_, String>(0))?
            {
                used.add(serde_json::from_str::<Request>(&row?)?.resources);
            }
            let holds = db
                .prepare("SELECT incident FROM placement_holds WHERE pool=?1 ORDER BY incident")?
                .query_map([&name], |r| r.get::<_, String>(0))?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            Ok(Pool {
                name,
                capacity: serde_json::from_str(&a)?,
                essential_reserve: serde_json::from_str(&b)?,
                used,
                holds,
            })
        })
        .collect()
}
