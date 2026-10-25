//! Supplementary evidence over mutually authenticated TLS. Certificate identities are
//! bound to existing task capabilities; an independent central digest verifies content.
use crate::{
    engine::{Engine, LabResult},
    gateway,
    memory::{self, Relevance, MAX_OBJECT},
    model::now_ms,
};
use rusqlite::params;
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{watch, Semaphore},
    time::timeout,
};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
    },
    TlsAcceptor, TlsConnector,
};
const WIRE_LIMIT: usize = 256 * 1024;
const TIMEOUT: Duration = Duration::from_secs(3);

#[derive(Clone, Serialize, Deserialize)]
pub struct EvidenceLocation {
    pub event_id: u64,
    pub agent_id: i64,
    pub address: SocketAddr,
    pub server_name: String,
    pub cert_hash: String,
    // Secret is deliberately excluded from Debug and API responses.
    pub token: String,
}
#[derive(Serialize, Deserialize)]
struct Request {
    event_id: u64,
    token: String,
}
#[derive(Serialize, Deserialize)]
struct Reply {
    bundle: Option<Vec<Vec<u8>>>,
    error: Option<String>,
}

pub fn certificates(path: &std::path::Path) -> LabResult<Vec<CertificateDer<'static>>> {
    Ok(CertificateDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?)
}
pub fn private_key(path: &std::path::Path) -> LabResult<PrivateKeyDer<'static>> {
    Ok(PrivateKeyDer::from_pem_file(path)?)
}
pub fn root_store(certs: Vec<CertificateDer<'static>>) -> LabResult<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    for cert in certs {
        roots.add(cert)?;
    }
    Ok(roots)
}
pub fn server_config(
    roots: rustls::RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> LabResult<Arc<rustls::ServerConfig>> {
    let verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots)).build()?;
    Ok(Arc::new(
        rustls::ServerConfig::builder()
            .with_client_cert_verifier(verifier)
            .with_single_cert(chain, key)?,
    ))
}
pub fn client_config(
    roots: rustls::RootCertStore,
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> LabResult<Arc<rustls::ClientConfig>> {
    Ok(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_client_auth_cert(chain, key)?,
    ))
}
async fn write_frame<W: AsyncWrite + Unpin, T: Serialize>(
    stream: &mut W,
    value: &T,
) -> LabResult<()> {
    let raw = serde_json::to_vec(value)?;
    if raw.len() > WIRE_LIMIT {
        return Err("Evidence wire budget exceeded".into());
    }
    stream.write_u32(raw.len() as u32).await?;
    stream.write_all(&raw).await?;
    stream.flush().await?;
    Ok(())
}
async fn read_frame<R: AsyncRead + Unpin, T: serde::de::DeserializeOwned>(
    stream: &mut R,
) -> LabResult<T> {
    let length = stream.read_u32().await? as usize;
    if length > WIRE_LIMIT {
        return Err("Evidence wire budget exceeded".into());
    }
    let mut raw = vec![0; length];
    stream.read_exact(&mut raw).await?;
    Ok(serde_json::from_slice(&raw)?)
}

impl Engine {
    pub(crate) fn init_evidence_transport(&self) -> LabResult<()> {
        self.connection.execute_batch("CREATE TABLE IF NOT EXISTS agent_certificates(agent_id INTEGER PRIMARY KEY REFERENCES agents(id),fingerprint TEXT UNIQUE NOT NULL);")?;
        Ok(())
    }
    pub fn bind_agent_certificate(&self, agent: i64, fingerprint: &str, now: u64) -> LabResult<()> {
        let fingerprint = memory::hex(&memory::unhex(fingerprint)?);
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        self.connection.execute("INSERT INTO agent_certificates VALUES(?1,?2) ON CONFLICT(agent_id) DO UPDATE SET fingerprint=excluded.fingerprint",params![agent,fingerprint])?;
        self.audit(
            "agent.certificate-bound",
            &format!("agent-{agent} / {fingerprint}"),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn add_evidence_location(&self, location: &EvidenceLocation, now: u64) -> LabResult<()> {
        memory::unhex(&location.cert_hash)?;
        ServerName::try_from(location.server_name.clone())?;
        if location.token.len() != 64 || location.server_name.len() > 253 {
            return Err("Invalid evidence location".into());
        }
        let tx = rusqlite::Transaction::new_unchecked(
            &self.connection,
            rusqlite::TransactionBehavior::Immediate,
        )?;
        let count: usize = self.connection.query_row(
            "SELECT count(*) FROM evidence_locations WHERE event_id=?1 AND agent_id<>?2",
            params![location.event_id, location.agent_id],
            |r| r.get(0),
        )?;
        if count >= 2 {
            return Err("At most two remote evidence locations per event".into());
        }
        self.connection.execute("INSERT INTO evidence_locations VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(event_id,agent_id) DO UPDATE SET address=excluded.address,server_name=excluded.server_name,cert_hash=excluded.cert_hash,token=excluded.token",params![location.event_id,location.agent_id,location.address.to_string(),location.server_name,location.cert_hash.to_lowercase(),location.token])?;
        self.audit(
            "evidence.location-registered",
            &format!("event-{} / agent-{}", location.event_id, location.agent_id),
            now,
        )?;
        tx.commit()?;
        Ok(())
    }
    fn locations(&self, id: u64) -> LabResult<Vec<EvidenceLocation>> {
        let rows=self.connection.prepare("SELECT l.agent_id,l.address,l.server_name,l.cert_hash,l.token FROM evidence_locations l JOIN agents a ON a.id=l.agent_id WHERE l.event_id=?1 AND a.state='active' LIMIT 2")?.query_map([id],|r|Ok((r.get::<_,i64>(0)?,r.get::<_,String>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?)))?.collect::<Result<Vec<_>,_>>()?;
        rows.into_iter()
            .map(|(agent_id, address, server_name, cert_hash, token)| {
                Ok(EvidenceLocation {
                    event_id: id,
                    agent_id,
                    address: address.parse()?,
                    server_name,
                    cert_hash,
                    token,
                })
            })
            .collect()
    }
    fn serve_evidence(
        &mut self,
        peer: &str,
        request: Request,
        now: u64,
    ) -> LabResult<Vec<Vec<u8>>> {
        let requests: u64 = self.connection.query_row(
            "SELECT count(*) FROM evidence_retrieval_audit WHERE location=?1 AND time_ms>=?2",
            params![peer, now.saturating_sub(60_000)],
            |r| r.get(0),
        )?;
        if requests >= 32 {
            if requests == 32 {
                self.retrieval_audit(request.event_id, peer, "rate_limited", now)?;
            }
            return Err("Evidence retrieval rate limit".into());
        }
        if request.token.len() != 64 {
            self.retrieval_audit(request.event_id, peer, "invalid_capability", now)?;
            return Err("Invalid capability".into());
        }
        let bound:bool=self.connection.query_row("SELECT EXISTS(SELECT 1 FROM grants g JOIN agent_tasks t ON t.id=g.task_id JOIN agent_certificates c ON c.agent_id=t.agent_id WHERE g.token_hash=?1 AND c.fingerprint=?2)",params![gateway::digest(&request.token),peer],|r|r.get(0))?;
        if !bound {
            self.retrieval_audit(request.event_id, peer, "identity_denied", now)?;
            return Err("Certificate identity does not own capability".into());
        }
        let decision = self.access(
            &request.token,
            &format!("event-{}", request.event_id),
            "read",
            None,
            now,
        )?;
        self.retrieval_audit(
            request.event_id,
            peer,
            if decision.allowed {
                "authorized"
            } else {
                "scope_denied"
            },
            now,
        )?;
        if !decision.allowed {
            return Err("Evidence capability denied".into());
        }
        let bundle = self.evidence_bundle(request.event_id)?;
        self.retrieval_audit(request.event_id, peer, "verified_served", now)?;
        Ok(bundle)
    }
    fn remote_budget(&self, id: u64, now: u64) -> LabResult<()> {
        let count:u64=self.connection.query_row("SELECT count(*) FROM evidence_retrieval_audit WHERE location='remote' AND outcome='attempt' AND time_ms>=?1",[now.saturating_sub(60_000)],|r|r.get(0))?;
        if count >= 16 {
            return Err("Remote retrieval budget exhausted".into());
        }
        self.retrieval_audit(id, "remote", "attempt", now)
    }
    pub fn retrieval_audits(&self) -> LabResult<Vec<serde_json::Value>> {
        Ok(self.connection.prepare("SELECT time_ms,event_id,location,outcome FROM evidence_retrieval_audit ORDER BY id DESC LIMIT 128")?.query_map([],|r|Ok(serde_json::json!({"time_ms":r.get::<_,u64>(0)?,"event_id":r.get::<_,u64>(1)?,"location":r.get::<_,String>(2)?,"outcome":r.get::<_,String>(3)?})))?.collect::<Result<Vec<_>,_>>()?)
    }
}

/// Dedicated bounded listener; the existing operator HTTP console stays unchanged.
pub async fn serve(
    listener: TcpListener,
    config: Arc<rustls::ServerConfig>,
    engine: Arc<Mutex<Engine>>,
    mut stop: watch::Receiver<bool>,
) -> LabResult<()> {
    let acceptor = TlsAcceptor::from(config);
    let capacity = Arc::new(Semaphore::new(8));
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            _=stop.changed()=>break,
            Some(_)=tasks.join_next(), if !tasks.is_empty()=>{},
            accepted=listener.accept()=>{
                let (socket,_)=accepted?;
                let Ok(permit)=capacity.clone().try_acquire_owned() else {drop(socket);continue;};
                let acceptor=acceptor.clone();let engine=engine.clone();
                tasks.spawn(async move {
                    let _permit=permit;
                    let result=timeout(TIMEOUT,async {
                        let mut stream=acceptor.accept(socket).await?;
                        let peer=stream.get_ref().1.peer_certificates().and_then(|c|c.first()).ok_or("Missing authenticated client certificate")?;
                        let fingerprint=memory::hex(&memory::digest(peer.as_ref()));
                        let request:Request=read_frame(&mut stream).await?;
                        let result=engine.lock().map_err(|_|"Engine unavailable")?.serve_evidence(&fingerprint,request,now_ms());
                        let reply=match result {Ok(bundle)=>Reply {bundle:Some(bundle),error:None},Err(e)=>Reply {bundle:None,error:Some(e.to_string())}};
                        write_frame(&mut stream,&reply).await?;
                        stream.shutdown().await?;
                        Ok::<_,Box<dyn std::error::Error+Send+Sync>>(())
                    }).await;
                    if result.is_err() { /* connection is dropped on timeout */ }
                });
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    Ok(())
}

#[derive(Clone)]
pub struct EvidenceClient {
    config: Arc<rustls::ClientConfig>,
    capacity: Arc<Semaphore>,
}
impl EvidenceClient {
    pub fn new(config: Arc<rustls::ClientConfig>) -> Self {
        Self {
            config,
            capacity: Arc::new(Semaphore::new(4)),
        }
    }
    async fn fetch(&self, location: &EvidenceLocation) -> LabResult<Vec<Vec<u8>>> {
        let socket = TcpStream::connect(location.address).await?;
        let connector = TlsConnector::from(self.config.clone());
        let mut stream = connector
            .connect(ServerName::try_from(location.server_name.clone())?, socket)
            .await?;
        let cert = stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|c| c.first())
            .ok_or("Missing server certificate")?;
        if memory::hex(&memory::digest(cert.as_ref())) != location.cert_hash {
            return Err("Remote agent certificate identity mismatch".into());
        }
        write_frame(
            &mut stream,
            &Request {
                event_id: location.event_id,
                token: location.token.clone(),
            },
        )
        .await?;
        let reply: Reply = read_frame(&mut stream).await?;
        let bundle = reply
            .bundle
            .ok_or_else(|| reply.error.unwrap_or_else(|| "Evidence unavailable".into()))?;
        if bundle.len() != 3 || bundle.iter().any(|b| b.len() > MAX_OBJECT) {
            return Err("Remote evidence budget exceeded".into());
        }
        Ok(bundle)
    }
    /// No engine mutex is held across network I/O. Verified local evidence always wins.
    pub async fn retrieve(
        &self,
        engine: Arc<Mutex<Engine>>,
        id: u64,
        now: u64,
    ) -> LabResult<crate::model::DisplayEvent> {
        let locations = {
            let e = engine.lock().map_err(|_| "Engine unavailable")?;
            if let Ok(event) = e.reconstruct(id) {
                e.retrieval_audit(id, "local", "verified", now)?;
                return Ok(event);
            }
            e.locations(id)?
        };
        let _permit = self
            .capacity
            .clone()
            .try_acquire_owned()
            .map_err(|_| "Remote retrieval backpressure")?;
        let mut last = "No available evidence location".to_string();
        for location in locations {
            for attempt in 0..3 {
                engine
                    .lock()
                    .map_err(|_| "Engine unavailable")?
                    .remote_budget(id, now)?;
                match timeout(TIMEOUT, self.fetch(&location)).await {
                    Ok(Ok(bundle)) => {
                        let e = engine.lock().map_err(|_| "Engine unavailable")?;
                        // Recheck identity state after I/O in case the operator quarantined it.
                        let active: bool = e.connection.query_row(
                            "SELECT EXISTS(SELECT 1 FROM agents WHERE id=?1 AND state='active')",
                            [location.agent_id],
                            |r| r.get(0),
                        )?;
                        if !active {
                            e.retrieval_audit(id, "remote", "quarantined", now)?;
                            return Err("Remote identity quarantined".into());
                        }
                        if let Err(error) = e.accept_evidence_bundle(id, &bundle) {
                            e.retrieval_audit(id, "remote", "integrity_rejected", now)?;
                            return Err(error);
                        }
                        e.retrieval_audit(id, "remote", "verified", now)?;
                        return e.reconstruct(id);
                    }
                    Ok(Err(error)) => last = error.to_string(),
                    Err(_) => last = "Evidence request timeout".into(),
                }
                engine
                    .lock()
                    .map_err(|_| "Engine unavailable")?
                    .retrieval_audit(id, "remote", "unavailable", now)?;
                if attempt < 2 {
                    tokio::time::sleep(Duration::from_millis(25 * (attempt + 1))).await;
                }
            }
        }
        Err(last.into())
    }
    /// Retry only bounded relevant work. Persistent attempts impose a cooldown across restarts.
    pub async fn promote_pending(&self, engine: Arc<Mutex<Engine>>, now: u64) -> LabResult<usize> {
        let work = {
            let e = engine.lock().map_err(|_| "Engine unavailable")?;
            let rows=e.connection.prepare("SELECT r.payload FROM relevance r WHERE r.score>=?1 AND EXISTS(SELECT 1 FROM evidence_locations l WHERE l.event_id=r.event_id) AND NOT EXISTS(SELECT 1 FROM investigation_cache c WHERE c.event_id=r.event_id) AND NOT EXISTS(SELECT 1 FROM evidence_retrieval_audit a WHERE a.event_id=r.event_id AND a.location='remote' AND a.time_ms>?2) ORDER BY r.trigger_id DESC LIMIT 8")?.query_map(params![e.memory_config()?.promotion_score,now.saturating_sub(60_000)],|r|r.get::<_,String>(0))?.collect::<Result<Vec<_>,_>>()?;
            rows
        };
        let mut promoted = 0;
        for raw in work {
            let mut relevance: Relevance = serde_json::from_str(&raw)?;
            let config = engine
                .lock()
                .map_err(|_| "Engine unavailable")?
                .memory_config()?;
            if now.saturating_sub(relevance.computed_ms) >= config.context_ms {
                continue;
            }
            match self.retrieve(engine.clone(), relevance.event_id, now).await {
                Ok(event) => {
                    relevance.status = "verified_remote_or_local".into();
                    let e = engine.lock().map_err(|_| "Engine unavailable")?;
                    e.promote(&event, relevance, now)?;
                    e.maintain_memory(now)?;
                    promoted += 1;
                }
                Err(error) => {
                    relevance.status = format!("unavailable: {error}");
                    engine
                        .lock()
                        .map_err(|_| "Engine unavailable")?
                        .save_relevance(&relevance)?;
                }
            }
        }
        Ok(promoted)
    }
}
