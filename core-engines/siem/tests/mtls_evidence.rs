use athernex_siem::{
    engine::Engine,
    evidence_transport::{self as transport, EvidenceClient, EvidenceLocation},
    memory::{digest, hex, DAY},
    model::*,
};
use rcgen::{BasicConstraints, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use std::sync::{Arc, Mutex};
use tokio::{net::TcpListener, sync::watch};
use tokio_rustls::rustls::{
    self,
    pki_types::{CertificateDer, PrivatePkcs8KeyDer},
};
fn fact(time: u64, key: &str, severity: u8) -> InputEvent {
    InputEvent {
        time_ms: time,
        source: "endpoint".into(),
        subject: "alice".into(),
        object: "192.0.2.1".into(),
        kind: Kind::Network,
        outcome: Outcome::Observe,
        severity,
        bytes: 1,
        trace: 1,
        idempotency_key: key.into(),
        context: None,
    }
}
struct Pki {
    ca: CertificateDer<'static>,
    server: CertificateDer<'static>,
    server_key: Vec<u8>,
    client: CertificateDer<'static>,
    client_key: Vec<u8>,
    other: CertificateDer<'static>,
    other_key: Vec<u8>,
}
fn pki() -> Pki {
    let ca_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = params.self_signed(&ca_key).unwrap();
    let leaf = |name: &str, usage| {
        let key = KeyPair::generate().unwrap();
        let mut p = CertificateParams::new(vec![name.into()]).unwrap();
        p.extended_key_usages = vec![usage];
        let cert = p.signed_by(&key, &ca, &ca_key).unwrap();
        (cert.der().clone(), key.serialize_der())
    };
    let (server, server_key) = leaf("localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let (client, client_key) = leaf("investigator", ExtendedKeyUsagePurpose::ClientAuth);
    let (other, other_key) = leaf("unregistered", ExtendedKeyUsagePurpose::ClientAuth);
    Pki {
        ca: ca.der().clone(),
        server,
        server_key,
        client,
        client_key,
        other,
        other_key,
    }
}
fn client(p: &Pki, other: bool) -> EvidenceClient {
    let (cert, key) = if other {
        (&p.other, &p.other_key)
    } else {
        (&p.client, &p.client_key)
    };
    EvidenceClient::new(
        transport::client_config(
            transport::root_store(vec![p.ca.clone()]).unwrap(),
            vec![cert.clone()],
            PrivatePkcs8KeyDer::from(key.clone()).into(),
        )
        .unwrap(),
    )
}
// A lost local object preserves the independent trusted reference. Deliberately bypass
// immutable-delete guards only in the corruption/loss fixture, never in the product.
fn lose_occurrence(path: &std::path::Path, id: u64) {
    let db = rusqlite::Connection::open(path).unwrap();
    db.execute_batch("DROP TRIGGER IF EXISTS immutable_object_delete;")
        .unwrap();
    db.execute(
        "DELETE FROM evidence_objects WHERE hash=(SELECT hash FROM evidence_refs WHERE id=?1)",
        [id],
    )
    .unwrap();
}
struct Fixture {
    p: Pki,
    server: Arc<Mutex<Engine>>,
    local: Arc<Mutex<Engine>>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<athernex_siem::engine::LabResult<()>>,
    location: EvidenceLocation,
    path: std::path::PathBuf,
    _dir: tempfile::TempDir,
    now: u64,
}
async fn fixture(max_uses: u64) -> Fixture {
    let p = pki();
    let now = now_ms();
    let mut server = Engine::memory().unwrap();
    server
        .ingest(&[fact(now - 5 * DAY, "old", 1)], now - 5 * DAY)
        .unwrap();
    let agent = server
        .register_agent("investigator", "evidence reader", now)
        .unwrap();
    server
        .bind_agent_certificate(agent, &hex(&digest(p.client.as_ref())), now)
        .unwrap();
    let task = server
        .create_task(agent, "Read exact evidence", "event-1", 10, now)
        .unwrap();
    let grant = server.issue_grant(task, 300, max_uses, now).unwrap();
    let server = Arc::new(Mutex::new(server));
    let config = transport::server_config(
        transport::root_store(vec![p.ca.clone()]).unwrap(),
        vec![p.server.clone()],
        PrivatePkcs8KeyDer::from(p.server_key.clone()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(transport::serve(listener, config, server.clone(), stopped));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("local.db");
    let mut local = Engine::open(&path).unwrap();
    local
        .ingest(&[fact(now - 5 * DAY, "old", 1)], now - 5 * DAY)
        .unwrap();
    let remote = local
        .register_agent("storage-node", "evidence server", now)
        .unwrap();
    let location = EvidenceLocation {
        event_id: 1,
        agent_id: remote,
        address,
        server_name: "localhost".into(),
        cert_hash: hex(&digest(p.server.as_ref())),
        token: grant.token,
    };
    local.add_evidence_location(&location, now).unwrap();
    Fixture {
        p,
        server,
        local: Arc::new(Mutex::new(local)),
        stop,
        task,
        location,
        path,
        _dir: dir,
        now,
    }
}
#[tokio::test]
async fn real_mtls_scoped_authorization_and_automatic_remote_promotion() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    {
        let mut e = f.local.lock().unwrap();
        e.tick(f.now).unwrap();
        e.ingest(&[fact(f.now, "new-alert", 5)], f.now).unwrap();
        assert!(e
            .memory_state()
            .unwrap()
            .context
            .iter()
            .all(|c| c.evidence.event.id != 1));
    }
    let count = client(&f.p, false)
        .promote_pending(f.local.clone(), f.now)
        .await
        .unwrap();
    assert_eq!(count, 1);
    {
        let e = f.local.lock().unwrap();
        let state = e.memory_state().unwrap();
        let old = state
            .context
            .iter()
            .find(|c| c.evidence.event.id == 1)
            .unwrap();
        assert_eq!(old.evidence.event.time_ms, f.now - 5 * DAY);
        assert_eq!(old.relevance.status, "verified_remote_or_local");
        assert!(e
            .retrieval_audits()
            .unwrap()
            .iter()
            .any(|a| a["outcome"] == "verified" && a["location"] == "remote"));
    }
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        1
    );
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}
#[tokio::test]
async fn local_evidence_works_when_endpoint_is_offline_and_never_spends_remote_grant() {
    let f = fixture(1).await;
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
    let event = client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .unwrap();
    assert_eq!(event.event.time_ms, f.now - 5 * DAY);
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        0
    );
    lose_occurrence(&f.path, 1);
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    let audits = f.local.lock().unwrap().retrieval_audits().unwrap();
    assert_eq!(
        audits.iter().filter(|a| a["outcome"] == "attempt").count(),
        3
    );
}
#[tokio::test]
async fn trusted_ca_but_wrong_agent_certificate_cannot_use_stolen_token() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    assert!(client(&f.p, true)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        0
    );
    assert!(f
        .server
        .lock()
        .unwrap()
        .retrieval_audits()
        .unwrap()
        .iter()
        .any(|a| a["outcome"] == "identity_denied"));
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}
#[tokio::test]
async fn wrong_server_pin_and_exhausted_capability_fail_closed() {
    let f = fixture(1).await;
    lose_occurrence(&f.path, 1);
    let mut wrong = f.location.clone();
    wrong.cert_hash = "00".repeat(32);
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&wrong, f.now)
        .unwrap();
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&f.location, f.now)
        .unwrap();
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_ok());
    lose_occurrence(&f.path, 1);
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        1
    );
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}
#[tokio::test]
async fn mtls_requires_a_client_certificate() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(transport::root_store(vec![f.p.ca.clone()]).unwrap())
        .with_no_client_auth();
    let c = EvidenceClient::new(Arc::new(config));
    assert!(c.retrieve(f.local.clone(), 1, f.now).await.is_err());
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        0
    );
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}
#[tokio::test]
async fn timeout_retries_are_bounded_and_do_not_mark_evidence_verified() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut location = f.location.clone();
    location.address = listener.local_addr().unwrap();
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&location, f.now)
        .unwrap();
    let stalled = tokio::spawn(async move {
        let mut sockets = Vec::new();
        for _ in 0..3 {
            sockets.push(listener.accept().await.unwrap());
        }
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
    });
    let start = std::time::Instant::now();
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(12));
    stalled.abort();
    assert!(f
        .local
        .lock()
        .unwrap()
        .memory_state()
        .unwrap()
        .context
        .is_empty());
}

#[tokio::test]
async fn compromised_mtls_peer_cannot_substitute_evidence() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let f = fixture(10).await;
    let mut bundle = f.server.lock().unwrap().evidence_bundle(1).unwrap();
    bundle[0][10] ^= 1;
    lose_occurrence(&f.path, 1);
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
    let config = transport::server_config(
        transport::root_store(vec![f.p.ca.clone()]).unwrap(),
        vec![f.p.server.clone()],
        PrivatePkcs8KeyDer::from(f.p.server_key.clone()).into(),
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut location = f.location.clone();
    location.address = listener.local_addr().unwrap();
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&location, f.now)
        .unwrap();
    let compromised = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = tokio_rustls::TlsAcceptor::from(config)
            .accept(socket)
            .await
            .unwrap();
        let n = stream.read_u32().await.unwrap();
        let mut request = vec![0; n as usize];
        stream.read_exact(&mut request).await.unwrap();
        let reply = serde_json::to_vec(&serde_json::json!({"bundle":bundle,"error":null})).unwrap();
        stream.write_u32(reply.len() as u32).await.unwrap();
        stream.write_all(&reply).await.unwrap();
        stream.flush().await.unwrap();
    });
    let error = client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("mismatch"));
    compromised.await.unwrap();
    let e = f.local.lock().unwrap();
    assert!(e.reconstruct(1).is_err());
    assert!(e
        .retrieval_audits()
        .unwrap()
        .iter()
        .any(|a| a["outcome"] == "integrity_rejected"));
}
#[tokio::test]
async fn remote_attempts_are_rate_limited_across_client_instances() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
    for _ in 0..7 {
        assert!(client(&f.p, false)
            .retrieve(f.local.clone(), 1, f.now)
            .await
            .is_err());
    }
    assert_eq!(
        f.local
            .lock()
            .unwrap()
            .retrieval_audits()
            .unwrap()
            .iter()
            .filter(|a| a["outcome"] == "attempt")
            .count(),
        16
    );
}
#[tokio::test]
async fn certificate_owned_token_still_cannot_read_another_event() {
    let f = fixture(10).await;
    f.local
        .lock()
        .unwrap()
        .ingest(&[fact(f.now, "second", 1)], f.now)
        .unwrap();
    lose_occurrence(&f.path, 2);
    let mut location = f.location.clone();
    location.event_id = 2;
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&location, f.now)
        .unwrap();
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 2, f.now)
        .await
        .is_err());
    assert_eq!(
        f.server.lock().unwrap().hive(f.now).unwrap().grants[0].uses,
        0
    );
    assert!(f
        .server
        .lock()
        .unwrap()
        .retrieval_audits()
        .unwrap()
        .iter()
        .any(|a| a["outcome"] == "scope_denied"));
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}

#[tokio::test]
async fn expired_event_capability_is_rejected_even_with_the_correct_certificate() {
    let f = fixture(10).await;
    lose_occurrence(&f.path, 1);
    let token = {
        let e = f.server.lock().unwrap();
        let t = e
            .create_task(1, "Expired read", "event-1", 10, f.now - 2_000)
            .unwrap();
        e.issue_grant(t, 1, 10, f.now - 2_000).unwrap().token
    };
    let mut location = f.location.clone();
    location.token = token;
    f.local
        .lock()
        .unwrap()
        .add_evidence_location(&location, f.now)
        .unwrap();
    assert!(client(&f.p, false)
        .retrieve(f.local.clone(), 1, f.now)
        .await
        .is_err());
    assert!(f
        .server
        .lock()
        .unwrap()
        .hive(f.now)
        .unwrap()
        .decisions
        .iter()
        .any(|d| d.reason == "task_or_grant_expired"));
    f.stop.send(true).unwrap();
    f.task.await.unwrap().unwrap();
}
