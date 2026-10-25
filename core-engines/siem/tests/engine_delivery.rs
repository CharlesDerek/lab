#![cfg(target_os = "linux")]
use athernex_endpoint::{engine_update, private_write, Client, Config, Store};
use athernex_endpoint_protocol::{
    self as p,
    engine::{File, Release, Roles, SignedRelease},
    engine_fleet::Receipt,
    Platform,
};
use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{self, App},
};
use std::{
    future::IntoFuture,
    path::PathBuf,
    sync::{Arc, Mutex},
};

struct Fixture {
    _dir: tempfile::TempDir,
    app: App,
    config: Config,
    state: PathBuf,
    catalog: PathBuf,
    release: SignedRelease,
    key: String,
    server: tokio::task::JoinHandle<std::io::Result<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.server.abort();
    }
}
async fn fixture() -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().canonicalize().unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let catalog = root.join("catalog");
    std::fs::create_dir_all(catalog.join("engines")).unwrap();
    let (private, key) = p::update::generate_key().unwrap();
    let names = [
        "bin/clamscan",
        "bin/freshclam",
        "sbin/clamd",
        "sbin/clamonacc",
        "lib/libfixture.so",
        "etc/certs/clamav.crt",
    ];
    let files = names
        .iter()
        .map(|name| File {
            path: (*name).into(),
            sha256: p::hash(name.as_bytes()),
            bytes: name.len() as u64,
            executable: name.starts_with("bin/") || name.starts_with("sbin/"),
        })
        .collect();
    let release = SignedRelease::sign(
        Release {
            schema: 1,
            protocol: p::PROTOCOL,
            engine: "clamav".into(),
            target: p::update::target(),
            version: "fixture".into(),
            channel: "stable".into(),
            sequence: 1,
            issued_ms: now_ms(),
            expires_ms: now_ms() + 300000,
            roles: Roles {
                scanner: names[0].into(),
                updater: names[1].into(),
                daemon: names[2].into(),
                monitor: Some(names[3].into()),
                library_dirs: vec!["lib".into()],
                certificates: "etc/certs".into(),
            },
            files,
        },
        &private,
    )
    .unwrap();
    let bundle = catalog.join("engines").join(release.id().unwrap());
    std::fs::create_dir_all(&bundle).unwrap();
    for name in names {
        let path = bundle.join("content").join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, name.as_bytes()).unwrap();
    }
    std::fs::write(
        bundle.join("manifest.json"),
        serde_json::to_vec(&release).unwrap(),
    )
    .unwrap();
    std::fs::write(catalog.join("engines/public-key.txt"), &key).unwrap();
    let mut engine = Engine::open(&root.join("server.db")).unwrap();
    engine.configure_mode(false).unwrap();
    let token = engine.create_enrollment(Platform::Linux, now_ms()).unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("fixture-operator-key-long-enough").unwrap(),
        ),
    };
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(
        axum::serve(
            listener,
            web::router_with_release_catalog(app.clone(), catalog.clone()),
        )
        .into_future(),
    );
    let state = root.join("agent");
    std::fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config:Config=serde_json::from_value(serde_json::json!({"server":format!("http://{address}/"),"endpoint_id":"a".repeat(64),"credential":"b".repeat(64),"enrollment_token":token,"scanner":root.join("old-scanner"),"updater":root.join("old-updater"),"scan_roots":[root.join("watched")],"allow_scripts":false,"engine_updates":{"managed":true,"public_key":key,"root":root.join("engine-releases"),"allow_unsigned_native":true}})).unwrap();
    private_write(
        &state.join("config.json"),
        &serde_json::to_vec_pretty(&config).unwrap(),
    )
    .unwrap();
    let copy = config.clone();
    let path = state.clone();
    tokio::task::spawn_blocking(move || {
        let store = Store::open(&path).unwrap();
        let client = Client::new(copy).unwrap();
        client.enroll().unwrap();
        client.managed_engines(&store).unwrap();
    })
    .await
    .unwrap();
    Fixture {
        _dir: dir,
        app,
        config,
        state,
        catalog,
        release,
        key,
        server,
    }
}
async fn cycle(f: &Fixture) -> Result<(), String> {
    let config = f.config.clone();
    let path = f.state.clone();
    tokio::task::spawn_blocking(move || {
        Client::new(config)
            .and_then(|client| client.managed_engines(&Store::open(&path)?))
            .map_err(|e| e.to_string())
    })
    .await
    .unwrap()
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_http_delivery_stages_verified_files_and_replays_receipts_after_agent_restart() {
    let f = fixture().await;
    let proposal = {
        let e = f.app.engine.lock().unwrap();
        e.propose_engine_update(&f.config.endpoint_id, &f.release, &f.key, false, now_ms())
            .unwrap()
    };
    cycle(&f).await.unwrap();
    assert!(engine_update::status(&f.state).unwrap().staged.is_none());
    {
        let e = f.app.engine.lock().unwrap();
        assert!(e
            .review_engine_update(&proposal.deployment.id, "bad-hash", &f.key, true, now_ms())
            .is_err());
        e.review_engine_update(
            &proposal.deployment.id,
            &proposal.plan_hash,
            &f.key,
            true,
            now_ms(),
        )
        .unwrap();
    }
    cycle(&f).await.unwrap();
    let status = engine_update::status(&f.state).unwrap();
    assert_eq!(status.staged, Some(f.release.clone()));
    assert!(status.installed.is_none());
    cycle(&f).await.unwrap();
    cycle(&f).await.unwrap();
    let e = f.app.engine.lock().unwrap();
    let finished = e.engine_deployment(&proposal.deployment.id).unwrap();
    assert_eq!(finished.state, "delivered");
    assert_eq!(finished.staging_receipt.unwrap().outcome, "staged");
    assert!(finished.installation_receipt.is_none());
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tampered_catalog_is_refused_without_staging_and_cancellation_blocks_download() {
    let mut f = fixture().await;
    let proposal = {
        let e = f.app.engine.lock().unwrap();
        let p = e
            .propose_engine_update(&f.config.endpoint_id, &f.release, &f.key, false, now_ms())
            .unwrap();
        e.review_engine_update(&p.deployment.id, &p.plan_hash, &f.key, true, now_ms())
            .unwrap();
        p
    };
    let path = f
        .catalog
        .join("engines")
        .join(f.release.id().unwrap())
        .join("content/bin/clamscan");
    std::fs::write(path, b"tampered").unwrap();
    assert!(cycle(&f).await.is_err());
    assert!(cycle(&f).await.is_err());
    cycle(&f).await.unwrap();
    // A lost acknowledgement may replay a refused staging receipt after it
    // already exists. It must not be mistaken for an installation result.
    // Revoking future delivery does not suppress the already recorded result.
    f.config.engine_updates.managed = false;
    cycle(&f).await.unwrap();
    cycle(&f).await.unwrap();
    let journal: serde_json::Value = serde_json::from_slice(
        &std::fs::read(f.state.join("engine-updates/delivery.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(journal["terminal"], true);
    assert!(engine_update::status(&f.state).unwrap().staged.is_none());
    let e = f.app.engine.lock().unwrap();
    assert_eq!(
        e.engine_deployment(&proposal.deployment.id).unwrap().state,
        "refused"
    );
    let receipt = e
        .engine_deployment(&proposal.deployment.id)
        .unwrap()
        .staging_receipt
        .unwrap();
    e.finish_engine_delivery(&f.config.endpoint_id, &receipt, now_ms())
        .unwrap();
    let mut changed = receipt;
    changed.detail = "Changed staging refusal".into();
    assert!(e
        .finish_engine_delivery(&f.config.endpoint_id, &changed, now_ms())
        .is_err());
    let p = e
        .propose_engine_update(&f.config.endpoint_id, &f.release, &f.key, false, now_ms())
        .unwrap();
    e.review_engine_update(&p.deployment.id, &p.plan_hash, &f.key, false, now_ms())
        .unwrap();
    assert!(e
        .authorize_engine_download(&f.config.endpoint_id, &p.deployment.id, &f.key, now_ms())
        .is_err());
    let invented = Receipt {
        deployment_id: p.deployment.id,
        release_id: f.release.id().unwrap(),
        outcome: "installed".into(),
        detail: String::new(),
        finished_ms: now_ms(),
    };
    assert!(e
        .finish_engine_delivery(&f.config.endpoint_id, &invented, now_ms())
        .is_err());
}
