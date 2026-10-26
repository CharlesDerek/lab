use super::*;
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::sync::{Arc, Mutex};
const OPERATOR: &str = "public-native-authentication-agent-operator-fixture-32";

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
    cleanup_ok: Arc<AtomicBool>,
}
impl Server {
    fn start(app: App, listener: TcpListener, cleanup_ok: Arc<AtomicBool>) -> Self {
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let worker = thread::spawn(move || {
            safe(
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build(),
                "transport",
            )
            .block_on(async move {
                let listener = safe(tokio::net::TcpListener::from_std(listener), "transport");
                safe(
                    axum::serve(listener, router(app))
                        .with_graceful_shutdown(async {
                            let _ = stopped.await;
                        })
                        .await,
                    "transport",
                );
            });
        });
        Self {
            stop: Some(stop),
            worker: Some(worker),
            cleanup_ok,
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let deadline = Instant::now() + Duration::from_secs(15);
            while !worker.is_finished() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if !worker.is_finished() || worker.join().is_err() {
                self.cleanup_ok.store(false, Ordering::SeqCst);
            }
        }
    }
}
#[derive(serde::Deserialize)]
struct Observation {
    evidence_id: u64,
    event: EndpointEvent,
}
fn originals(
    http: &reqwest::blocking::Client,
    url: &str,
) -> BTreeMap<String, (u64, EndpointEvent)> {
    let mut found = BTreeMap::new();
    let mut before = i64::MAX as u64;
    let mut complete = false;
    for _ in 0..128 {
        let response = safe(
            http.get(url)
                .query(&[("before", before)])
                .bearer_auth(OPERATOR)
                .send(),
            "transport",
        );
        let rows: Vec<Observation> = safe(
            safe(response.error_for_status(), "transport").json(),
            "original",
        );
        if rows.is_empty() {
            complete = true;
            break;
        }
        before = rows.last().expect("Nonempty observations").evidence_id;
        for row in rows {
            ensure(
                found
                    .insert(row.event.id.clone(), (row.evidence_id, row.event))
                    .is_none(),
                "replay",
            );
        }
    }
    ensure(complete, "original");
    found
}
fn app(engine: Engine) -> App {
    App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "public-native-authentication-agent-fixture".into(),
        ingest_token: None,
        operator: Arc::new(safe(
            athernex_siem::auth::OperatorAuth::new(OPERATOR),
            "authorization",
        )),
    }
}
pub(super) fn deliver(
    temp: &Path,
    state: &Path,
    listener: TcpListener,
    config: &Config,
    exe: &Path,
    selected: &[EndpointEvent],
    cleanup_ok: Arc<AtomicBool>,
) {
    let address = safe(listener.local_addr(), "transport");
    let db = temp.join("server.db");
    let mut engine = safe(Engine::open(&db), "transport");
    safe(engine.configure_mode(false), "transport");
    let token = safe(
        engine.create_enrollment(protocol::Platform::current(), crate::now_ms()),
        "authorization",
    );
    safe(
        engine.enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token,
                endpoint_id: config.endpoint_id.clone(),
                credential: config.credential.clone(),
                hostname: "Controlled native authentication agent fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            crate::now_ms(),
        ),
        "authorization",
    );
    let application = app(engine);
    let server = Server::start(application.clone(), listener, cleanup_ok.clone());
    let http = safe(
        reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build(),
        "transport",
    );
    let export = format!(
        "http://{address}/api/endpoints/{}/events",
        config.endpoint_id
    );
    let ingest = format!(
        "http://{address}/api/endpoint/{}/events",
        config.endpoint_id
    );
    let Some(Telemetry::WindowsAuthentication { event }) = &selected
        .first()
        .unwrap_or_else(|| fail("original"))
        .telemetry
    else {
        fail("original")
    };
    let account = event
        .target_user
        .as_deref()
        .unwrap_or_else(|| fail("original"));
    let mut agent = Agent::start(exe, state, cleanup_ok.clone());
    until(
        || {
            agent.alive();
            let found = originals(&http, &export);
            selected.iter().all(|e| found.contains_key(&e.id)) && queued(state, account).is_empty()
        },
        "transport",
    );
    let before_replay = originals(&http, &export);
    println!("\nATHERNEX_AUTH_AGENT_STAGE=http_delivery_verified");
    // All duplicate/conflict checks traverse the authenticated real HTTP router.
    for batch in selected.chunks(8) {
        let response = safe(
            http.post(&ingest)
                .bearer_auth(&config.credential)
                .json(batch)
                .send(),
            "replay",
        );
        let response: serde_json::Value =
            safe(safe(response.error_for_status(), "replay").json(), "replay");
        ensure(
            response["durability"] == "committed"
                && response["accepted"].as_u64() == Some(0)
                && response["acknowledged"].as_u64() == Some(batch.len() as u64),
            "replay",
        );
    }
    let mut changed = selected.first().unwrap_or_else(|| fail("replay")).clone();
    changed.detail.push_str(" conflicting controlled replay");
    ensure(
        safe(
            http.post(&ingest)
                .bearer_auth(&config.credential)
                .json(&[changed])
                .send(),
            "replay",
        )
        .status()
            == reqwest::StatusCode::BAD_REQUEST,
        "replay",
    );
    let replayed = originals(&http, &export);
    ensure(
        selected.iter().all(|event| {
            replayed.get(&event.id).map(|(id, _)| id)
                == before_replay.get(&event.id).map(|(id, _)| id)
        }),
        "replay",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=server_replay_verified");
    ensure(
        safe(http.get(&export).send(), "authorization").status()
            == reqwest::StatusCode::UNAUTHORIZED,
        "authorization",
    );
    ensure(
        safe(
            http.get(&export).bearer_auth(&config.credential).send(),
            "authorization",
        )
        .status()
            == reqwest::StatusCode::UNAUTHORIZED,
        "authorization",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=export_authorization_verified");
    let found = originals(&http, &export);
    for expected in selected {
        ensure(
            found
                .get(&expected.id)
                .is_some_and(|(_, actual)| same_event(actual, expected)),
            "original",
        );
    }
    println!("\nATHERNEX_AUTH_AGENT_STAGE=original_export_verified");
    let evidence = found
        .get(&selected.first().unwrap_or_else(|| fail("original")).id)
        .unwrap_or_else(|| fail("original"))
        .0;
    let page = page(&http, &format!("http://{address}/event/{evidence}"));
    ensure(page.contains("Open original device evidence"), "portal");
    println!("\nATHERNEX_AUTH_AGENT_STAGE=original_link_verified");
    {
        let mut engine = safe(application.engine.lock(), "device_separation");
        enroll(&mut engine, &"c".repeat(64), &"d".repeat(64));
    }
    let second_ingest = format!("http://{address}/api/endpoint/{}/events", "c".repeat(64));
    let second_export = format!("http://{address}/api/endpoints/{}/events", "c".repeat(64));
    // Endpoint credentials cannot ingest under another device or export originals.
    ensure(
        safe(
            http.post(&second_ingest)
                .bearer_auth(&config.credential)
                .json(&selected[..1])
                .send(),
            "device_separation",
        )
        .status()
            == reqwest::StatusCode::UNAUTHORIZED,
        "device_separation",
    );
    for batch in selected.chunks(8) {
        ensure(
            safe(
                http.post(&second_ingest)
                    .bearer_auth("d".repeat(64))
                    .json(batch)
                    .send(),
                "device_separation",
            )
            .status()
            .is_success(),
            "device_separation",
        );
    }
    let second = originals(&http, &second_export);
    for expected in selected {
        ensure(
            second.get(&expected.id).is_some_and(|(id, actual)| {
                same_event(actual, expected)
                    && found
                        .get(&expected.id)
                        .is_some_and(|(first, _)| id != first)
            }),
            "device_separation",
        );
    }
    let primary = originals(&http, &export);
    ensure(
        found.iter().all(|(key, (id, event))| {
            primary
                .get(key)
                .is_some_and(|(after, original)| id == after && same_event(event, original))
        }),
        "device_separation",
    );
    println!("\nATHERNEX_AUTH_AGENT_STAGE=device_separation_verified");
    verify_detection(&application, config, &found);
    println!("\nATHERNEX_AUTH_AGENT_STAGE=detection_verified");
    for (path, text) in [
        (
            "/endpoints".to_owned(),
            "Windows Security logons: coverage incomplete / catching up",
        ),
        (format!("/endpoints/{}", config.endpoint_id), "Original XML"),
    ] {
        let page = safe(
            safe(
                safe(
                    http.get(format!("http://{address}{path}"))
                        .bearer_auth(OPERATOR)
                        .send(),
                    "portal",
                )
                .error_for_status(),
                "portal",
            )
            .text(),
            "portal",
        );
        ensure(page.contains(text), "portal");
        if path.starts_with("/endpoints/") {
            ensure(page.contains("&lt;Event") && selected.iter().all(|e| {
                matches!(&e.telemetry, Some(Telemetry::WindowsAuthentication {event}) if !page.contains(&event.xml))
            }), "portal");
        }
    }
    println!("\nATHERNEX_AUTH_AGENT_STAGE=portal_coverage_verified");
    ensure(agent.stop(false), "cleanup");
    drop(server);
    drop(application);
    let listener = safe(TcpListener::bind(address), "transport");
    safe(listener.set_nonblocking(true), "transport");
    let application = app(safe(Engine::open(&db), "replay"));
    let server = Server::start(application.clone(), listener, cleanup_ok.clone());
    let reopened = originals(&http, &export);
    for expected in selected {
        ensure(
            reopened.get(&expected.id).is_some_and(|(id, actual)| {
                found
                    .get(&expected.id)
                    .is_some_and(|(before, _)| id == before)
                    && same_event(actual, expected)
            }),
            "replay",
        );
        let response = safe(
            http.post(&ingest)
                .bearer_auth(&config.credential)
                .json(&[expected])
                .send(),
            "replay",
        );
        let response: serde_json::Value =
            safe(safe(response.error_for_status(), "replay").json(), "replay");
        ensure(
            response["durability"] == "committed"
                && response["accepted"].as_u64() == Some(0)
                && response["acknowledged"].as_u64() == Some(1),
            "replay",
        );
    }
    let replayed = originals(&http, &export);
    ensure(
        replayed.len() == reopened.len()
            && selected.iter().all(|e| {
                replayed.get(&e.id).map(|(id, _)| id) == reopened.get(&e.id).map(|(id, _)| id)
            }),
        "replay",
    );
    verify_detection(&application, config, &replayed);
    println!("\nATHERNEX_AUTH_AGENT_STAGE=server_restart_verified");
    drop(server);
    drop(application);
}

fn page(http: &reqwest::blocking::Client, url: &str) -> String {
    safe(
        safe(
            safe(http.get(url).bearer_auth(OPERATOR).send(), "portal").error_for_status(),
            "portal",
        )
        .text(),
        "portal",
    )
}
fn enroll(engine: &mut Engine, id: &str, credential: &str) {
    let token = safe(
        engine.create_enrollment(protocol::Platform::current(), crate::now_ms()),
        "authorization",
    );
    safe(
        engine.enroll_endpoint(
            &protocol::Enrollment {
                protocol: protocol::PROTOCOL,
                enrollment_token: token,
                endpoint_id: id.into(),
                credential: credential.into(),
                hostname: "Controlled native authentication agent fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            crate::now_ms(),
        ),
        "authorization",
    );
}
fn verify_detection(app: &App, config: &Config, found: &BTreeMap<String, (u64, EndpointEvent)>) {
    let engine = safe(app.engine.lock(), "detection");
    let snapshot = safe(engine.snapshot(), "detection");
    ensure(snapshot.findings.iter().any(|finding| finding.rule == "AX-001" && finding.evidence.iter().filter(|evidence| {
        found.values().any(|(id, original)| *id == evidence.event.id && matches!(&original.telemetry,
            Some(Telemetry::WindowsAuthentication {event}) if event.event_code == 4625
            && evidence.context.as_ref().is_some_and(|context| context.host == config.endpoint_id
            && context.pid == event.caller_pid && context.uid.is_none() && context.process_start_ms.is_none()
            && context.journal_cursor.is_empty())))
    }).count() >= 8), "detection");
}
