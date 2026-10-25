use super::*;
use athernex_siem::{
    engine::Engine,
    web::{router, App},
};
use std::sync::{Arc, Mutex};
const OPERATOR: &str = "public-native-process-operator-fixture-32";

struct Server {
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Server {
    fn start(app: App, listener: TcpListener) -> Self {
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
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
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
            "original_export",
        );
        if rows.is_empty() {
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
    found
}
fn app(engine: Engine) -> App {
    App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "public-native-process-fixture".into(),
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
                hostname: "Controlled native process fixture".into(),
                platform: protocol::Platform::current(),
                arch: std::env::consts::ARCH.into(),
                version: "fixture".into(),
            },
            crate::now_ms(),
        ),
        "authorization",
    );
    let application = app(engine);
    let server = Server::start(application.clone(), listener);
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
    let mut agent = Agent::start(exe, state);
    until(
        || {
            agent.alive();
            let found = originals(&http, &export);
            selected.iter().all(|e| found.contains_key(&e.id))
        },
        "transport",
    );
    let before_replay = originals(&http, &export);
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=http_delivery_verified");
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
                && response["acknowledged"].as_u64() == Some(batch.len() as u64),
            "replay",
        );
    }
    let mut changed = selected.first().unwrap_or_else(|| fail("replay")).clone();
    changed.detail.push_str(" conflicting controlled replay");
    ensure(
        !safe(
            http.post(&ingest)
                .bearer_auth(&config.credential)
                .json(&[changed])
                .send(),
            "replay",
        )
        .status()
        .is_success(),
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
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=server_replay_verified");
    ensure(
        !safe(http.get(&export).send(), "authorization")
            .status()
            .is_success(),
        "authorization",
    );
    ensure(
        !safe(
            http.get(&export).bearer_auth(&config.credential).send(),
            "authorization",
        )
        .status()
        .is_success(),
        "authorization",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=export_authorization_verified");
    let found = originals(&http, &export);
    for expected in selected {
        ensure(
            found.get(&expected.id).is_some_and(|(_, actual)| {
                serde_json::to_value(actual).ok() == serde_json::to_value(expected).ok()
            }),
            "original_export",
        );
    }
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=original_export_verified");
    for (path, text) in [
        (
            "/endpoints".to_owned(),
            "Windows ETW process events: coverage incomplete",
        ),
        (
            format!("/endpoints/{}", config.endpoint_id),
            "Original EVENT_RECORD",
        ),
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
    }
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=portal_coverage_verified");
    ensure(agent.cleanup(), "cleanup");
    drop(server);
    drop(application);
    let listener = safe(TcpListener::bind(address), "transport");
    safe(listener.set_nonblocking(true), "transport");
    let application = app(safe(Engine::open(&db), "replay"));
    let server = Server::start(application.clone(), listener);
    let reopened = originals(&http, &export);
    for expected in selected {
        ensure(
            reopened.get(&expected.id).is_some_and(|(id, actual)| {
                found
                    .get(&expected.id)
                    .is_some_and(|(before, _)| id == before)
                    && serde_json::to_value(actual).ok() == serde_json::to_value(expected).ok()
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
        ensure(response.status().is_success(), "replay");
    }
    let replayed = originals(&http, &export);
    ensure(
        replayed.len() == reopened.len()
            && selected.iter().all(|e| {
                replayed.get(&e.id).map(|(id, _)| id) == reopened.get(&e.id).map(|(id, _)| id)
            }),
        "replay",
    );
    println!("\nATHERNEX_PROCESS_EVENTS_STAGE=server_restart_verified");
    drop(server);
    drop(application);
}
