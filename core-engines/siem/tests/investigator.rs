use athernex_siem::{
    engine::Engine,
    investigator::{self, Analysis, InvestigationRequest},
    model::{now_ms, InputEvent, Kind, Outcome},
};
use orchestrator::governor::Resources;
use std::future::IntoFuture;
fn setup() -> (Engine, InvestigationRequest) {
    let mut e = Engine::memory().unwrap();
    let now = now_ms();
    e.ingest(
        &[InputEvent {
            time_ms: now,
            source: "fixture".into(),
            subject: "alice".into(),
            object: "fixture-host".into(),
            kind: Kind::Authentication,
            outcome: Outcome::Allow,
            severity: 1,
            bytes: 0,
            trace: 0,
            idempotency_key: "fixture-1".into(),
            context: None,
        }],
        now,
    )
    .unwrap();
    let id = e
        .create_case("Public investigation fixture", 2, now)
        .unwrap();
    let event = e.events().unwrap().remove(0);
    e.attach_case_event(id, 1, event, now).unwrap();
    e.configure_pool(
        "analysis",
        Resources {
            cpu_millis: 1000,
            memory_mib: 1024,
            tokens: 20000,
            ..Default::default()
        },
        Resources::default(),
        now,
    )
    .unwrap();
    (
        e,
        InvestigationRequest {
            id: "job-1".into(),
            case_id: id,
            pool: "analysis".into(),
            max_events: 16,
            token_budget: 4096,
            deadline_ms: now + 60000,
        },
    )
}
#[test]
fn fabricated_citations_values_and_actions_are_refused_and_budget_released_after_worker_returns() {
    let (e, request) = setup();
    let packet = e
        .prepare_investigation(&request, "analyst", now_ms())
        .unwrap();
    let mut wrong = investigator::baseline(&packet);
    wrong.facts[0].value = "fabricated malware".into();
    assert!(wrong.validate(&packet).is_err());
    let mut outside = investigator::baseline(&packet);
    outside.facts[0].event_id += 100;
    assert!(outside.validate(&packet).is_err());
    assert!(serde_json::from_value::<Analysis>(serde_json::json!({"facts":[],"hypotheses":[],"abstain_reason":"missing evidence","execute":"rm -rf"})).is_err());
    let result = e
        .finish_investigation(&request.id, Ok((wrong, 12)), now_ms())
        .unwrap();
    assert_eq!(result.state, "failed");
    assert!(result.analysis.is_none());
    assert_eq!(e.resource_pools().unwrap()[0].used, Resources::default());
}
#[test]
fn cancellation_does_not_release_worker_capacity_early_and_duplicate_execution_is_refused() {
    let (e, request) = setup();
    let packet = e
        .prepare_investigation(&request, "analyst", now_ms())
        .unwrap();
    assert!(e
        .prepare_investigation(&request, "analyst", now_ms())
        .is_err());
    assert!(e
        .cancel_investigation(&request.id, "other", false, now_ms())
        .is_err());
    e.cancel_investigation(&request.id, "analyst", false, now_ms())
        .unwrap();
    assert_eq!(e.resource_pools().unwrap()[0].used.tokens, 4096);
    let done = e
        .finish_investigation(
            &request.id,
            Ok((investigator::baseline(&packet), 0)),
            now_ms(),
        )
        .unwrap();
    assert_eq!(done.state, "cancelled");
    assert_eq!(e.resource_pools().unwrap()[0].used.tokens, 0);
}
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn configured_model_adapter_calls_real_http_fixture_and_validates_structured_evidence() {
    use axum::{routing::post, Json, Router};
    let (e, request) = setup();
    let packet = e
        .prepare_investigation(&request, "analyst", now_ms())
        .unwrap();
    let analysis = serde_json::to_string(&investigator::baseline(&packet)).unwrap();
    let server=Router::new().route("/api/generate",post(move|Json(body):Json<serde_json::Value>|{let analysis=analysis.clone();async move {
        assert_eq!(body["stream"],false);assert!(body["system"].as_str().unwrap().contains("untrusted data"));
        Json(serde_json::json!({"done":true,"response":analysis,"prompt_eval_count":100,"eval_count":50}))
    }}));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(axum::serve(listener, server).into_future());
    let output = tokio::task::spawn_blocking(move || {
        investigator::ollama(
            &packet,
            &format!("http://{address}/api/generate"),
            "fixture-model",
        )
    })
    .await
    .unwrap()
    .unwrap();
    let done = e
        .finish_investigation(&request.id, Ok(output), now_ms())
        .unwrap();
    assert_eq!(done.state, "completed");
    assert_eq!(done.tokens_used, 150);
    assert_eq!(done.analysis.unwrap().facts.len(), 1);
    task.abort();
}
