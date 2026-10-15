use athernex_siem::{
    engine::Engine,
    model::now_ms,
    web::{router, App},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;

fn app(token: Option<String>) -> App {
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(true).unwrap();
    engine.seed(now_ms()).unwrap();
    engine.seed_hive(now_ms()).unwrap();
    engine.flush(now_ms()).unwrap();
    App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "test-session-token".into(),
        ingest_token: token,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("test-operator-key-32-characters-long").unwrap(),
        ),
    }
}

#[tokio::test]
async fn all_console_views_render_and_disallow_scripts() {
    let router = router(app(None));
    for path in [
        "/",
        "/investigate",
        "/detections",
        "/workbench",
        "/research",
        "/hive",
        "/retention",
        "/agent/1",
        "/task/1",
        "/archive/1",
        "/archive/1/event/1",
        "/event/1",
        "/incident/1",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .header(
                        "authorization",
                        "Bearer test-operator-key-32-characters-long",
                    )
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK, "{path}");
        assert!(response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'none'"));
        let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("<h1>"));
        assert!(!html.contains("<script"));
    }
}

#[tokio::test]
async fn csrf_blocks_mutations_and_valid_actions_change_state() {
    let app = app(None);
    let router = router(app.clone());
    let before = app
        .engine
        .lock()
        .unwrap()
        .snapshot()
        .unwrap()
        .total_received;
    for (token, status) in [
        ("wrong", StatusCode::BAD_REQUEST),
        ("test-session-token", StatusCode::SEE_OTHER),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .header(
                        "authorization",
                        "Bearer test-operator-key-32-characters-long",
                    )
                    .method("POST")
                    .uri("/action")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf={token}&op=scenario&value=auth&back=%2F"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
    }
    assert_eq!(
        app.engine
            .lock()
            .unwrap()
            .snapshot()
            .unwrap()
            .total_received,
        before + 9
    );
}

#[tokio::test]
async fn api_requires_token_validates_and_deduplicates() {
    let router = router(app(Some("test-private-ingestion-token".into())));
    let input=serde_json::json!([{"time_ms":now_ms(),"source":"fixture","subject":"actor","object":"control","kind":"authentication","outcome":"deny","severity":3,"idempotency_key":"http-fixture"}]).to_string();
    for (token, status, accepted) in [
        ("wrong", StatusCode::BAD_REQUEST, None),
        ("test-private-ingestion-token", StatusCode::OK, Some(1)),
        ("test-private-ingestion-token", StatusCode::OK, Some(0)),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/ingest")
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(input.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), status);
        if let Some(accepted) = accepted {
            let body = to_bytes(response.into_body(), 1_000_000).await.unwrap();
            let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(json["accepted"], accepted);
        }
    }
}

#[tokio::test]
async fn oversized_ingest_is_rejected_before_processing() {
    let router = router(app(Some("test-private-ingestion-token".into())));
    let response = router
        .oneshot(
            Request::builder()
                .header(
                    "authorization",
                    "Bearer test-operator-key-32-characters-long",
                )
                .method("POST")
                .uri("/api/ingest")
                .header("content-type", "application/json")
                .body(Body::from(" ".repeat(256 * 1024 + 1)))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn operator_authentication_is_separate_from_agent_capabilities() {
    let app = app(None);
    let token = app
        .engine
        .lock()
        .unwrap()
        .issue_grant(1, 60, 2, now_ms())
        .unwrap()
        .token;
    let router = router(app);
    for (path, token, status) in [
        ("/", None, StatusCode::SEE_OTHER),
        ("/api/state", None, StatusCode::UNAUTHORIZED),
        (
            "/api/export",
            Some(token.as_str()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "/api/gateway/evidence",
            Some(token.as_str()),
            StatusCode::OK,
        ),
        (
            "/api/gateway/rules",
            Some(token.as_str()),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), status, "{path}");
    }
    let response = router
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/hive/action")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(
                    "csrf=test-session-token&op=grant&id=1&seconds=60&uses=100",
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn operator_cookie_logout_and_origin_boundary_are_enforced() {
    let router = router(app(None));
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("key=test-operator-key-32-characters-long"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["cache-control"], "no-store");
    let cookie = response.headers()["set-cookie"].to_str().unwrap();
    assert!(cookie.contains("HttpOnly") && cookie.contains("SameSite=Strict"));
    let cookie = cookie.split(';').next().unwrap().to_string();
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/state")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/action")
                .header("cookie", &cookie)
                .header("host", "127.0.0.1:8787")
                .header("origin", "https://outside.example")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=test-session-token&op=live"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/healthz")
                .header("host", "attacker.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/logout")
                .header("cookie", &cookie)
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from("csrf=test-session-token"))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/state")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn simultaneous_requests_cannot_spend_the_last_use_twice() {
    let app = app(None);
    let token = app
        .engine
        .lock()
        .unwrap()
        .issue_grant(1, 60, 1, now_ms())
        .unwrap()
        .token;
    let router = router(app);
    let request = || {
        Request::builder()
            .uri("/api/gateway/evidence")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let (a, b) = tokio::join!(router.clone().oneshot(request()), router.oneshot(request()));
    let statuses = [a.unwrap().status(), b.unwrap().status()];
    assert_eq!(statuses.iter().filter(|s| **s == StatusCode::OK).count(), 1);
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::FORBIDDEN)
            .count(),
        1
    );
}

#[tokio::test]
async fn operational_console_is_empty_and_refuses_demo_mutations() {
    let engine = Engine::memory().unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "test-session-token".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("test-operator-key-32-characters-long").unwrap(),
        ),
    };
    let router = router(app.clone());
    for path in [
        "/",
        "/sources",
        "/source/agent-gateway",
        "/cases",
        "/hive",
        "/workbench",
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header(
                        "authorization",
                        "Bearer test-operator-key-32-characters-long",
                    )
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let html = String::from_utf8(
            to_bytes(response.into_body(), 1_000_000)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        assert!(!html.contains("Inject scenario"));
        assert!(!html.contains("Synthetic environment"));
        assert!(html.contains("LIVE SOURCES"));
    }
    for op in ["scenario", "live", "simulate"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/action")
                    .header(
                        "authorization",
                        "Bearer test-operator-key-32-characters-long",
                    )
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(format!(
                        "csrf=test-session-token&op={op}&value=auth"
                    )))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    assert_eq!(
        app.engine
            .lock()
            .unwrap()
            .snapshot()
            .unwrap()
            .total_received,
        0
    );
}
#[tokio::test]
async fn scoped_ingestion_cannot_impersonate_journal_or_operator() {
    let mut engine = Engine::memory().unwrap();
    engine.configure_mode(false).unwrap();
    let token = engine
        .create_source("fixture", "api", "", now_ms())
        .unwrap()
        .unwrap();
    engine
        .create_source("journal", "journal", "", now_ms())
        .unwrap();
    let app = App {
        engine: Arc::new(Mutex::new(engine)),
        csrf: "test-session-token".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("test-operator-key-32-characters-long").unwrap(),
        ),
    };
    let router = router(app.clone());
    let input = serde_json::json!([{"time_ms":now_ms(),"source":"fixture","subject":"test-user","object":"test-resource","kind":"authentication","outcome":"deny","severity":3,"idempotency_key":"event-1"}]);
    for (path, key, expected) in [
        ("/api/ingest/fixture", "wrong", StatusCode::UNAUTHORIZED),
        ("/api/ingest/journal", token.as_str(), StatusCode::FORBIDDEN),
        (
            "/api/ingest/agent-gateway",
            token.as_str(),
            StatusCode::FORBIDDEN,
        ),
        ("/api/ingest/fixture", token.as_str(), StatusCode::OK),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("authorization", format!("Bearer {key}"))
                    .header("content-type", "application/json")
                    .body(Body::from(input.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected, "{path}");
    }
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/state")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.engine
            .lock()
            .unwrap()
            .snapshot()
            .unwrap()
            .total_received,
        1
    );
}
