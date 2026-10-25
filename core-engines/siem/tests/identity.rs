use athernex_siem::{
    engine::Engine,
    identity::{verify_audit, AuditCheckpoint, Role},
    model::now_ms,
    web::{self, App},
};
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
fn app() -> App {
    App {
        engine: Arc::new(Mutex::new(Engine::memory().unwrap())),
        csrf: "fixture-csrf".into(),
        ingest_token: None,
        operator: Arc::new(
            athernex_siem::auth::OperatorAuth::new("fixture-bootstrap-key-long-enough").unwrap(),
        ),
    }
}
#[tokio::test]
async fn roles_rotation_revocation_and_named_cookie_apply_to_legacy_and_control_routes() {
    let app = app();
    let now = now_ms();
    let viewer = app
        .engine
        .lock()
        .unwrap()
        .issue_operator("reader", Role::Viewer, now + 60000, now)
        .unwrap();
    let analyst = app
        .engine
        .lock()
        .unwrap()
        .issue_operator("analyst", Role::Analyst, now + 60000, now)
        .unwrap();
    let router = web::router(app.clone());
    for path in ["/api/state", "/control", "/api/control"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(path)
                    .header("authorization", format!("Bearer {}", viewer.token))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = router
        .clone()
        .oneshot(
            Request::post("/action")
                .header("authorization", format!("Bearer {}", viewer.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response=router.clone().oneshot(Request::post("/api/control").header("authorization",format!("Bearer {}",analyst.token)).header("content-type","application/json").body(Body::from(r#"{"operation":"issue_operator","id":"escalated","role":"admin","expires_ms":1900000000000}"#)).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    let response = router
        .clone()
        .oneshot(
            Request::post("/login")
                .header("content-type", "application/x-www-form-urlencoded")
                .body(Body::from(format!("key={}", viewer.token)))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/control")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let rotated = app
        .engine
        .lock()
        .unwrap()
        .issue_operator("reader", Role::Viewer, now + 60000, now)
        .unwrap();
    for (header, value) in [
        ("cookie", cookie),
        ("authorization", format!("Bearer {}", viewer.token)),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/control")
                    .header(header, value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    app.engine
        .lock()
        .unwrap()
        .revoke_operator("reader", now)
        .unwrap();
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/control")
                .header("authorization", format!("Bearer {}", rotated.token))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn browser_control_mutations_require_csrf_and_tokens_never_appear_in_state() {
    let app = app();
    let router = web::router(app.clone());
    let session = app
        .operator
        .login("fixture-bootstrap-key-long-enough")
        .unwrap();
    let body = format!(
        r#"{{"operation":"issue_operator","id":"reader","role":"viewer","expires_ms":{}}}"#,
        now_ms() + 60000
    );
    for csrf in [None, Some("wrong"), Some("fixture-csrf")] {
        let mut request = Request::post("/api/control")
            .header("cookie", format!("athernex_operator={session}"))
            .header("content-type", "application/json");
        if let Some(csrf) = csrf {
            request = request.header("x-athernex-csrf", csrf);
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::from(body.clone())).unwrap())
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if csrf == Some("fixture-csrf") {
                StatusCode::OK
            } else {
                StatusCode::FORBIDDEN
            }
        );
        if csrf == Some("fixture-csrf") {
            let issued: serde_json::Value =
                serde_json::from_slice(&to_bytes(response.into_body(), 10000).await.unwrap())
                    .unwrap();
            let state = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri("/api/control")
                        .header("cookie", format!("athernex_operator={session}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let raw =
                String::from_utf8(to_bytes(state.into_body(), 100000).await.unwrap().to_vec())
                    .unwrap();
            assert!(!raw.contains(issued["token"].as_str().unwrap()));
        }
    }
}
#[test]
fn backup_restores_operator_revocations_and_audit_checkpoint_detects_truncation() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live.db");
    let now = now_ms();
    let mut e = Engine::open(&path).unwrap();
    e.configure_mode(false).unwrap();
    let credential = e
        .issue_operator("responder", Role::Responder, now + 60000, now)
        .unwrap();
    e.revoke_operator("responder", now).unwrap();
    let before = e.audit_checkpoint().unwrap();
    let records = e.export_audit(0, 1000).unwrap();
    let start = AuditCheckpoint {
        sequence: 0,
        sha256: "0".repeat(64),
    };
    verify_audit(&records, &start, &before).unwrap();
    assert!(verify_audit(&records[..records.len() - 1], &start, &before).is_err());
    let backup = dir.path().join("backup");
    e.backup_to(&backup, now).unwrap();
    let checkpoint = e.audit_checkpoint().unwrap();
    drop(e);
    let restored =
        athernex_siem::storage::restore_backup(&backup, &dir.path().join("restored")).unwrap();
    let e = Engine::open(&restored).unwrap();
    assert!(e.authenticate_operator(&credential.token, now).is_err());
    assert_eq!(e.audit_checkpoint().unwrap(), checkpoint);
    assert!(athernex_siem::storage::restore_backup(&backup, &dir.path().join("restored")).is_err());
}

#[test]
fn startup_rejects_audit_record_changes_even_when_sqlite_is_structurally_valid() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("db");
    let e = Engine::open(&path).unwrap();
    let now = now_ms();
    e.issue_operator("audited", Role::Viewer, now + 60000, now)
        .unwrap();
    drop(e);
    let db = rusqlite::Connection::open(&path).unwrap();
    db.execute("UPDATE audit_chain SET detail='rewritten' WHERE sequence=(SELECT min(sequence) FROM audit_chain)",[]).unwrap();
    drop(db);
    assert!(Engine::open(&path)
        .err()
        .unwrap()
        .to_string()
        .contains("Audit sequence or integrity"));
}
