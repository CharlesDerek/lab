use crate::{
    engine::LabResult,
    model::now_ms,
    render::{escape, size},
    storage::StorageConfig,
    web::{App, WebError},
};
use axum::{
    body::Body,
    extract::{Path, State},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::Deserialize;
use std::fmt::Write;
fn checked<T>(r: LabResult<T>) -> Result<T, WebError> {
    r.map_err(|e| WebError(e.to_string()))
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/storage", get(page))
        .route("/storage/action", post(action))
        .route("/api/storage", get(state))
        .route("/api/storage/segment/{id}", get(download))
}
async fn state(State(app): State<App>) -> Result<Json<crate::storage::StorageState>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(engine.storage_state())?))
}
async fn page(State(app): State<App>) -> Result<Html<String>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let state = checked(engine.storage_state())?;
    let snapshot = checked(engine.snapshot())?;
    let mut html=format!("<section class=page-heading><div><div class=eyebrow>EVIDENCE CAPACITY</div><h1>Storage and recovery</h1><p>{} · Live data {} / {} MiB · {} sealed segments</p></div></section>",if state.admission_ready{"Accepting telemetry"}else{"Admission paused: capacity needs attention"},size(state.used_bytes),state.config.ledger_mib,state.segments.len());
    if let Some(free) = state.free_disk_bytes {
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>Disk headroom</h2><p>{} available; admission reserves {} MiB.</p></section>",size(free),state.config.minimum_free_mib).unwrap();
    }
    write!(html,"<section class='panel controls-panel fleet-panel'><h2>Capacity policy</h2><form class=control-form method=post action=/storage/action><input type=hidden name=csrf value='{}'><input type=hidden name=op value=configure><label>Live ledger MiB<input type=number name=ledger_mib min=16 max=1024 value='{}' required></label><label>Attached evidence segments<input type=number name=segment_limit min=1 max=8 value='{}' required></label><label>Seal threshold (records)<input type=number name=segment_records min=64 max=65536 value='{}' required></label><label>Minimum free disk MiB<input type=number name=minimum_free_mib min=0 value='{}' required></label><button class='button primary'>Save capacity policy</button></form><form class=control-form method=post action=/storage/action><input type=hidden name=csrf value='{}'><input type=hidden name=op value=seal><button class=button>Seal cold evidence now</button></form><p>Sealing preserves historical lookup and replay protection. At the segment limit ingestion pauses; export a complete backup before changing retention. Individual segment downloads are evidence exports, not complete operational backups.</p></section>",escape(&app.csrf),state.config.ledger_mib,state.config.segment_limit,state.config.segment_records,state.config.minimum_free_mib,escape(&app.csrf)).unwrap();
    for segment in state.segments {
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>Evidence segment {}</h2><p>{} records · {}</p><code>{}</code><p><a class=button href='/api/storage/segment/{}'>Download sealed evidence</a></p></section>",segment.id,segment.events,size(segment.bytes),escape(&segment.sha256),segment.id).unwrap();
    }
    Ok(Html(
        crate::render::page(
            &snapshot,
            "storage",
            &crate::web::Filters::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- STORAGE_CONTENT -->", &html),
    ))
}
#[derive(Deserialize)]
struct StorageAction {
    csrf: String,
    op: String,
    #[serde(default)]
    ledger_mib: u64,
    #[serde(default)]
    segment_limit: usize,
    #[serde(default)]
    segment_records: usize,
    #[serde(default)]
    minimum_free_mib: u64,
}
async fn action(
    State(app): State<App>,
    Form(form): Form<StorageAction>,
) -> Result<Redirect, WebError> {
    if !crate::gateway::same_secret(&form.csrf, &app.csrf) {
        return Err(WebError("Session token rejected".into()));
    }
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    match form.op.as_str() {
        "configure" => checked(engine.configure_storage(
            StorageConfig {
                ledger_mib: form.ledger_mib,
                segment_limit: form.segment_limit,
                segment_records: form.segment_records,
                minimum_free_mib: form.minimum_free_mib,
            },
            now_ms(),
        ))?,
        "seal" => {
            checked(engine.seal_evidence(now_ms()))?;
        }
        _ => return Err(WebError("Unknown storage operation".into())),
    };
    Ok(Redirect::to("/storage"))
}
async fn download(State(app): State<App>, Path(id): Path<u64>) -> Result<Response, WebError> {
    let path = {
        let engine = app
            .engine
            .lock()
            .map_err(|_| WebError("Engine unavailable".into()))?;
        checked(engine.segment_path(id))?
    };
    let file = tokio::fs::File::open(path)
        .await
        .map_err(|e| WebError(e.to_string()))?;
    Ok((
        [
            ("content-type", "application/vnd.sqlite3".to_owned()),
            (
                "content-disposition",
                format!("attachment; filename=athernex-evidence-{id}.sqlite3"),
            ),
        ],
        Body::from_stream(tokio_util::io::ReaderStream::new(file)),
    )
        .into_response())
}
