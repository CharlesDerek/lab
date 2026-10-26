use crate::{
    engine::LabResult,
    identity::{Actor, Role},
    model::now_ms,
    web::{App, WebError},
};
use athernex_endpoint_protocol::{
    self as protocol,
    engine::{self as wire, SignedRelease},
    engine_fleet::{Health, Receipt},
};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path as FsPath, PathBuf},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, ReadBuf};
#[derive(Clone)]
struct Catalog(Arc<PathBuf>);
static DOWNLOADS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
struct Stream {
    file: tokio::io::Take<tokio::fs::File>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.file).poll_read(cx, buf)
    }
}
fn read(path: &FsPath, max: u64) -> LabResult<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > max {
        return Err("Engine catalog member is not a bounded regular file".into());
    }
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(max + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("Engine catalog member grew beyond its budget".into());
    }
    Ok(bytes)
}
pub fn key(root: &FsPath) -> LabResult<String> {
    let key = String::from_utf8(read(&root.join("public-key.txt"), 128)?)?
        .trim()
        .to_string();
    protocol::update::fingerprint(&key)?;
    Ok(key)
}
pub fn release(root: &FsPath, id: &str) -> LabResult<SignedRelease> {
    if !protocol::hex_id(id) {
        return Err("Invalid engine release identity".into());
    }
    let release: SignedRelease = serde_json::from_slice(&read(
        &root.join(id).join("manifest.json"),
        wire::MAX_MANIFEST,
    )?)?;
    release.authenticate(&key(root)?)?;
    if release.id()? != id {
        return Err("Engine catalog identity mismatch".into());
    }
    Ok(release)
}
pub fn routes(root: PathBuf) -> Router<App> {
    Router::new()
        .route("/engine-updates", get(portal))
        .route("/engine-updates/action", post(form_action))
        .route("/api/control/engines", get(list).post(propose))
        .route("/api/control/engines/{id}/review", post(review))
        .route(
            "/api/control/engine-rollouts",
            get(rollouts).post(propose_rollout),
        )
        .route(
            "/api/control/engine-rollouts/{id}/review",
            post(review_rollout),
        )
        .route("/api/endpoint/{endpoint}/engines/health", post(health))
        .route("/api/endpoint/{endpoint}/engines/poll", post(poll))
        .route(
            "/api/endpoint/{endpoint}/engines/{id}/install",
            post(install),
        )
        .route(
            "/api/endpoint/{endpoint}/engines/{id}/file/{index}",
            get(download),
        )
        .route("/api/endpoint/{endpoint}/engines/receipt", post(receipt))
        .layer(Extension(Catalog(Arc::new(root))))
}
fn checked<T>(r: LabResult<T>) -> Result<T, WebError> {
    r.map_err(|e| WebError(e.to_string()))
}
async fn rollouts(State(app): State<App>) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(json!(checked(e.engine_rollouts())?)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutProposal {
    request: crate::fleet_rollout::RolloutRequest,
    release_id: String,
}
async fn propose_rollout(
    State(app): State<App>,
    Extension(catalog): Extension<Catalog>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(p): Json<RolloutProposal>,
) -> Response {
    if !can_review(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = (|| -> LabResult<Value> {
        let release = release(&catalog.0, &p.release_id)?;
        let key = key(&catalog.0)?;
        let e = app.engine.lock().map_err(|_| "Engine unavailable")?;
        let id = e.propose_engine_rollout(p.request, &release, &key, now_ms())?;
        Ok(json!(e.engine_rollout(&id)?))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutReview {
    plan_hash: String,
    action: String,
}
async fn review_rollout(
    State(app): State<App>,
    Path(id): Path<String>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(p): Json<RolloutReview>,
) -> Response {
    if !can_review(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = (|| -> LabResult<()> {
        let e = app.engine.lock().map_err(|_| "Engine unavailable")?;
        e.review_engine_rollout(&id, &p.plan_hash, &p.action, now_ms())
    })();
    match result {
        Ok(()) => Json(json!({"reviewed":id})).into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
fn can_review(app: &App, actor: &Actor, headers: &HeaderMap) -> bool {
    matches!(actor.role, Role::Admin | Role::Responder)
        && (!crate::fleet_web::bearer(headers).is_empty()
            || headers
                .get("x-athernex-csrf")
                .and_then(|h| h.to_str().ok())
                .is_some_and(|v| crate::gateway::same_secret(v, &app.csrf)))
}
async fn list(State(app): State<App>) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(json!(checked(e.engine_deployments())?)))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proposal {
    endpoint: String,
    release_id: String,
    install: bool,
}
async fn propose(
    State(app): State<App>,
    Extension(catalog): Extension<Catalog>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(p): Json<Proposal>,
) -> Response {
    if !can_review(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = (|| -> LabResult<Value> {
        let key = key(&catalog.0)?;
        let release = release(&catalog.0, &p.release_id)?;
        let e = app.engine.lock().map_err(|_| "Engine unavailable")?;
        Ok(json!(e.propose_engine_update(
            &p.endpoint,
            &release,
            &key,
            p.install,
            now_ms()
        )?))
    })();
    match result {
        Ok(value) => Json(value).into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Review {
    plan_hash: String,
    approve: bool,
}
async fn review(
    State(app): State<App>,
    Path(id): Path<String>,
    Extension(catalog): Extension<Catalog>,
    Extension(actor): Extension<Actor>,
    headers: HeaderMap,
    Json(p): Json<Review>,
) -> Response {
    if !can_review(&app, &actor, &headers) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = (|| -> LabResult<()> {
        let key = key(&catalog.0)?;
        let e = app.engine.lock().map_err(|_| "Engine unavailable")?;
        e.review_engine_update(&id, &p.plan_hash, &key, p.approve, now_ms())
    })();
    match result {
        Ok(()) => Json(json!({"reviewed":id})).into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
async fn health(
    State(app): State<App>,
    Path(endpoint): Path<String>,
    headers: HeaderMap,
    Json(health): Json<Health>,
) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    checked(e.authenticate_endpoint(&endpoint, crate::fleet_web::bearer(&headers)))?;
    checked(e.endpoint_engine_health(&endpoint, &health, now_ms()))?;
    Ok(Json(json!({"committed":true})))
}
async fn poll(
    State(app): State<App>,
    Path(endpoint): Path<String>,
    Extension(catalog): Extension<Catalog>,
    headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    checked(e.authenticate_endpoint(&endpoint, crate::fleet_web::bearer(&headers)))?;
    // A catalog is optional until a deployment is proposed.
    if !catalog.0.join("public-key.txt").exists() {
        return Ok(Json(json!({"deployment":null})));
    }
    Ok(Json(
        json!({"deployment":checked(e.poll_engine_update(&endpoint,&checked(key(&catalog.0))?,now_ms()))?}),
    ))
}
async fn install(
    State(app): State<App>,
    Path((endpoint, id)): Path<(String, String)>,
    Extension(catalog): Extension<Catalog>,
    headers: HeaderMap,
) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    checked(e.authenticate_endpoint(&endpoint, crate::fleet_web::bearer(&headers)))?;
    Ok(Json(
        json!({"deployment":checked(e.authorize_engine_install(&endpoint,&id,&checked(key(&catalog.0))?,now_ms()))?}),
    ))
}
async fn receipt(
    State(app): State<App>,
    Path(endpoint): Path<String>,
    headers: HeaderMap,
    Json(receipt): Json<Receipt>,
) -> Result<Json<Value>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    checked(e.authenticate_endpoint(&endpoint, crate::fleet_web::bearer(&headers)))?;
    checked(e.finish_engine_delivery(&endpoint, &receipt, now_ms()))?;
    Ok(Json(
        json!({"committed":true,"state":checked(e.engine_deployment(&receipt.deployment_id))?.state}),
    ))
}
async fn download(
    State(app): State<App>,
    Path((endpoint, id, index)): Path<(String, String, usize)>,
    Extension(catalog): Extension<Catalog>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let permit = DOWNLOADS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
        .clone()
        .try_acquire_owned()
        .map_err(|_| WebError("Engine download capacity reached".into()))?;
    let deployment = {
        let e = app
            .engine
            .lock()
            .map_err(|_| WebError("Engine unavailable".into()))?;
        checked(e.authenticate_endpoint(&endpoint, crate::fleet_web::bearer(&headers)))?;
        checked(e.authorize_engine_download(&endpoint, &id, &checked(key(&catalog.0))?, now_ms()))?
    };
    let member = deployment
        .release
        .release
        .files
        .get(index)
        .cloned()
        .ok_or(WebError("Unknown signed engine file".into()))?;
    let count = member.bytes;
    let file = tokio::task::spawn_blocking(move || -> LabResult<fs::File> {
        let root = catalog
            .0
            .join(deployment.release.id()?)
            .join("content")
            .canonicalize()?;
        let path = root.join(&member.path).canonicalize()?;
        if !path.starts_with(&root) {
            return Err("Engine file leaves its release tree".into());
        }
        let mut file = fs::File::open(&path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() != member.bytes {
            return Err("Engine file size mismatch".into());
        }
        let mut hash = Sha256::new();
        let mut buffer = [0u8; 65536];
        let mut seen = 0u64;
        loop {
            let n = file.read(&mut buffer)?;
            if n == 0 {
                break;
            }
            seen += n as u64;
            if seen > member.bytes {
                return Err("Engine file grew beyond its signed budget".into());
            }
            hash.update(&buffer[..n]);
        }
        if seen != member.bytes || format!("{:x}", hash.finalize()) != member.sha256 {
            return Err("Engine file checksum mismatch".into());
        }
        use std::io::Seek;
        file.rewind()?;
        Ok(file)
    })
    .await
    .map_err(|_| WebError("Engine file worker failed".into()))?;
    use tokio::io::AsyncReadExt;
    let body = Body::from_stream(tokio_util::io::ReaderStream::new(Stream {
        file: tokio::fs::File::from_std(checked(file)?).take(count),
        _permit: permit,
    }));
    Ok((
        [
            ("content-type", "application/octet-stream"),
            ("content-length", &count.to_string()),
        ],
        body,
    )
        .into_response())
}

fn engine_form(csrf: &str, operation: &str, id: &str, hash: &str) -> String {
    use crate::render::escape;
    format!("<form class=control-form method=post action=/engine-updates/action><input type=hidden name=csrf value='{}'><input type=hidden name=operation value='{}'><input type=hidden name=id value='{}'><input type=hidden name=plan_hash value='{}'>",escape(csrf),escape(operation),escape(id),escape(hash))
}
async fn portal(
    State(app): State<App>,
    Extension(catalog): Extension<Catalog>,
    Extension(actor): Extension<Actor>,
) -> Result<axum::response::Html<String>, WebError> {
    use crate::render::escape;
    use std::fmt::Write;
    let mut releases = Vec::new();
    if catalog.0.join("public-key.txt").exists() {
        let entries = checked(fs::read_dir(&*catalog.0).map_err(Into::into))?;
        for entry in entries.take(65) {
            let entry = checked(entry.map_err(Into::into))?;
            let id = entry.file_name().to_string_lossy().into_owned();
            if protocol::hex_id(&id) {
                let release = checked(release(&catalog.0, &id))?;
                if release.release.expires_ms > now_ms() {
                    releases.push((id, release));
                }
            }
        }
        if releases.len() > 64 {
            return Err(WebError("Engine catalog exceeds its capacity".into()));
        }
    }
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let fleet = checked(e.fleet())?;
    let mut html=String::from("<section class=page-heading><div><div class=eyebrow>SIGNED ENGINE RELEASES</div><h1>Engine updates</h1><p>Stage verified ClamAV releases or approve automatic installation. A canary rollout preserves protection and collection health before promoting later groups.</p><a class=button href=/control>Security and capacity</a><a class=button href=/endpoint-updates>Agent and controller updates</a></div></section>");
    let permitted = matches!(actor.role, Role::Admin | Role::Responder);
    if permitted && !releases.is_empty() {
        let release_options = |html: &mut String| {
            html.push_str("<label>Signed engine release<select name=release_id required>");
            for (id, release) in &releases {
                write!(
                    html,
                    "<option value='{id}'>{} · {} · sequence {}</option>",
                    escape(&release.release.target),
                    escape(&release.release.version),
                    release.release.sequence
                )
                .unwrap();
            }
            html.push_str("</select></label>");
        };
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Device delivery</h2>");
        html.push_str(&engine_form(&app.csrf, "propose", "", ""));
        release_options(&mut html);
        html.push_str("<label>Endpoint<select name=endpoint required>");
        for endpoint in fleet.endpoints.iter().filter(|e| e.state == "active") {
            write!(
                html,
                "<option value='{}'>{}</option>",
                endpoint.id,
                escape(&endpoint.hostname)
            )
            .unwrap();
        }
        html.push_str("</select></label><label class=checkbox-label><input type=checkbox name=install> Approve automatic installation after staging</label><button class=button>Propose engine delivery</button></form></section><section class='panel controls-panel fleet-panel'><h2>Canary rollout</h2><p>Every selected device must have opted in to managed automatic engine updates and report fresh controller, protection and collection health.</p>");
        html.push_str(&engine_form(&app.csrf, "propose_rollout", "", ""));
        release_options(&mut html);
        html.push_str("<label>Name<input name=name required maxlength=64></label><label>Later group size<input name=batch_size type=number min=1 max=16 value=4 required></label><label>Healthy observation seconds<input name=observe_secs type=number min=60 max=3600 value=300 required></label><label>Finish within minutes<input name=deadline_minutes type=number min=3 max=10080 value=60 required></label>");
        for endpoint in fleet.endpoints.iter().filter(|e| e.state == "active") {
            write!(html,"<label>{}<select name='target_{}'><option value=skip>Skip</option><option value=canary>First group</option><option value=later>Later group</option></select></label>",escape(&endpoint.hostname),endpoint.id).unwrap();
        }
        html.push_str("<button class=button>Propose engine rollout</button></form></section>");
    } else if releases.is_empty() {
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Release catalog</h2><p>No unexpired signed engine releases are available. Publish a signed engine bundle to begin.</p></section>");
    }
    let rollouts = checked(e.engine_rollouts())?;
    for rollout in &rollouts {
        let plan = &rollout.plan;
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>{} · {}</h2><p>{}</p><p>Version {} · sequence {} · {} seconds observed health per group</p>",escape(&plan.request.name),escape(&rollout.state),escape(&rollout.reason),escape(&plan.release.release.version),plan.release.release.sequence,plan.request.observe_secs).unwrap();
        for member in &rollout.members {
            write!(
                html,
                "<p><a href='/endpoints/{}'>Device {}</a> · group {} · {} · {} seconds healthy</p>",
                member.endpoint_id,
                &member.endpoint_id[56..],
                member.cohort + 1,
                escape(member.deployment_state.as_deref().unwrap_or("waiting")),
                member
                    .healthy_since_ms
                    .zip(member.last_healthy_ms)
                    .map(|(a, b)| b.saturating_sub(a) / 1000)
                    .unwrap_or(0)
            )
            .unwrap();
            if plan
                .request
                .endpoint_ids
                .iter()
                .position(|id| id == &member.endpoint_id)
                .and_then(|index| plan.gates.get(index))
                .is_some_and(|gate| gate.macos_process_events)
            {
                html.push_str("<p>Required: healthy macOS Endpoint Security process coverage with the reviewed source policy; Linux and Windows sources cannot replace it.</p>");
            }
            if plan
                .request
                .endpoint_ids
                .iter()
                .position(|id| id == &member.endpoint_id)
                .and_then(|index| plan.gates.get(index))
                .is_some_and(|gate| gate.windows_process_events)
            {
                html.push_str("<p>Required: healthy Windows ETW process coverage; Linux process coverage cannot replace this source.</p>");
            }
            if plan
                .request
                .endpoint_ids
                .iter()
                .position(|id| id == &member.endpoint_id)
                .and_then(|index| plan.gates.get(index))
                .is_some_and(|gate| gate.windows_network_events)
            {
                html.push_str("<p>Required: healthy Windows ETW network coverage; Linux network or process coverage cannot replace this source.</p>");
            }
        }
        if permitted {
            let actions: &[&str] = match rollout.state.as_str() {
                "pending" => &["approve", "cancel"],
                "running" | "scheduled" => &["pause", "cancel"],
                "paused" => &["resume", "cancel"],
                _ => &[],
            };
            for action in actions {
                html.push_str(&engine_form(
                    &app.csrf,
                    "review_rollout",
                    &rollout.id,
                    &rollout.plan_hash,
                ));
                write!(html,"<input type=hidden name=action value='{action}'><button class=button>{action} exact engine rollout</button></form>").unwrap();
            }
        }
        write!(html,"<details><summary>Exact approval content</summary><p>Plan SHA-256</p><code>{}</code><pre class=raw-message>{}</pre></details></section>",rollout.plan_hash,escape(&checked(serde_json::to_string_pretty(plan).map_err(Into::into))?)).unwrap();
    }
    let grouped: std::collections::HashSet<&str> = rollouts
        .iter()
        .flat_map(|r| &r.members)
        .filter_map(|m| m.deployment_id.as_deref())
        .collect();
    html.push_str("<section class='panel controls-panel fleet-panel'><h2>Device receipts</h2>");
    for record in checked(e.engine_deployments())? {
        let name = fleet
            .endpoints
            .iter()
            .find(|e| e.id == record.deployment.endpoint_id)
            .map(|e| e.hostname.as_str())
            .unwrap_or(&record.deployment.endpoint_id);
        write!(
            html,
            "<article><h3>Engine {} · {}</h3><p><a href='/endpoints/{}'>{}</a> · {}</p><p>{} · sequence {}</p>",
            escape(&record.deployment.release.release.version),
            escape(&record.state),
            record.deployment.endpoint_id,
            escape(name),
            if record.deployment.install {
                "Installation approved by plan"
            } else {
                "Staging only"
            },
            escape(&record.deployment.release.release.target),
            record.deployment.release.release.sequence,
        )
        .unwrap();
        let in_rollout = grouped.contains(record.deployment.id.as_str());
        if in_rollout {
            html.push_str("<p>This device belongs to a reviewed engine rollout; use its group controls above.</p>");
        }
        if permitted && !in_rollout {
            let actions: &[(&str, &str)] = match record.state.as_str() {
                "pending" => &[
                    ("approve", "Approve exact engine delivery"),
                    ("cancel", "Cancel delivery"),
                ],
                "approved" | "downloading" | "staged" => &[("cancel", "Cancel delivery")],
                _ => &[],
            };
            for (op, label) in actions {
                html.push_str(&engine_form(
                    &app.csrf,
                    "review",
                    &record.deployment.id,
                    &record.plan_hash,
                ));
                write!(html,"<input type=hidden name=action value='{op}'><button class=button>{label}</button></form>").unwrap();
            }
        }
        write!(html,"<details><summary>Exact delivery approval</summary><p>Plan SHA-256</p><code>{}</code><pre class=raw-message>{}</pre></details>",record.plan_hash,escape(&checked(serde_json::to_string_pretty(&record.deployment).map_err(Into::into))?)).unwrap();
        for receipt in record
            .staging_receipt
            .iter()
            .chain(record.installation_receipt.iter())
        {
            write!(
                html,
                "<p>{}: {}</p>",
                escape(&receipt.outcome),
                escape(&receipt.detail)
            )
            .unwrap();
        }
        html.push_str("</article>");
    }
    html.push_str("</section>");
    Ok(axum::response::Html(
        crate::render::page(
            &checked(e.snapshot())?,
            "endpoints",
            &Default::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- ENDPOINT_CONTENT -->", &html),
    ))
}
async fn form_action(
    State(app): State<App>,
    Extension(catalog): Extension<Catalog>,
    Extension(actor): Extension<Actor>,
    axum::Form(fields): axum::Form<std::collections::HashMap<String, String>>,
) -> Response {
    if !matches!(actor.role, Role::Admin | Role::Responder)
        || !fields
            .get("csrf")
            .is_some_and(|v| crate::gateway::same_secret(v, &app.csrf))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let result = (|| -> LabResult<()> {
        let field = |name: &str| {
            fields
                .get(name)
                .map(|v| v.as_str())
                .ok_or_else(|| format!("Missing {name}"))
        };
        let now = now_ms();
        let e = app.engine.lock().map_err(|_| "Engine unavailable")?;
        match field("operation")? {
            "propose" => {
                let release = release(&catalog.0, field("release_id")?)?;
                e.propose_engine_update(
                    field("endpoint")?,
                    &release,
                    &key(&catalog.0)?,
                    fields.contains_key("install"),
                    now,
                )?;
            }
            "review" => {
                let action = field("action")?;
                if !["approve", "cancel"].contains(&action) {
                    return Err("Unknown review action".into());
                }
                e.review_engine_update(
                    field("id")?,
                    field("plan_hash")?,
                    &key(&catalog.0)?,
                    action == "approve",
                    now,
                )?;
            }
            "review_rollout" => {
                e.review_engine_rollout(field("id")?, field("plan_hash")?, field("action")?, now)?
            }
            "propose_rollout" => {
                let mut canaries = Vec::new();
                let mut later = Vec::new();
                for (name, value) in &fields {
                    if let Some(id) = name.strip_prefix("target_") {
                        match value.as_str() {
                            "canary" => canaries.push(id.into()),
                            "later" => later.push(id.into()),
                            "skip" => {}
                            _ => return Err("Invalid group selection".into()),
                        }
                    }
                }
                canaries.sort();
                later.sort();
                let count = canaries.len();
                canaries.extend(later);
                let deadline = field("deadline_minutes")?
                    .parse::<u64>()?
                    .checked_mul(60000)
                    .and_then(|v| now.checked_add(v))
                    .ok_or("Invalid deadline")?;
                let request = crate::fleet_rollout::RolloutRequest {
                    name: field("name")?.into(),
                    endpoint_ids: canaries,
                    canary_count: count,
                    batch_size: field("batch_size")?.parse()?,
                    observe_secs: field("observe_secs")?.parse()?,
                    not_before_ms: now,
                    deadline_ms: deadline,
                };
                e.propose_engine_rollout(
                    request,
                    &release(&catalog.0, field("release_id")?)?,
                    &key(&catalog.0)?,
                    now,
                )?;
            }
            _ => return Err("Unknown engine operation".into()),
        }
        Ok(())
    })();
    match result {
        Ok(()) => axum::response::Redirect::to("/engine-updates").into_response(),
        Err(error) => WebError(error.to_string()).into_response(),
    }
}
