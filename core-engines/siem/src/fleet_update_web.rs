use crate::{
    engine::LabResult,
    model::now_ms,
    render::escape,
    web::{App, WebError},
};
use athernex_endpoint_protocol::{
    self as protocol,
    update::{self as wire, DeploymentReceipt, SignedRelease},
};
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Extension, Form, Json, Router,
};
use serde::Deserialize;
use std::{
    fmt::Write as _,
    fs::{self, OpenOptions},
    io::{Read, Seek, SeekFrom},
    path::{Path as FsPath, PathBuf},
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

// The permit follows the response body, so slow clients cannot keep an
// unbounded number of open release streams after the handler returns.
struct ReleaseStream {
    reader: tokio::io::Take<tokio::fs::File>,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsyncRead for ReleaseStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.reader).poll_read(cx, buffer)
    }
}
static DOWNLOADS: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

fn checked<T>(result: LabResult<T>) -> Result<T, WebError> {
    result.map_err(|e| WebError(e.to_string()))
}
pub fn catalog_root() -> PathBuf {
    std::env::var_os("ATHERNEX_ENDPOINT_RELEASES")
        .map(PathBuf::from)
        .unwrap_or_else(|| ".athernex/endpoint-releases".into())
}
fn file(path: &FsPath, max: u64) -> LabResult<fs::File> {
    let mut options = OpenOptions::new();
    options.read(true);
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() > max {
        return Err("Release catalog entry must be a bounded regular file".into());
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > max {
        return Err("Release catalog file exceeds its type/byte budget".into());
    }
    Ok(file)
}
fn read(path: &FsPath, max: u64) -> LabResult<Vec<u8>> {
    let mut bytes = Vec::new();
    file(path, max)?.take(max + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max {
        return Err("Release catalog file grew beyond its byte budget".into());
    }
    Ok(bytes)
}
pub(crate) fn public_key(root: &FsPath) -> LabResult<String> {
    let key = String::from_utf8(read(&root.join("public-key.txt"), 128)?)?;
    wire::fingerprint(&key)?;
    Ok(key)
}
pub(crate) fn release(root: &FsPath, id: &str, key: &str) -> LabResult<SignedRelease> {
    if !protocol::hex_id(id) {
        return Err("Invalid release reference".into());
    }
    let release: SignedRelease =
        serde_json::from_slice(&read(&root.join(format!("{id}.json")), wire::MAX_MANIFEST)?)?;
    release.authenticate(key)?;
    if release.id()? != id {
        return Err("Release reference does not match its signed manifest".into());
    }
    if file(
        &root.join(format!("{}.bin", release.release.sha256)),
        wire::MAX_BINARY,
    )?
    .metadata()?
    .len()
        != release.release.bytes
    {
        return Err("Release binary size does not match its signed manifest".into());
    }
    Ok(release)
}
pub(crate) fn catalog(root: &FsPath, key: &str) -> LabResult<Vec<SignedRelease>> {
    let mut releases = Vec::new();
    for (entries, entry) in fs::read_dir(root)?.enumerate() {
        if entries >= 128 {
            return Err("Release catalog directory entry budget reached".into());
        }
        let path = entry?.path();
        if path.extension().is_some_and(|s| s == "json") {
            if releases.len() >= 32 {
                return Err("Release catalog capacity exceeded".into());
            }
            let id = path
                .file_stem()
                .and_then(|s| s.to_str())
                .ok_or("Invalid catalog entry")?;
            releases.push(release(root, id, key)?);
        }
    }
    releases.sort_by_key(|r| std::cmp::Reverse(r.release.sequence));
    Ok(releases)
}
pub fn routes(root: PathBuf) -> Router<App> {
    Router::new()
        .merge(crate::fleet_rollout_web::routes())
        .route("/endpoint-updates", get(portal))
        .route("/endpoints/updates/action", post(action))
        .route("/api/endpoint-updates", get(records))
        .route("/api/endpoint/{id}/updates/poll", post(poll))
        .route("/api/endpoint/{id}/updates/{deployment}/start", post(start))
        .route(
            "/api/endpoint/{id}/updates/{deployment}/binary",
            get(binary),
        )
        .route("/api/endpoint/{id}/updates/receipt", post(receipt))
        .route(
            "/api/endpoint/{id}/updates/{deployment}/install",
            post(install),
        )
        .route(
            "/api/endpoint/{id}/updates/install-receipt",
            post(installation_receipt),
        )
        .layer(Extension(Arc::new(root)))
}
#[derive(Deserialize)]
struct PageQuery {
    #[serde(default = "last_row")]
    before: u64,
}
fn last_row() -> u64 {
    i64::MAX as u64
}
async fn records(
    State(app): State<App>,
    Query(query): Query<PageQuery>,
) -> Result<Json<Vec<crate::fleet_update::DeploymentRecord>>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(
        engine.endpoint_deployments(query.before, now_ms()),
    )?))
}
async fn poll(State(app): State<App>, Path(id): Path<String>, headers: HeaderMap) -> Response {
    crate::fleet_web::endpoint_op(&app, &id, &headers, |e| {
        e.poll_endpoint_update(&id, now_ms())
    })
}
async fn start(
    State(app): State<App>,
    Path((id, deployment)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    crate::fleet_web::endpoint_op(&app, &id, &headers, |e| {
        e.authorized_endpoint_update(&id, &deployment, now_ms())
    })
}
async fn receipt(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(receipt): Json<DeploymentReceipt>,
) -> Response {
    crate::fleet_web::endpoint_op(&app, &id, &headers, |e| {
        e.endpoint_update_receipt(&id, &receipt, now_ms())?;
        Ok(serde_json::json!({"committed":true}))
    })
}
async fn install(
    State(app): State<App>,
    Path((id, deployment)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    crate::fleet_web::endpoint_op(&app, &id, &headers, |e| {
        e.start_endpoint_installation(&id, &deployment, now_ms())
    })
}
async fn installation_receipt(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(receipt): Json<wire::InstallationReceipt>,
) -> Response {
    crate::fleet_web::endpoint_op(&app, &id, &headers, |e| {
        e.endpoint_installation_receipt(&id, &receipt, now_ms())?;
        Ok(serde_json::json!({"committed":true}))
    })
}
#[derive(Deserialize)]
struct ChunkQuery {
    offset: u64,
}
async fn binary(
    State(app): State<App>,
    Extension(root): Extension<Arc<PathBuf>>,
    Path((id, deployment)): Path<(String, String)>,
    headers: HeaderMap,
    Query(query): Query<ChunkQuery>,
) -> Response {
    let result = (|| -> LabResult<_> {
        let engine = app.engine.lock().map_err(|_| "Engine unavailable")?;
        engine.authenticate_endpoint(&id, crate::fleet_web::bearer(&headers))?;
        let deployment = engine.authorized_endpoint_update(&id, &deployment, now_ms())?;
        if query.offset >= deployment.release.release.bytes || query.offset % wire::CHUNK_BYTES != 0
        {
            return Err("Invalid release chunk offset".into());
        }
        Ok(deployment.release.release)
    })();
    let release = match result {
        Ok(release) => release,
        Err(e) => return crate::fleet_web::failure(e),
    };
    let permit = match DOWNLOADS
        .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(8)))
        .clone()
        .try_acquire_owned()
    {
        Ok(permit) => permit,
        Err(_) => {
            return crate::fleet_web::failure("Release download capacity reached; retry later")
        }
    };
    let count = wire::CHUNK_BYTES.min(release.bytes - query.offset);
    let result = tokio::task::spawn_blocking(move || -> LabResult<fs::File> {
        let mut source = file(
            &root.join(format!("{}.bin", release.sha256)),
            wire::MAX_BINARY,
        )?;
        if source.metadata()?.len() != release.bytes {
            return Err("Release binary size changed".into());
        }
        source.seek(SeekFrom::Start(query.offset))?;
        Ok(source)
    })
    .await;
    match result {
        Ok(Ok(source)) => (
            [
                ("content-type", "application/octet-stream".to_string()),
                ("content-length", count.to_string()),
            ],
            axum::body::Body::from_stream(tokio_util::io::ReaderStream::new(ReleaseStream {
                reader: tokio::fs::File::from_std(source).take(count),
                _permit: permit,
            })),
        )
            .into_response(),
        Ok(Err(e)) => crate::fleet_web::failure(e),
        Err(e) => crate::fleet_web::failure(e),
    }
}
fn form(csrf: &str, op: &str, id: &str) -> String {
    format!("<form class=control-form method=post action=/endpoints/updates/action><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{}'><input type=hidden name=id value='{}'>",escape(csrf),escape(op),escape(id))
}
async fn portal(
    State(app): State<App>,
    Extension(root): Extension<Arc<PathBuf>>,
    Query(query): Query<PageQuery>,
) -> Result<Html<String>, WebError> {
    let catalog = if root.join("public-key.txt").exists() {
        let key = checked(public_key(&root))?;
        let releases = checked(catalog(&root, &key))?;
        Some((key, releases))
    } else {
        None
    };
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let fleet = checked(engine.fleet())?;
    let records = checked(engine.endpoint_deployments(query.before, now_ms()))?;
    let snapshot = checked(engine.snapshot())?;
    let mut html=String::from("<section class=page-heading><div><div class=eyebrow>ENDPOINT RELEASES</div><h1>Signed endpoint updates</h1><p>Review agent or controller release delivery to each device. Choose staging only or approved automatic installation on a device with local permission. Automatic installation restarts management and protection during verification.</p><a class=button href=/endpoints>Back to endpoints</a> <a class=button href=/endpoint-rollouts>Manage fleet rollouts</a></div></section>");
    if let Some((key, releases)) = &catalog {
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>Trusted release catalog</h2><p>Release key fingerprint</p><code>{}</code><p>{} signed manifests. Expired releases cannot be delivered.</p></section>",escape(&wire::fingerprint(key).map_err(WebError)?),releases.len()).unwrap();
    } else {
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>No release catalog configured</h2><p>Provision signed release manifests and their binaries before proposing an update.</p></section>");
    }
    for endpoint in &fleet.endpoints {
        write!(
            html,
            "<section class='panel controls-panel fleet-panel'><h2>{}</h2><code>{}</code>",
            escape(&endpoint.hostname),
            escape(&endpoint.id)
        )
        .unwrap();
        for (component, health) in [
            (wire::Component::Agent, &endpoint.health.updates),
            (
                wire::Component::Controller,
                &endpoint.health.controller_updates,
            ),
        ] {
            write!(html, "<h3>{} updates</h3>", component.label()).unwrap();
            if let Some(health) = health {
                write!(html,"<p>Update state: {} · channel {} · sequence floor {}</p><p>Managed delivery: {} · last connection {}</p><p>{}</p>",escape(&health.state),escape(&health.channel),health.highwater,if health.managed {"enabled"} else {"disabled"},crate::render::age(endpoint.last_seen_ms),escape(&health.error)).unwrap();
                if let Some(installed) = &health.installed_release {
                    write!(
                        html,
                        "<p>Installed release</p><code>{}</code>",
                        escape(installed)
                    )
                    .unwrap();
                }
                if let Some(staged) = &health.staged_release {
                    write!(html, "<p>Staged release</p><code>{}</code>", escape(staged)).unwrap();
                }
                if health.managed && endpoint.state == "active" {
                    if let Some((key, releases)) = &catalog {
                        let platform = match endpoint.platform {
                            protocol::Platform::Linux => "linux",
                            protocol::Platform::Macos => "macos",
                            protocol::Platform::Windows => "windows",
                        };
                        let target = format!("{platform}-{}", endpoint.arch);
                        let eligible = releases
                            .iter()
                            .filter(|r| {
                                r.release.expires_ms > now_ms()
                                    && r.release.issued_ms <= now_ms().saturating_add(60_000)
                                    && r.release.sequence > health.highwater
                                    && r.release.channel == health.channel
                                    && r.release.target == target
                                    && wire::fingerprint(key).ok().as_deref()
                                        == Some(&health.key_fingerprint)
                                    && now_ms().saturating_sub(endpoint.last_seen_ms) <= 120_000
                            })
                            .collect::<Vec<_>>();
                        if eligible.is_empty() {
                            html.push_str("<p>No release currently matches this device's platform, trust key, channel, sequence and recent connection.</p>");
                        } else {
                            html.push_str(&form(&app.csrf, "propose", &endpoint.id));
                            write!(
                                html,
                                "<input type=hidden name=component value='{}'>",
                                if component == wire::Component::Agent {
                                    "agent"
                                } else {
                                    "controller"
                                }
                            )
                            .unwrap();
                            html.push_str("<label>Signed release<select name=release_id required>");
                            for release in eligible {
                                write!(
                                    html,
                                    "<option value='{}'>{} · {} · sequence {}</option>",
                                    release.id().map_err(WebError)?,
                                    escape(&release.release.target),
                                    escape(&release.release.version),
                                    release.release.sequence
                                )
                                .unwrap();
                            }
                            html.push_str("</select></label>");
                            if health.automatic && health.supervised {
                                html.push_str("<label class=checkbox-label><input type=checkbox name=install> Automatically install after staging (restarts endpoint services)</label>");
                            }
                            html.push_str(
                                "<button class=button>Propose signed delivery</button></form>",
                            );
                        }
                    }
                }
            } else {
                html.push_str("<p>This component has no locally configured release policy.</p>");
            }
        }
        html.push_str("</section>");
    }
    html.push_str("<section class='panel controls-panel fleet-panel'><h2>Deployment history</h2><p>Cancellation stops further delivery authorization. Already staged bytes remain on the endpoint; an installation that has started must complete or recover.</p>");
    for record in &records {
        let deployment = &record.deployment;
        write!(html,"<article><p>Component: {}</p><h3>{} · sequence {} · {}</h3><p>Endpoint</p><code>{}</code><p>Release</p><code>{}</code><p>Executable SHA-256</p><code>{}</code>",deployment.component.label(),escape(&deployment.release.release.version),deployment.release.release.sequence,escape(&record.state),escape(&deployment.endpoint_id),escape(&deployment.release_id),escape(&deployment.release.release.sha256)).unwrap();
        write!(
            html,
            "<p>Installation: {}</p>",
            if deployment.install {
                "automatic installation included in this approval"
            } else {
                "staging only; local maintenance required"
            }
        )
        .unwrap();
        if record.state == "pending" {
            html.push_str(&form(&app.csrf, "approve", &deployment.id));
            write!(
                html,
                "<button class='button primary'>{}</button></form>",
                if deployment.install {
                    "Approve delivery and installation"
                } else {
                    "Approve signed delivery"
                }
            )
            .unwrap();
        }
        if ["pending", "approved", "ready_to_install"].contains(&record.state.as_str()) {
            html.push_str(&form(&app.csrf, "cancel", &deployment.id));
            html.push_str("<button class=button>Cancel delivery</button></form>");
        }
        if let Some(receipt) = &record.installation {
            write!(
                html,
                "<p>Installation receipt: {}</p><p>{}</p>",
                escape(&receipt.outcome),
                escape(&receipt.detail)
            )
            .unwrap();
        }
        if let Some(receipt) = &record.receipt {
            write!(
                html,
                "<p>Endpoint receipt: {}</p><p>{}</p>",
                escape(&receipt.outcome),
                escape(&receipt.detail)
            )
            .unwrap();
        }
        html.push_str("</article>");
    }
    html.push_str("</section>");
    if records.len() == 64 {
        write!(
            html,
            "<a class=button href='/endpoint-updates?before={}'>Older deployments</a>",
            records.last().unwrap().row
        )
        .unwrap();
    }
    Ok(Html(
        crate::render::page(
            &snapshot,
            "endpoints",
            &crate::web::Filters::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- ENDPOINT_CONTENT -->", &html),
    ))
}
#[derive(Deserialize)]
struct Action {
    csrf: String,
    op: String,
    id: String,
    #[serde(default)]
    release_id: String,
    #[serde(default)]
    install: String,
    #[serde(default)]
    component: wire::Component,
}
async fn action(
    State(app): State<App>,
    Extension(root): Extension<Arc<PathBuf>>,
    Form(form): Form<Action>,
) -> Result<Redirect, WebError> {
    if !crate::gateway::same_secret(&form.csrf, &app.csrf) {
        return Err(WebError("Session token rejected".into()));
    }
    let proposed = if form.op == "propose" {
        let key = checked(public_key(&root))?;
        Some((checked(release(&root, &form.release_id, &key))?, key))
    } else {
        None
    };
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    match form.op.as_str() {
        "propose" => {
            let (release, key) = proposed.unwrap();
            checked(engine.propose_component_release(
                &form.id,
                &release,
                &key,
                form.component,
                form.install == "on",
                now_ms(),
            ))?;
        }
        "approve" => checked(engine.review_endpoint_update(&form.id, true, now_ms()))?,
        "cancel" => checked(engine.review_endpoint_update(&form.id, false, now_ms()))?,
        _ => return Err(WebError("Unknown deployment action".into())),
    }
    Ok(Redirect::to("/endpoint-updates"))
}
