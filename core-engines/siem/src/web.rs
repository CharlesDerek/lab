use crate::{
    engine::{Engine, LabResult},
    model::*,
    render,
};
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::Deserialize;
use std::sync::{Arc, Mutex};

#[derive(Clone)]
pub struct App {
    pub engine: Arc<Mutex<Engine>>,
    pub csrf: String,
    pub ingest_token: Option<String>,
    pub operator: Arc<crate::auth::OperatorAuth>,
}

#[derive(Debug, Default, Deserialize)]
pub struct Filters {
    #[serde(default)]
    pub omit: String,
    #[serde(default)]
    pub q: String,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub page: usize,
    #[serde(default)]
    pub notice: String,
}

pub struct WebError(pub String);
impl IntoResponse for WebError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Html(format!("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><link rel=stylesheet href=/assets/app.css><title>Request held · Athernex</title><main class=error-page><div class=eyebrow>ATHERNEX / REQUEST HELD</div><h1>The boundary held.</h1><p>{}</p><a class=button href=/>Return to the console</a></main>",render::escape(&self.0)))).into_response()
    }
}

fn checked<T>(result: LabResult<T>) -> Result<T, WebError> {
    result.map_err(|e| WebError(e.to_string()))
}

pub fn router(app: App) -> Router {
    Router::new()
        .route("/sources",get(sources))
        .route("/source/{id}",get(source))
        .route("/sources/action",post(source_action))
        .route("/api/ingest/{id}",post(source_ingest))
        .route("/cases",get(cases))
        .route("/case/{id}",get(case))
        .route("/cases/action",post(case_action))
        .route("/api/cases/{id}/export",get(case_export))
        .route("/event/{id}/original",get(original_event))
        .route("/readyz",get(readiness))
        .route("/login",get(login_get).post(login_post))
        .route("/logout",post(logout))
        .route("/hive",get(hive))
        .route("/agent/{id}",get(agent))
        .route("/task/{id}",get(task))
        .route("/retention",get(retention))
        .route("/archive/{id}",get(archive))
        .route("/archive/{block}/event/{id}",get(archive_event))
        .route("/hive/action",post(hive_action))
        .route("/retention/configure",post(retention_configure))
        .route("/api/gateway/{resource}",get(gateway_read).post(gateway_append))
        .route("/",get(overview))
        .route("/investigate",get(investigate))
        .route("/detections",get(detections))
        .route("/workbench",get(workbench))
        .route("/research",get(research))
        .route("/event/{id}",get(event))
        .route("/incident/{id}",get(incident))
        .route("/action",post(action))
        .route("/api/state",get(api_state))
        .route("/api/events",get(api_events))
        .route("/api/ingest",post(api_ingest))
        .route("/api/export",get(api_export))
        .route("/healthz",get(||async {Json(serde_json::json!({"status":"alive","service":"athernex-siem","schema":"AEF1"}))}))
        .route("/assets/app.css",get(||async {([("content-type","text/css; charset=utf-8"),("cache-control","no-cache")],include_str!("../assets/app.css"))}))
        .route("/favicon.svg",get(||async {([("content-type","image/svg+xml")],"<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'><rect width='64' height='64' rx='16' fill='#081813'/><path d='M16 47 32 14l16 33M23 36h18' fill='none' stroke='#64e3eb' stroke-width='5'/></svg>" )}))
        .layer(DefaultBodyLimit::max(256*1024))
        .layer(axum::middleware::map_response(|mut response:Response|async move {
            let headers=response.headers_mut();
            headers.insert("content-security-policy","default-src 'self'; style-src 'self'; script-src 'none'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'".parse().unwrap());
            headers.insert("x-content-type-options","nosniff".parse().unwrap());
            headers.insert("cache-control","no-store".parse().unwrap());
            headers.insert("referrer-policy","same-origin".parse().unwrap());
            response
        }))
        .layer(axum::middleware::from_fn_with_state(app.clone(),operator_boundary))
        .with_state(app)
}

fn page(
    app: &App,
    view: &str,
    filters: &Filters,
    selected: Option<i64>,
) -> Result<Html<String>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let mut snapshot = checked(engine.snapshot())?;
    if view == "archive" {
        snapshot.events = checked(engine.archive_events(selected.unwrap_or(0)))?;
    }
    Ok(Html(render::page(
        &snapshot, view, filters, selected, &app.csrf,
    )))
}
async fn overview(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "overview", &filters, None)
}
async fn investigate(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "investigate", &filters, None)
}
async fn detections(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "detections", &filters, None)
}
async fn workbench(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "workbench", &filters, None)
}
async fn research(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "research", &filters, None)
}
async fn event(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "event", &Filters::default(), Some(id))
}
async fn incident(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "incident", &Filters::default(), Some(id))
}

#[derive(Deserialize)]
struct Action {
    csrf: String,
    op: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    back: String,
}

async fn action(State(app): State<App>, Form(form): Form<Action>) -> Result<Redirect, WebError> {
    if form.csrf != app.csrf {
        return Err(WebError(
            "Session token rejected. Reload the console and try again.".into(),
        ));
    }
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let now = now_ms();
    let id = || {
        form.value
            .parse::<i64>()
            .map_err(|_| WebError("Invalid identifier".into()))
    };
    if !engine.demo && ["scenario", "live", "simulate"].contains(&form.op.as_str()) {
        return Err(WebError(
            "Synthetic controls require a separate --demo database".into(),
        ));
    }
    match form.op.as_str() {
        "scenario" => {
            checked(engine.scenario(&form.value, now))?;
        }
        "flush" => {
            checked(engine.flush(now))?;
        }
        "live" => {
            engine.live = !engine.live;
        }
        "rule" => {
            checked(engine.toggle_rule(&form.value, now))?;
        }
        "propose" => {
            checked(engine.propose(id()?, now))?;
        }
        "approve" | "reject" | "simulate" | "execute" => {
            checked(engine.review_plan(id()?, &form.op, now))?;
        }
        "resolve" => {
            checked(engine.close_finding(id()?, now))?;
        }
        _ => return Err(WebError("Unknown operation".into())),
    }
    let back = if [
        "/",
        "/investigate",
        "/detections",
        "/workbench",
        "/research",
        "/hive",
        "/retention",
    ]
    .contains(&form.back.as_str())
    {
        form.back.as_str()
    } else {
        "/"
    };
    Ok(Redirect::to(back))
}

async fn api_state(State(app): State<App>) -> Result<Json<serde_json::Value>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let s = checked(engine.snapshot())?;
    Ok(Json(
        serde_json::json!({"schema":"AEF1","retained_events":s.events.len(),"total_received":s.total_received,"duplicates":s.duplicates,"open_findings":s.findings.iter().filter(|f|f.status=="open").count(),"payload_bytes":s.payload_bytes,"normalized_json_bytes":s.normalized_json_bytes,"database_bytes":s.database_bytes,"wal_bytes":s.wal_bytes,"dictionary_entries":s.dictionary_entries,"live":s.live,"limits":{"events":MAX_EVENTS,"findings":MAX_FINDINGS,"batch":MAX_BATCH},"mode":if s.demo {"demo"} else {"operational"},"sources":s.sources,"cases":s.cases,"storage_error":s.storage_error,"model_provider":"none","hive":s.hive,"retention":s.retention}),
    ))
}

async fn api_events(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Json<serde_json::Value>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let events = checked(engine.events())?;
    let matches = render::filter_events(&events, &filters);
    let page = filters.page.min(MAX_EVENTS / 50);
    Ok(Json(
        serde_json::json!({"total":matches.len(),"page":page,"page_size":50,"events":matches.into_iter().skip(page*50).take(50).collect::<Vec<_>>()}),
    ))
}

async fn api_ingest(
    State(app): State<App>,
    headers: HeaderMap,
    Json(inputs): Json<Vec<InputEvent>>,
) -> Result<Json<serde_json::Value>, WebError> {
    let token = app.ingest_token.as_ref().ok_or_else(|| {
        WebError(
            "API ingest is disabled; set ATHERNEX_INGEST_TOKEN before starting the server.".into(),
        )
    })?;
    if headers.get("authorization").and_then(|h| h.to_str().ok())
        != Some(format!("Bearer {token}").as_str())
    {
        return Err(WebError("Ingest token rejected".into()));
    }
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    if !engine.demo {
        return Err(WebError(
            "Register a source in /sources and use /api/ingest/{source}".into(),
        ));
    }
    let inserted = checked(engine.ingest(&inputs, now_ms()))?;
    Ok(Json(
        serde_json::json!({"accepted":inserted,"duplicate":inputs.len()-inserted,"schema":"AEF1"}),
    ))
}

async fn api_export(State(app): State<App>) -> Result<Response, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let snapshot = checked(engine.snapshot())?;
    let body = serde_json::to_string_pretty(&snapshot).map_err(|e| WebError(e.to_string()))?;
    Ok((
        [
            ("content-type", "application/json"),
            (
                "content-disposition",
                "attachment; filename=athernex-lab-evidence.json",
            ),
        ],
        body,
    )
        .into_response())
}

async fn operator_boundary(
    State(app): State<App>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    // DNS rebinding: this local service accepts only loopback hostnames.
    if let Some(host) = request.headers().get("host").and_then(|h| h.to_str().ok()) {
        let name = host.split(':').next().unwrap_or("");
        if !["localhost", "127.0.0.1"].contains(&name) {
            return StatusCode::FORBIDDEN.into_response();
        }
    }
    if request.method() != axum::http::Method::GET {
        if let Some(origin) = request
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok())
        {
            let expected = format!(
                "http://{}",
                request
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("")
            );
            if origin != expected {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    let path = request.uri().path();
    let public = path == "/login"
        || path == "/healthz"
        || path == "/readyz"
        || path == "/favicon.svg"
        || path.starts_with("/assets/")
        || path == "/api/ingest"
        || path.starts_with("/api/ingest/")
        || path.starts_with("/api/gateway/");
    if !public && !app.operator.authorized(request.headers()) {
        return if path.starts_with("/api/") || request.method() != axum::http::Method::GET {
            (
                StatusCode::UNAUTHORIZED,
                Json(serde_json::json!({"error":"operator_authentication_required"})),
            )
                .into_response()
        } else {
            Redirect::to("/login").into_response()
        };
    }
    next.run(request).await
}
async fn login_get() -> Html<String> {
    Html(crate::auth::login_page(""))
}
#[derive(Deserialize)]
struct Login {
    key: String,
}
async fn login_post(State(app): State<App>, Form(form): Form<Login>) -> Response {
    match app.operator.login(&form.key) {
        Ok(token) => {
            let mut response = Redirect::to("/").into_response();
            response.headers_mut().insert(
                "set-cookie",
                format!(
                    "athernex_operator={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600"
                )
                .parse()
                .unwrap(),
            );
            response
        }
        Err(_) => (
            StatusCode::UNAUTHORIZED,
            Html(crate::auth::login_page(
                "Operator key rejected. Check your private key file or interactive terminal.",
            )),
        )
            .into_response(),
    }
}
#[derive(Deserialize)]
struct Csrf {
    csrf: String,
}
async fn logout(
    State(app): State<App>,
    headers: HeaderMap,
    Form(form): Form<Csrf>,
) -> Result<Response, WebError> {
    check_csrf(&app, &form.csrf)?;
    app.operator.logout(&headers);
    let mut response = Redirect::to("/login").into_response();
    response.headers_mut().insert(
        "set-cookie",
        "athernex_operator=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
            .parse()
            .unwrap(),
    );
    Ok(response)
}
fn check_csrf(app: &App, csrf: &str) -> Result<(), WebError> {
    if !crate::gateway::same_secret(csrf, &app.csrf) {
        Err(WebError("Session token rejected".into()))
    } else {
        Ok(())
    }
}
async fn hive(State(app): State<App>) -> Result<Html<String>, WebError> {
    page(&app, "hive", &Filters::default(), None)
}
async fn agent(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "agent", &Filters::default(), Some(id))
}
async fn task(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "task", &Filters::default(), Some(id))
}
async fn retention(State(app): State<App>) -> Result<Html<String>, WebError> {
    page(&app, "retention", &Filters::default(), None)
}
async fn archive(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "archive", &Filters::default(), Some(id))
}
#[derive(Deserialize)]
struct HiveAction {
    csrf: String,
    op: String,
    #[serde(default)]
    id: i64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    role: String,
    #[serde(default)]
    title: String,
    #[serde(default)]
    resource: String,
    #[serde(default)]
    minutes: u64,
    #[serde(default)]
    seconds: u64,
    #[serde(default)]
    uses: u64,
}
async fn hive_action(
    State(app): State<App>,
    Form(form): Form<HiveAction>,
) -> Result<Response, WebError> {
    check_csrf(&app, &form.csrf)?;
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let now = now_ms();
    let path = match form.op.as_str() {
        "register" => format!(
            "/agent/{}",
            checked(engine.register_agent(&form.name, &form.role, now))?
        ),
        "task" => format!(
            "/task/{}",
            checked(engine.create_task(form.id, &form.title, &form.resource, form.minutes, now))?
        ),
        "grant" => {
            let grant = checked(engine.issue_grant(form.id, form.seconds, form.uses, now))?;
            let snapshot = checked(engine.snapshot())?;
            return Ok(
                Html(render::grant_reveal(&snapshot, &grant, form.id, &app.csrf)).into_response(),
            );
        }
        "quarantine" | "restore" => {
            checked(engine.set_agent_state(
                form.id,
                if form.op == "quarantine" {
                    "quarantined"
                } else {
                    "active"
                },
                now,
            ))?;
            format!("/agent/{}", form.id)
        }
        "complete" => {
            checked(engine.finish_task(form.id, now))?;
            format!("/task/{}", form.id)
        }
        "revoke" => {
            checked(engine.revoke_grant(form.id, now))?;
            "/hive".into()
        }
        "exercise" => {
            if !engine.demo {
                return Err(WebError("Boundary exercises require --demo".into()));
            }
            checked(engine.exercise_hive(form.id, now))?;
            format!("/agent/{}", form.id)
        }
        _ => return Err(WebError("Unknown hive operation".into())),
    };
    Ok(Redirect::to(&path).into_response())
}
#[derive(Deserialize)]
struct RetentionForm {
    csrf: String,
    days: u64,
    cap_kib: u64,
    seconds: u64,
}
async fn retention_configure(
    State(app): State<App>,
    Form(form): Form<RetentionForm>,
) -> Result<Redirect, WebError> {
    check_csrf(&app, &form.csrf)?;
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    checked(engine.configure_retention(form.days, form.cap_kib, form.seconds, now_ms()))?;
    Ok(Redirect::to("/retention"))
}
fn bearer(headers: &HeaderMap) -> &str {
    headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}
async fn gateway_read(
    State(app): State<App>,
    Path(resource): Path<String>,
    headers: HeaderMap,
) -> Result<Response, WebError> {
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let decision = checked(engine.access(bearer(&headers), &resource, "read", None, now_ms()))?;
    if !decision.allowed {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"decision":decision})),
        )
            .into_response());
    }
    let data = match resource.as_str() {
        "evidence" => serde_json::to_value(checked(engine.findings())?).unwrap(),
        "rules" => serde_json::json!({"enabled":checked(engine.enabled_rules())?}),
        "archive" => serde_json::to_value(checked(engine.retention())?).unwrap(),
        _ => {
            let id = resource
                .strip_prefix("finding-")
                .and_then(|v| v.parse::<i64>().ok())
                .ok_or_else(|| WebError("No resource adapter".into()))?;
            let finding = checked(engine.findings())?.into_iter().find(|f| f.id == id);
            match finding {Some(f)=>serde_json::to_value(f).unwrap(),None=>return Ok((StatusCode::NOT_FOUND,Json(serde_json::json!({"decision":decision,"error":"finding_no_longer_retained"}))).into_response())}
        }
    };
    Ok(Json(serde_json::json!({"decision":decision,"data":data})).into_response())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendNote {
    text: String,
}
async fn gateway_append(
    State(app): State<App>,
    Path(resource): Path<String>,
    headers: HeaderMap,
    Json(note): Json<AppendNote>,
) -> Result<Response, WebError> {
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let decision = checked(engine.access(
        bearer(&headers),
        &resource,
        "append",
        Some(&note.text),
        now_ms(),
    ))?;
    Ok((
        if decision.allowed {
            StatusCode::OK
        } else {
            StatusCode::FORBIDDEN
        },
        Json(serde_json::json!({"decision":decision})),
    )
        .into_response())
}

async fn archive_event(
    State(app): State<App>,
    Path((block, id)): Path<(i64, i64)>,
) -> Result<Html<String>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let mut snapshot = checked(engine.snapshot())?;
    snapshot.events = checked(engine.archive_events(block))?;
    snapshot.selected_archive = Some(block);
    let html = render::page(&snapshot, "event", &Filters::default(), Some(id), &app.csrf);
    Ok(Html(html.replace(
        "href=/investigate>← Event explorer",
        &format!("href=/archive/{block}>← Archive block"),
    )))
}

async fn sources(State(app): State<App>) -> Result<Html<String>, WebError> {
    page(&app, "sources", &Filters::default(), None)
}
async fn source(State(app): State<App>, Path(id): Path<String>) -> Result<Html<String>, WebError> {
    page(
        &app,
        "source",
        &Filters {
            q: id,
            ..Filters::default()
        },
        None,
    )
}
async fn cases(
    State(app): State<App>,
    Query(filters): Query<Filters>,
) -> Result<Html<String>, WebError> {
    page(&app, "cases", &filters, None)
}
async fn case(State(app): State<App>, Path(id): Path<i64>) -> Result<Html<String>, WebError> {
    page(&app, "case", &Filters::default(), Some(id))
}
#[derive(Deserialize)]
struct SourceAction {
    csrf: String,
    op: String,
    id: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    selector: String,
}
async fn source_action(
    State(app): State<App>,
    Form(form): Form<SourceAction>,
) -> Result<Response, WebError> {
    check_csrf(&app, &form.csrf)?;
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let token = if form.op == "create" {
        checked(engine.create_source(&form.id, &form.kind, &form.selector, now_ms()))?
    } else {
        checked(engine.source_action(&form.id, &form.op, now_ms()))?
    };
    if let Some(token) = token {
        let s = checked(engine.snapshot())?;
        let mut html = render::page(
            &s,
            "source",
            &Filters {
                q: form.id.clone(),
                ..Filters::default()
            },
            None,
            &app.csrf,
        );
        let reveal=format!("<section class='panel token-reveal'><div class=eyebrow>SOURCE CREDENTIAL / SHOWN ONCE</div><h2>Store this token securely.</h2><p>Use it as a Bearer credential for <code>/api/ingest/{}</code>. Every event must name this source. Rotation invalidates the old token immediately.</p><pre class=secret-token>{}</pre></section>",render::escape(&form.id),render::escape(&token));
        html = html.replace("<main id=main>", &format!("<main id=main>{reveal}"));
        return Ok(Html(html).into_response());
    }
    Ok(Redirect::to(&format!("/source/{}", form.id)).into_response())
}
async fn source_ingest(
    State(app): State<App>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(inputs): Json<Vec<InputEvent>>,
) -> Result<Response, WebError> {
    let mut engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    // A bearer HTTP request can never impersonate the journal adapter or internal gateway.
    if !checked(engine.sources())?
        .iter()
        .any(|s| s.id == id && s.kind == "api")
    {
        return Ok((
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({"error":"source_credential_rejected"})),
        )
            .into_response());
    }
    match engine.ingest_source(&id,Some(bearer(&headers)),&inputs,None,0,now_ms()) {
        Ok(accepted)=>Ok(Json(serde_json::json!({"accepted":accepted,"duplicate":inputs.len()-accepted,"durability":"buffered; inspect rolling memory for flush status"})).into_response()),
        Err(e) if e.to_string()=="Source credential rejected"=>Ok((StatusCode::UNAUTHORIZED,Json(serde_json::json!({"error":"source_credential_rejected"}))).into_response()),
        Err(e)=>Err(WebError(e.to_string()))
    }
}
#[derive(Deserialize, Default)]
struct CaseAction {
    csrf: String,
    op: String,
    #[serde(default)]
    id: i64,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    title: String,
    #[serde(default)]
    owner: String,
    #[serde(default)]
    status: String,
    #[serde(default)]
    severity: u8,
    #[serde(default)]
    note: String,
    #[serde(default)]
    target: String,
    #[serde(default)]
    event: u64,
    #[serde(default)]
    block: Option<i64>,
    #[serde(default)]
    exported: String,
}
fn evidence(engine: &Engine, id: u64, block: Option<i64>) -> LabResult<DisplayEvent> {
    if let Some(block) = block {
        return engine
            .archive_events(block)?
            .into_iter()
            .find(|e| e.event.id == id)
            .ok_or("Archive evidence no longer retained".into());
    }
    engine
        .events()?
        .into_iter()
        .chain(engine.cases()?.into_iter().flat_map(|c| c.evidence))
        .find(|e| e.event.id == id)
        .ok_or("Evidence no longer retained".into())
}
async fn case_action(
    State(app): State<App>,
    Form(form): Form<CaseAction>,
) -> Result<Redirect, WebError> {
    check_csrf(&app, &form.csrf)?;
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let now = now_ms();
    let id = match form.op.as_str() {
        "create" => checked(engine.create_case(&form.title, form.severity, now))?,
        "update" => {
            checked(engine.update_case(
                form.id,
                form.version,
                crate::operations::CaseUpdate {
                    owner: &form.owner,
                    status: &form.status,
                    severity: form.severity,
                    note: &form.note,
                },
                now,
            ))?;
            form.id
        }
        "attach" => {
            let (id, version) = form
                .target
                .split_once(':')
                .ok_or(WebError("Select an investigation".into()))?;
            let id = id.parse().map_err(|_| WebError("Invalid case".into()))?;
            let version = version
                .parse()
                .map_err(|_| WebError("Invalid case revision".into()))?;
            let event = checked(evidence(&engine, form.event, form.block))?;
            checked(engine.attach_case_event(id, version, event, now))?;
            id
        }
        "delete" if form.exported == "yes" => {
            checked(engine.delete_case(form.id, form.version, now))?;
            return Ok(Redirect::to("/cases"));
        }
        _ => {
            return Err(WebError(
                "Unknown investigation action or missing export confirmation".into(),
            ))
        }
    };
    Ok(Redirect::to(&format!("/case/{id}")))
}
async fn case_export(State(app): State<App>, Path(id): Path<i64>) -> Result<Response, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let case = checked(engine.cases())?
        .into_iter()
        .find(|c| c.id == id)
        .ok_or(WebError("Investigation not found".into()))?;
    let data = serde_json::to_string_pretty(&case).map_err(|e| WebError(e.to_string()))?;
    Ok((
        [
            ("content-type", "application/json"),
            (
                "content-disposition",
                "attachment; filename=athernex-investigation.json",
            ),
        ],
        data,
    )
        .into_response())
}
async fn readiness(State(app): State<App>) -> Response {
    let Ok(engine) = app.engine.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    let now = now_ms();
    let ready = engine.storage_error.is_empty()
        && engine.sources().is_ok_and(|sources| {
            sources.iter().all(|s| {
                s.kind != "journal"
                    || !s.enabled
                    || (s.error.is_empty()
                        && s.last_poll_ms > 0
                        && now.saturating_sub(s.last_poll_ms) < 120_000)
            })
        });
    (if ready {StatusCode::OK} else {StatusCode::SERVICE_UNAVAILABLE},Json(serde_json::json!({"status":if ready {"ready"}else{"degraded"},"mode":if engine.demo {"demo"}else{"operational"}}))).into_response()
}
#[derive(Deserialize)]
struct OriginalQuery {
    block: Option<i64>,
}
async fn original_event(
    State(app): State<App>,
    Path(id): Path<u64>,
    Query(query): Query<OriginalQuery>,
) -> Result<Html<String>, WebError> {
    let (source, event, snapshot) = {
        let engine = app
            .engine
            .lock()
            .map_err(|_| WebError("Engine unavailable".into()))?;
        let event = checked(evidence(&engine, id, query.block))?;
        let source = checked(engine.sources())?
            .into_iter()
            .find(|s| s.id == event.source_label && s.kind == "journal")
            .ok_or(WebError("This event has no local journal source".into()))?;
        (source, event, checked(engine.snapshot())?)
    };
    let cursor = &event
        .context
        .as_ref()
        .ok_or(WebError("No journal reference retained".into()))?
        .journal_cursor;
    let rows = checked(crate::collector::read_journal(&source, Some(cursor)).await)?;
    let original = rows
        .iter()
        .find(|r| r.get("__CURSOR").and_then(|v| v.as_str()) == Some(cursor.as_str()))
        .and_then(|r| r.get("MESSAGE"))
        .and_then(|v| v.as_str());
    let message=original.map(|m|m.chars().take(16_384).collect::<String>()).unwrap_or_else(||"The exact record is unavailable. Journald may have rotated it; compact facts remain available.".into());
    let mut s = snapshot;
    s.events = vec![event];
    s.selected_archive = query.block;
    let html = render::page(&s, "event", &Filters::default(), Some(id as i64), &app.csrf);
    Ok(Html(html.replace("</main>",&format!("<section class='panel controls-panel'><div class=eyebrow>ON-DEMAND / OS JOURNAL</div><h2>Original message</h2><p>Read from the exact journal cursor. Not copied to the SIEM archive. Display capped at 16,384 characters.</p><pre class=raw-message>{}</pre></section></main>",render::escape(&message)))))
}
