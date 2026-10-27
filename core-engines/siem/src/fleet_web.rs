use crate::{
    engine::LabResult,
    fleet::Fleet,
    model::now_ms,
    render::escape,
    web::{App, WebError},
};
use athernex_endpoint_protocol::{
    self as protocol, Action, EndpointEvent, Enrollment, Heartbeat, Platform, Receipt,
};
use axum::{
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
    Form, Json, Router,
};
use serde::{Deserialize, Serialize};
use std::{fmt::Write as _, io::Write, path::Path as FsPath};

fn macos_network_endpoint(
    value: Option<&protocol::macos_network_events::MacosNetworkEndpoint>,
) -> String {
    value
        .map(|v| {
            format!(
                "{} port {}{}",
                v.address,
                v.port,
                v.scope_id
                    .map(|n| format!(" scope {n}"))
                    .unwrap_or_default()
            )
        })
        .unwrap_or_else(|| "Not reported".into())
}
fn macos_authentication_token(value: &str) -> String {
    if value.is_empty() {
        return "Empty token".into();
    }
    let bytes = value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            std::str::from_utf8(pair)
                .ok()
                .and_then(|s| u8::from_str_radix(s, 16).ok())
        })
        .collect::<Option<Vec<_>>>();
    if let Some(bytes) = bytes.filter(|_| value.len().is_multiple_of(2)) {
        if let Ok(text) = std::str::from_utf8(&bytes) {
            if !text.chars().any(char::is_control) {
                return text.into();
            }
        }
    }
    format!("Bytes (hex): {value}")
}
fn optional_macos_authentication_token(value: Option<&str>) -> String {
    value
        .map(macos_authentication_token)
        .unwrap_or_else(|| "Not reported".into())
}

fn checked<T>(r: LabResult<T>) -> Result<T, WebError> {
    r.map_err(|e| WebError(e.to_string()))
}
fn csrf(app: &App, value: &str) -> Result<(), WebError> {
    if crate::gateway::same_secret(value, &app.csrf) {
        Ok(())
    } else {
        Err(WebError("Session token rejected".into()))
    }
}
pub(crate) fn bearer(h: &HeaderMap) -> &str {
    h.get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or("")
}
pub fn routes() -> Router<App> {
    Router::new()
        .route("/endpoints", get(portal))
        .route("/endpoints/{id}", get(observations_page))
        .route("/endpoints/action", post(action))
        .route("/endpoints/installer", post(installer))
        .route("/api/endpoints", get(fleet_api))
        .route("/api/endpoints/{id}/events", get(observations_api))
        .route("/api/endpoint/enroll", post(enroll))
        .route("/api/endpoint/{id}/heartbeat", post(heartbeat))
        .route("/api/endpoint/{id}/events", post(events))
        .route("/api/endpoint/{id}/poll", post(poll))
        .route("/api/endpoint/{id}/command/{command}/start", post(start))
        .route("/api/endpoint/{id}/receipt", post(receipt))
}

#[derive(Deserialize)]
struct ObservationQuery {
    #[serde(default = "observation_start")]
    before: u64,
}
fn observation_start() -> u64 {
    i64::MAX as u64
}
async fn observations_api(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<ObservationQuery>,
) -> Result<Json<Vec<crate::fleet::EndpointObservation>>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(engine.endpoint_observations(
        &id,
        query.before,
        64,
    ))?))
}
async fn observations_page(
    State(app): State<App>,
    Path(id): Path<String>,
    Query(query): Query<ObservationQuery>,
) -> Result<Html<String>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let endpoint = checked(engine.fleet())?
        .endpoints
        .into_iter()
        .find(|e| e.id == id)
        .ok_or(WebError("Endpoint not found".into()))?;
    let records = checked(engine.endpoint_observations(&id, query.before, 32))?;
    let mut html = format!("<section class=page-heading><div><div class=eyebrow>ENDPOINT EVIDENCE</div><h1>{}</h1><p>Authentication reports, kernel process and network tracker events, process and socket snapshots, malware and scan observations. Available evidence depends on enabled collectors; subscription gaps and activity between snapshots may be missing.</p><a class=button href=/endpoints>Back to endpoints</a></div></section>",escape(&endpoint.hostname));
    for record in &records {
        let event = &record.event;
        write!(html,"<section class='panel controls-panel fleet-panel'><h2>{} · observation {}</h2><p>Observed {} UTC · {} · <a href='/event/{}'>Normalized evidence</a></p><dl class=fact-grid>",escape(&event.kind),record.evidence_id,crate::render::time(event.time_ms),crate::render::age(event.time_ms),record.evidence_id).unwrap();
        let mut facts = Vec::new();
        if let Some(telemetry) = &event.telemetry {
            if let protocol::telemetry::Telemetry::Authentication { event } = telemetry {
                facts.extend([
                    (
                        "Authentication",
                        event
                            .service_outcome()
                            .map(|outcome| format!("{outcome:?}"))
                            .unwrap_or_else(|| {
                                "Module failure; service outcome not reported".into()
                            }),
                    ),
                    (
                        "Reported account",
                        event
                            .claimed_user
                            .clone()
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    ("Method", event.mechanism.clone()),
                    (
                        "Source address",
                        event
                            .source_ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Source port",
                        event
                            .source_port
                            .map(|port| port.to_string())
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    ("Journal producer", event.journal.executable.clone()),
                    (
                        "Reporter PID / UID",
                        format!(
                            "{} / {}",
                            event.journal.reporter_pid, event.journal.reporter_uid
                        ),
                    ),
                    ("Journal cursor", event.journal.cursor.clone()),
                    ("Original report", event.journal.message.clone()),
                ]);
            }
            if let protocol::telemetry::Telemetry::WindowsAuthentication { event } = telemetry {
                facts.extend([
                    (
                        "Windows logon",
                        event
                            .service_outcome()
                            .map(|value| format!("{value:?}"))
                            .unwrap_or_else(|| {
                                "NewCredentials session; outbound authentication not established"
                                    .into()
                            }),
                    ),
                    (
                        "Target account",
                        event
                            .target_user
                            .clone()
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Target domain",
                        event
                            .target_domain
                            .clone()
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Target SID",
                        event
                            .target_sid
                            .clone()
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    ("Logon type", event.logon_type.to_string()),
                    (
                        "Authentication package",
                        event.authentication_package.clone(),
                    ),
                    (
                        "Source address",
                        event
                            .source_ip
                            .map(|ip| ip.to_string())
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Source port",
                        event
                            .source_port
                            .map(|port| port.to_string())
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Reported caller PID",
                        event
                            .caller_pid
                            .map(|pid| pid.to_string())
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Reported caller image",
                        event
                            .caller_image
                            .clone()
                            .unwrap_or_else(|| "Not reported".into()),
                    ),
                    (
                        "Security record",
                        format!(
                            "{} · event {} · version {}",
                            event.record_id, event.event_code, event.version
                        ),
                    ),
                    ("Reported computer", event.computer.clone()),
                    ("Original XML", event.xml.clone()),
                ]);
            }
            if let protocol::telemetry::Telemetry::NetworkEvent {
                stream_id,
                namespace,
                sequence,
                monotonic_ns,
                event,
                ..
            } = telemetry
            {
                facts.extend([
                    ("Tracker change", format!("{:?}",event.change)),
                    ("Protocol", event.protocol.label().to_uppercase()),
                    ("Original tuple", format!("{} → {}",event.original.source,event.original.destination)),
                    ("Reply tuple", format!("{} → {}",event.reply.source,event.reply.destination)),
                    ("Network namespace", namespace.to_string()),
                    ("Subscription", stream_id.clone()),
                    ("Receive sequence / monotonic ns", format!("{sequence} / {monotonic_ns}")),
                    ("Attribution", "Process owner and firewall verdict are not established".into()),
                    ("Tracker details", serde_json::to_string(event).unwrap_or_default()),
                    ("Counters", "Cumulative tracker counters; not byte deltas. Removal does not establish socket close".into()),
                ]);
            }
            if let protocol::telemetry::Telemetry::ProcessEvent {
                stream_id, event, ..
            } = telemetry
            {
                facts.extend([
                    ("Kernel event", event.change.name().into()),
                    ("PID", event.pid.to_string()),
                    ("Thread ID", event.tid.to_string()),
                    ("Subscription", stream_id.clone()),
                    ("Kernel time (ns)", event.monotonic_ns.to_string()),
                    (
                        "CPU / sequence",
                        format!("{} / {}", event.cpu, event.sequence),
                    ),
                    (
                        "Kernel details",
                        serde_json::to_string(&event.change).unwrap_or_default(),
                    ),
                ]);
            }
            if let protocol::telemetry::Telemetry::MacosAuthentication { event } = telemetry {
                use protocol::macos_authentication::MacosAuthenticationPayload;
                let process = &event.original.event_process;
                facts.extend([
                    ("macOS authentication mechanism", crate::fleet::macos_authentication_mechanism(&event.mechanism).into()),
                    ("Reported authentication result", if event.reported_success { "Successful" } else { "Failed" }.into()),
                    ("Outcome qualification", "This is a mechanism/factor report, not a completed login, session or prevention verdict. Multiple factors and fallbacks are not counted as separate failed logins".into()),
                    ("Reported event process PID / version", format!("{} / {}", process.pid(), process.pid_version())),
                    ("Reported instigator PID / version", event.original.authentication.instigator().map(|p| format!("{} / {}", p.pid(), p.pid_version())).unwrap_or_else(|| "Not reported".into())),
                    ("Source stream", event.original.stream_id.clone()),
                    ("Collector receipt sequence", event.original.receipt_sequence.to_string()),
                    ("ES per-type / global sequence", format!("{} / {}", event.original.seq_num, event.original.global_seq_num)),
                    ("Time qualification", "Endpoint Security event timespec; no login/session start time or cross-host precision guarantee. Mach timebase is separate collector metadata".into()),
                    ("Retained authentication projection", "Selected native fields are retained in the original observation JSON, not the full native message. No password, private key material, biometric template, arguments or environment is captured".into()),
                    ("Identity qualification", "Event process and optional instigator are distinct source-reported roles. Record names, UID and token identifiers do not establish a current process or shared account across devices or mechanisms".into()),
                ]);
                match &event.original.authentication {
                    MacosAuthenticationPayload::OpenDirectory {
                        record_type_hex,
                        record_name_hex,
                        node_name_hex,
                        db_path_hex,
                        ..
                    } => {
                        facts.extend([
                            ("Reported OD record type", macos_authentication_token(record_type_hex)),
                            ("Reported OD record name", macos_authentication_token(record_name_hex)),
                            ("Reported OD node", macos_authentication_token(node_name_hex)),
                            ("Reported OD database path", optional_macos_authentication_token(db_path_hex.as_deref())),
                            ("OD record qualification", "The record name is scoped by its record type and node; it is not necessarily a username".into()),
                        ]);
                    }
                    MacosAuthenticationPayload::TouchId {
                        mode, has_uid, uid, ..
                    } => {
                        facts.extend([
                            (
                                "Reported Touch ID mode",
                                if *mode == 0 {
                                    "Verification"
                                } else {
                                    "Identification"
                                }
                                .into(),
                            ),
                            ("Source UID present", has_uid.to_string()),
                            (
                                "Reported factor UID",
                                uid.map(|v| v.to_string())
                                    .unwrap_or_else(|| "Not reported".into()),
                            ),
                        ]);
                    }
                    MacosAuthenticationPayload::Token {
                        pubkey_hash_hex,
                        token_id_hex,
                        kerberos_principal_hex,
                        ..
                    } => {
                        facts.extend([
                            (
                                "Reported public-key hash",
                                macos_authentication_token(pubkey_hash_hex),
                            ),
                            (
                                "Reported token identifier",
                                macos_authentication_token(token_id_hex),
                            ),
                            (
                                "Reported Kerberos principal",
                                optional_macos_authentication_token(
                                    kerberos_principal_hex.as_deref(),
                                ),
                            ),
                        ]);
                    }
                    MacosAuthenticationPayload::AutoUnlock {
                        username_hex,
                        purpose,
                    } => {
                        facts.extend([
                            (
                                "Reported Auto Unlock username",
                                macos_authentication_token(username_hex),
                            ),
                            (
                                "Reported Auto Unlock purpose",
                                if *purpose == 1 {
                                    "Machine unlock"
                                } else {
                                    "Authorization prompt"
                                }
                                .into(),
                            ),
                        ]);
                    }
                }
            }
            if let protocol::telemetry::Telemetry::MacosProcessEvent { event } = telemetry {
                let subject = event.subject();
                let hex = &subject.executable.path_bytes_hex;
                let bytes: Vec<u8> = hex
                    .as_bytes()
                    .chunks_exact(2)
                    .map(|pair| {
                        let digit = |v: u8| {
                            if v.is_ascii_digit() {
                                v - b'0'
                            } else {
                                v - b'a' + 10
                            }
                        };
                        digit(pair[0]) * 16 + digit(pair[1])
                    })
                    .collect();
                let path = std::str::from_utf8(&bytes)
                    .map(|v| v.to_owned())
                    .unwrap_or_else(|_| format!("Non-UTF-8 bytes: {hex}"));
                facts.extend([
                    ("macOS ES notification", crate::fleet::macos_process_change(&event.change).into()),
                    ("Reported actor PID / version", format!("{} / {}", event.actor_pid, event.actor_pid_version)),
                    ("Reported subject PID / version", format!("{} / {}", event.pid, event.pid_version)),
                    ("Reported parent PID", subject.ppid.to_string()),
                    ("Reported executable path", path),
                    ("Source path truncated", subject.executable.path_truncated.to_string()),
                    ("Subscription", event.original.stream_id.clone()),
                    ("Collector receipt sequence", event.original.receipt_sequence.to_string()),
                    ("ES per-type / global sequence", format!("{} / {}", event.original.seq_num, event.original.global_seq_num)),
                    ("Source Mach ticks", event.original.mach_time.to_string()),
                    ("Time qualification", "Endpoint Security event timespec; not process start time or a cross-host precision guarantee. Mach timebase is separate collector metadata".into()),
                    ("Attribution", "Actor and exec target or fork child remain distinct. Reported audit tokens, parent IDs and paths do not establish a current process, complete lifetime, verified executable or ancestry".into()),
                    ("Retained ES projection", "Selected native fields and collector metadata are preserved in the original observation JSON. This is not the full native message; argv, environment and signing details are excluded. NOTIFY results are not this product's prevention verdict".into()),
                ]);
                if let protocol::macos_process_events::MacosProcessPayload::Exit {
                    raw_wait_status,
                } = &event.original.event
                {
                    facts.push(("Reported raw wait status", raw_wait_status.to_string()));
                }
            }
            if let protocol::telemetry::Telemetry::WindowsProcessEvent { event } = telemetry {
                facts.extend([
                    ("Windows ETW change", crate::fleet::windows_process_change(&event.change).into()),
                    ("Reported PID", event.pid.to_string()),
                    ("Reported parent PID", event.parent_pid.map(|value| value.to_string()).unwrap_or_else(|| "Not reported".into())),
                    ("Reported session", event.session_id.map(|value| value.to_string()).unwrap_or_else(|| "Not reported".into())),
                    ("Reported process key", event.unique_process_key.map(|value| value.to_string()).unwrap_or_else(|| "Not reported".into())),
                    ("Reported exit status", event.exit_status.map(|value| value.to_string()).unwrap_or_else(|| "Not reported".into())),
                    ("Reported SID", event.user_sid.clone().unwrap_or_else(|| "Not reported".into())),
                    ("Reported image bytes (hex)", event.image_name_bytes_hex.clone().unwrap_or_else(|| "Not reported".into())),
                    ("Reported command line", event.command_line.clone().unwrap_or_else(|| "Not reported".into())),
                    ("Subscription", event.original.stream_id.clone()),
                    ("Collector receipt sequence", event.original.receipt_sequence.to_string()),
                    ("Source QPC ticks", event.original.header.timestamp_qpc.to_string()),
                    ("QPC frequency (Hz)", event.original.clock.frequency_hz.to_string()),
                    ("Time qualification", format!("Collector QPC estimate; sample-bracket and rounding uncertainty {} ms, excluding wall-clock changes or drift. Not a kernel UTC timestamp or verified process start time", event.time_uncertainty_ms)),
                    ("Attribution", "Reported PID, parent, SID, key and image bytes do not establish current process identity, executable path/hash, ancestry or a verified process lifetime".into()),
                    ("Original EVENT_RECORD", "Retained header, buffer context, extended data, payload and QPC clock anchor are included in the original observation JSON".into()),
                ]);
            }
            if let protocol::telemetry::Telemetry::MacosNetworkEvent { event } = telemetry {
                facts.extend([
                    ("macOS NetworkExtension observation", "New flow; selected metadata only".into()),
                    ("Reported transport", crate::fleet::macos_network_protocol(&event.protocol).into()),
                    ("Initial flow direction", crate::fleet::macos_network_direction(&event.direction).into()),
                    ("Raw socket family / type / protocol", format!("{} / {} / {}", event.original.socket_family, event.original.socket_type, event.original.socket_protocol)),
                    ("Reported local endpoint", macos_network_endpoint(event.local.as_ref())),
                    ("Reported remote endpoint", macos_network_endpoint(event.remote.as_ref())),
                    ("Source application audit token (hex)", event.original.source_app_audit_token_hex.clone().unwrap_or_else(|| "Not reported".into())),
                    ("Creator process audit token (hex)", event.original.source_process_audit_token_hex.clone().unwrap_or_else(|| "Not reported".into())),
                    ("Reported flow UUID", event.original.flow_id.clone()),
                    ("Provider stream", event.original.stream_id.clone()),
                    ("Collector admission ordinal", event.original.receipt_sequence.to_string()),
                    ("Time and identity qualification", "Collector receipt time and serialized admission order, not kernel event time/order. Local/remote are reported roles; tokens remain separate. No delivery, firewall verdict, process ownership or complete connection lifetime is established".into()),
                    ("Original network projection", "Exact selected metadata is retained in original JSON; packet bytes, URLs and hostnames are excluded. Upstream OS loss accounting is unavailable".into()),
                ]);
            }
            if let protocol::telemetry::Telemetry::WindowsNetworkEvent { event } = telemetry {
                facts.extend([
                    ("Windows ETW operation", crate::fleet::windows_network_operation(&event.operation).into()),
                    ("Transport / family", format!("{} / {}", crate::fleet::windows_network_protocol(&event.protocol), crate::fleet::windows_network_family(&event.family))),
                    ("Reported PID", event.reported_pid.to_string()),
                    ("Reported source", event.source.to_string()),
                    ("Reported destination", event.destination.to_string()),
                    ("Reported operation size", event.reported_size.to_string()),
                    ("Subscription", event.original.stream_id.clone()),
                    ("Collector receipt sequence", event.original.receipt_sequence.to_string()),
                    ("Source QPC ticks", event.original.header.timestamp_qpc.to_string()),
                    ("QPC frequency (Hz)", event.original.clock.frequency_hz.to_string()),
                    ("Time qualification", format!("Collector QPC estimate; sample-bracket and rounding uncertainty {} ms, excluding wall-clock changes or drift. Not a kernel UTC timestamp", event.time_uncertainty_ms)),
                    ("Attribution", "Reported PID, addresses and opaque original connection token do not establish an executable, process incarnation, connection identity or complete lifetime. A send/receive report or its size does not prove packet delivery or transferred-byte accounting; no firewall decision is inferred".into()),
                    ("Original EVENT_RECORD", "Retained header, buffer context, extended data, payload and QPC clock anchor are included in the original observation JSON".into()),
                ]);
            }
            if let protocol::telemetry::Telemetry::Connection { connection, .. } = telemetry {
                facts.extend([
                    ("Protocol", connection.protocol.to_uppercase()),
                    ("Socket state", connection.state.clone()),
                    ("Local address", connection.local.to_string()),
                    (
                        "Remote address",
                        connection
                            .remote
                            .map(|a| a.to_string())
                            .unwrap_or_else(|| "Not observed".into()),
                    ),
                    (
                        "Owner PID",
                        connection
                            .owner_pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "Unknown".into()),
                    ),
                ]);
            }
            if let Some(process) = telemetry.process() {
                facts.extend([
                    ("Process", process.name.clone()),
                    ("PID", process.pid.to_string()),
                    (
                        "Parent PID",
                        process
                            .parent_pid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "Unknown".into()),
                    ),
                    (
                        "OS user",
                        process.user_id.clone().unwrap_or_else(|| "Unknown".into()),
                    ),
                ]);
            }
        }
        for (label, value) in [
            ("File path", &event.path),
            ("Detection", &event.detection),
            ("SHA-256", &event.sha256),
        ] {
            if !value.is_empty() {
                facts.push((label, value.clone()));
            }
        }
        for (label, value) in facts {
            let class = if ["File path", "SHA-256"].contains(&label) {
                "fact-wide"
            } else {
                ""
            };
            write!(
                html,
                "<div class='{class}'><dt>{label}</dt><dd>{}</dd></div>",
                escape(&value)
            )
            .unwrap();
        }
        write!(html,"</dl><p>{}</p><details><summary>Original observation JSON</summary><pre class=raw-message>{}</pre></details></section>",escape(&event.detail),escape(&serde_json::to_string_pretty(event).map_err(|e|WebError(e.to_string()))?)).unwrap();
    }
    if records.is_empty() {
        html.push_str("<section class='panel controls-panel fleet-panel'><p>No retained observations in this range.</p></section>");
    }
    if records.len() == 32 {
        write!(
            html,
            "<a class=button href='/endpoints/{}?before={}'>Older observations</a>",
            escape(&id),
            records.last().unwrap().evidence_id
        )
        .unwrap();
    }
    Ok(Html(
        crate::render::page(
            &checked(engine.snapshot())?,
            "endpoints",
            &crate::web::Filters::default(),
            None,
            &app.csrf,
        )
        .replace("<!-- ENDPOINT_CONTENT -->", &html),
    ))
}

pub(crate) fn failure(error: impl std::fmt::Display) -> Response {
    let text = error.to_string();
    let status = if text.contains("credential") || text.starts_with("Enrollment") {
        StatusCode::UNAUTHORIZED
    } else if text.contains("capacity") || text.contains("budget") || text.contains("full") {
        StatusCode::SERVICE_UNAVAILABLE
    } else {
        StatusCode::BAD_REQUEST
    };
    (
        status,
        [("retry-after", "30")],
        Json(serde_json::json!({"error":text,"acknowledged":0})),
    )
        .into_response()
}
async fn enroll(State(app): State<App>, Json(request): Json<Enrollment>) -> Response {
    match app
        .engine
        .lock()
        .map_err(|_| "Engine unavailable")
        .and_then(|e| {
            e.enroll_endpoint(&request, now_ms())
                .map_err(|_| "Enrollment rejected")
        }) {
        Ok(()) => {
            Json(serde_json::json!({"enrolled":true,"protocol":protocol::PROTOCOL})).into_response()
        }
        Err(e) => failure(e),
    }
}
pub(crate) fn endpoint_op<T: Serialize>(
    app: &App,
    id: &str,
    headers: &HeaderMap,
    f: impl FnOnce(&crate::engine::Engine) -> LabResult<T>,
) -> Response {
    let result = (|| -> LabResult<T> {
        let engine = app.engine.lock().map_err(|_| "Engine unavailable")?;
        engine.authenticate_endpoint(id, bearer(headers))?;
        f(&engine)
    })();
    match result {
        Ok(v) => Json(v).into_response(),
        Err(e) => failure(e),
    }
}
async fn heartbeat(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(health): Json<Heartbeat>,
) -> Response {
    endpoint_op(&app, &id, &h, |e| {
        e.endpoint_heartbeat(&id, &health, now_ms())?;
        Ok(serde_json::json!({"committed":true}))
    })
}
async fn events(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(events): Json<Vec<EndpointEvent>>,
) -> Response {
    endpoint_op(&app, &id, &h, |e| {
        let accepted = e.endpoint_events(&id, &events, now_ms())?;
        Ok(
            serde_json::json!({"accepted":accepted,"acknowledged":events.len(),"durability":"committed"}),
        )
    })
}
async fn poll(State(app): State<App>, Path(id): Path<String>, h: HeaderMap) -> Response {
    endpoint_op(&app, &id, &h, |e| e.poll_endpoint_commands(&id, now_ms()))
}
async fn start(
    State(app): State<App>,
    Path((id, command)): Path<(String, String)>,
    h: HeaderMap,
) -> Response {
    endpoint_op(&app, &id, &h, |e| {
        e.start_endpoint_command(&id, &command, now_ms())
    })
}
async fn receipt(
    State(app): State<App>,
    Path(id): Path<String>,
    h: HeaderMap,
    Json(receipt): Json<Receipt>,
) -> Response {
    endpoint_op(&app, &id, &h, |e| {
        e.finish_endpoint_command(&id, &receipt, now_ms())?;
        Ok(serde_json::json!({"committed":true}))
    })
}
async fn fleet_api(State(app): State<App>) -> Result<Json<Fleet>, WebError> {
    let e = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    Ok(Json(checked(e.fleet())?))
}

fn form(csrf: &str, op: &str, id: &str) -> String {
    format!("<form class=control-form method=post action=/endpoints/action><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{}'><input type=hidden name=id value='{}'>",escape(csrf),escape(op),escape(id))
}
async fn portal(State(app): State<App>) -> Result<Html<String>, WebError> {
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    let fleet = checked(engine.fleet())?;
    let snapshot = checked(engine.snapshot())?;
    let mut content=String::from("<section class=page-heading><div><div class=eyebrow>ENDPOINT PROTECTION & RESPONSE</div><h1>Your managed endpoints</h1><p>Enroll a device, inspect its protection, and run reviewed actions with durable investigation receipts.</p></div></section>");
    content.push_str("<p><a class=button href=/endpoint-updates>Manage signed updates</a></p>");
    content.push_str("<section class='panel controls-panel fleet-panel'><h2>Install an endpoint</h2><p>Download a platform installer bundle. Each enrollment expires after 15 minutes and can register one device. Existing antivirus remains active.</p>");
    write!(content,"<form class=control-form method=post action=/endpoints/installer><input type=hidden name=csrf value='{}'><label>Server HTTPS origin<input name=server required type=url placeholder='https://security.example.com/'></label><label>Platform<select name=target><option value=linux-x86_64>Linux x86_64</option><option value=linux-aarch64>Linux ARM64</option><option value=windows-x86_64>Windows x86_64</option><option value=macos-aarch64>macOS Apple silicon</option><option value=macos-x86_64>macOS Intel</option></select></label><label><input type=checkbox name=antivirus checked> Install ClamAV and current signatures (downloads a verified upstream package)</label><button class='button primary'>Download installer</button></form><p>Available builds: {}. Builds must be provisioned by the release pipeline before download.</p></section>",escape(&app.csrf),escape(&available_artifacts().join(", "))).unwrap();
    for endpoint in &fleet.endpoints {
        let stale = now_ms().saturating_sub(endpoint.last_seen_ms) > 120_000;
        let protection_stale = endpoint.health.protection.as_ref().is_some_and(|p| {
            p.state == "active"
                && (now_ms().saturating_sub(p.checked_ms) > 90_000
                    || p.checked_ms > now_ms().saturating_add(60_000))
        });
        write!(content,"<section class='panel controls-panel fleet-panel'><h2>{}</h2><p>{:?} · {} · {} · {}</p><p>Scanner: {} · Real-time protection: {} · Agent {}</p><p>{}</p><code>{}</code>",escape(&endpoint.hostname),endpoint.platform,escape(&endpoint.arch),escape(&endpoint.state),if stale{"offline / stale"}else{"connected"},escape(&endpoint.health.scanner),if stale || protection_stale {"unknown / stale"} else if endpoint.health.realtime{"reported active"}else{"not active"},escape(&endpoint.health.version),escape(&endpoint.health.error),escape(&endpoint.id)).unwrap();
        if let Some(c) = &endpoint.health.collector {
            if let Some(authentication) = &c.authentication {
                write!(content,"<p>Authentication journal: {} · {} reports · {} unsupported records · {} loss notifications</p><p>Collection began {} UTC; earlier journal history is outside its scope.</p><p>{}</p>",if stale || !authentication.healthy(now_ms()) {"coverage incomplete / catching up"} else {"active"},authentication.authentication_events,authentication.rejected_records,authentication.loss_signals,crate::render::time(authentication.started_ms),escape(&authentication.error)).unwrap();
            }
            if let Some(authentication) = &c.windows_authentication {
                write!(content,"<p>Windows Security logons: {} · {} reports · {} unsupported records · {} loss notifications</p><p>Collection began {} UTC; earlier records and authentication providers outside Windows Security events 4624/4625 are outside its scope.</p><p>{}</p>",if stale || !authentication.healthy(now_ms()) {"coverage incomplete / catching up"} else {"active"},authentication.authentication_events,authentication.rejected_records,authentication.loss_signals,crate::render::time(authentication.started_ms),escape(&authentication.error)).unwrap();
            }
            write!(content,"<p>Telemetry: {} · {} processes · {} connections · {} pending changes · {}</p><p>{}</p>",escape(&c.mode),c.process_count,c.connection_count,c.pending_changes,if c.incomplete{"collection gaps / delivery pending"}else{"last snapshot collected"},escape(&c.error)).unwrap();
            if let Some(events) = &c.network_events {
                write!(content,"<p>Network tracker events: {} · namespace {} · IP families {:?} · {} received · {} dropped · {} loss notifications · {} subscriptions</p><p>Current subscription began {} UTC. TCP/UDP tracker observations only; traffic bypassing tracking, other namespaces and subscription gaps are outside coverage.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.namespace,events.families,events.received_events,events.dropped_events,events.loss_signals,events.subscriptions,crate::render::time(events.started_ms),escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.process_events {
                write!(content,"<p>Kernel process events: {} · {} received · {} dropped · {} loss notifications · {} subscriptions</p><p>Current subscription began {} UTC. Activity outside subscription windows is not observed.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.received_events,events.dropped_events,events.loss_signals,events.subscriptions,crate::render::time(events.started_ms),escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.macos_authentication {
                write!(content,"<p>macOS Endpoint Security authentication reports: {} · {} received · {} admitted · {} rejected · {} loss notifications</p><p>One authentication notification source with Open Directory, Touch ID, token and Auto Unlock report variants. Reported success is not login/session completion; factors and fallbacks do not feed failed-login bursts. Subscription gaps have no source replay. Source policy: <code>{}</code>. Observed mute scope: <code>{}</code>; {} path entries, {} process entries, {} subscribed-event intersections.</p><p>Global and per-type gaps overlap and are not summed. Other authentication sources and macOS process notifications cannot replace this coverage.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.received_records,events.admitted_records,events.rejected_records,events.loss_signals,escape(&events.source_policy_sha256),escape(&events.mute_snapshot_sha256),events.muted_path_count,events.muted_process_count,events.subscribed_mute_count,escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.macos_process_events {
                write!(content,"<p>macOS Endpoint Security process events: {} · {} received · {} admitted · {} rejected · {} loss notifications</p><p>Live exec/fork/exit notifications only; subscription gaps have no source replay. Exact retained projections can replay after durable admission. Source policy: <code>{}</code>. Observed mute scope: <code>{}</code>; {} path entries, {} process entries, {} subscribed-event intersections.</p><p>Global and per-type gap counters describe overlapping evidence and are not summed. Audit tokens and paths are historical reports, not current process or ancestry assertions. Arguments and environment are excluded.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.received_records,events.admitted_records,events.rejected_records,events.loss_signals,escape(&events.source_policy_sha256),escape(&events.mute_snapshot_sha256),events.muted_path_count,events.muted_process_count,events.subscribed_mute_count,escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.windows_process_events {
                write!(content,"<p>Windows ETW process events: {} · {} received · {} admitted · {} rejected · {} loss notifications</p><p>Collection began {} UTC. Live source only; collector restarts and gaps have no ETW source replay. Reported identifiers do not establish verified process lifetimes.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.received_records,events.admitted_records,events.rejected_records,events.loss_signals,crate::render::time(events.started_ms),escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.macos_network_events {
                write!(content,"<p>macOS NetworkExtension metadata: {} · {} received · {} admitted · {} excluded · {} rejected · {} loss notifications</p><p>New-flow metadata only. Local pipeline status does not establish absence of upstream OS loss: kernel loss accounting is unavailable. No packet delivery, firewall decision, process ownership or full lifetime is inferred. Provider may outlive the agent; disconnect does not uninstall it. Source policy: <code>{}</code>.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"local pipeline active"},events.received_records,events.admitted_records,events.excluded_records,events.rejected_records,events.loss_signals,escape(&events.source_policy_sha256),escape(&events.error)).unwrap();
            }
            if let Some(events) = &c.windows_network_events {
                write!(content,"<p>Windows ETW network events: {} · {} received · {} admitted · {} rejected · {} loss notifications</p><p>Collection began {} UTC. Live TCP/UDP IPv4/IPv6 source only; collector restarts and gaps have no ETW source replay. Reported operations do not establish packet delivery, firewall decisions, executable identity or complete connection lifetimes.</p><p>{}</p>",if stale || !events.healthy(now_ms()) {"coverage incomplete"} else {"active"},events.received_records,events.admitted_records,events.rejected_records,events.loss_signals,crate::render::time(events.started_ms),escape(&events.error)).unwrap();
            }
        }
        if let Some(p) = &endpoint.health.protection {
            write!(content,"<p>Native protection: {} · {} · last checked {}</p><p>Protected folders: {}</p><p>Scanner account excluded: {} · {} queued detections · {} dropped records</p><p>{}</p>",if stale || protection_stale {"unknown / stale".into()} else {escape(&p.state)},escape(&p.backend),if p.checked_ms==0{"never".into()}else{crate::render::age(p.checked_ms)},escape(&p.roots.join(", ")),p.excluded_uid.map(|u|u.to_string()).unwrap_or_else(||"none".into()),p.pending_events,p.dropped_events,escape(&p.error)).unwrap();
        }
        write!(
            content,
            "<p><a class=button href='/endpoints/{}'>Open device evidence</a></p>",
            escape(&endpoint.id)
        )
        .unwrap();
        content.push_str(&form(
            &app.csrf,
            if endpoint.state == "active" {
                "revoke"
            } else {
                "restore"
            },
            &endpoint.id,
        ));
        write!(
            content,
            "<button class=button>{}</button></form>",
            if endpoint.state == "active" {
                "Revoke endpoint access"
            } else {
                "Restore endpoint access"
            }
        )
        .unwrap();
        let mode = fleet
            .playbooks
            .iter()
            .find(|p| p.endpoint_id == endpoint.id)
            .map_or("disabled", |p| p.mode.as_str());
        content.push_str(&form(&app.csrf, "playbook", &endpoint.id));
        write!(content,"<h3>Malware response playbook</h3><p>Current mode: {}. A detection can propose or automatically approve quarantine of the exact reported file hash.</p><label>Policy<select name=action><option value=disabled>Disabled</option><option value=review>Propose quarantine for review</option><option value=automatic>Automatically approve hash-bound quarantine</option></select></label><button class=button>Save endpoint policy</button></form>",escape(mode)).unwrap();
        content.push_str(&form(&app.csrf, "queue", &endpoint.id));
        content.push_str("<label>Investigation ID<input name=case_id type=number min=1 required></label><label>Action<select name=action>");
        for capability in &endpoint.health.capabilities {
            write!(
                content,
                "<option value='{}'>{}</option>",
                escape(capability),
                escape(capability)
            )
            .unwrap();
        }
        content.push_str("</select></label><label>Path or quarantine reference<input name=path maxlength=1024></label><label>Expected file SHA-256 (quarantine)<input name=sha256 maxlength=64></label><label>Script interpreter<select name=interpreter><option value=sh>sh</option><option value=powershell>PowerShell</option></select></label><label>Automation script (only with local script permission)<textarea name=script maxlength=8192 rows=4></textarea></label><button class='button primary'>Propose action for review</button></form></section>");
    }
    if fleet.endpoints.is_empty() {
        content.push_str("<section class='panel controls-panel fleet-panel'><h2>No endpoints enrolled</h2><p>Download and install the agent on a device to begin.</p></section>");
    }
    content.push_str("<section class='panel controls-panel fleet-panel'><h2>Response work</h2>");
    for item in fleet.commands {
        write!(content,"<article><h3>{} · {}</h3><p>Endpoint {} · <a href='/case/{}'>Investigation {}</a></p><pre class=raw-message>{}</pre><p>Action SHA-256 {}</p>",escape(item.command.action.capability()),escape(&item.state),escape(&item.command.endpoint_id),item.command.case_id,item.command.case_id,escape(&serde_json::to_string_pretty(&item.command.action).unwrap_or_default()),escape(&item.command.action_hash)).unwrap();
        if item.state == "pending" {
            for (op, label) in [("approve", "Approve exact action"), ("reject", "Reject")] {
                content.push_str(&form(&app.csrf, op, &item.command.id));
                write!(content, "<button class=button>{label}</button></form>").unwrap();
            }
        }
        if let Some(receipt) = item.receipt {
            write!(
                content,
                "<pre class=raw-message>{}</pre>",
                escape(&receipt.output)
            )
            .unwrap();
        }
        content.push_str("</article>");
    }
    content.push_str("</section>");
    let html = crate::render::page(
        &snapshot,
        "endpoints",
        &crate::web::Filters::default(),
        None,
        &app.csrf,
    )
    .replace("<!-- ENDPOINT_CONTENT -->", &content);
    Ok(Html(html))
}
#[derive(Deserialize)]
struct FormAction {
    csrf: String,
    op: String,
    id: String,
    #[serde(default)]
    case_id: i64,
    #[serde(default)]
    action: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    interpreter: String,
    #[serde(default)]
    script: String,
}
async fn action(
    State(app): State<App>,
    Form(form): Form<FormAction>,
) -> Result<Redirect, WebError> {
    csrf(&app, &form.csrf)?;
    let engine = app
        .engine
        .lock()
        .map_err(|_| WebError("Engine unavailable".into()))?;
    match form.op.as_str() {
        "playbook" => checked(engine.configure_malware_playbook(&form.id, &form.action, now_ms()))?,
        "revoke" | "restore" => checked(engine.endpoint_state(
            &form.id,
            if form.op == "revoke" {
                "revoked"
            } else {
                "active"
            },
            now_ms(),
        ))?,
        "approve" | "reject" => {
            checked(engine.review_endpoint_action(&form.id, form.op == "approve", now_ms()))?
        }
        "queue" => {
            let action = match form.action.as_str() {
                "inventory" => Action::Inventory,
                "scan" => Action::Scan { path: form.path },
                "update_signatures" => Action::UpdateSignatures,
                "quarantine" => Action::Quarantine {
                    path: form.path,
                    sha256: form.sha256,
                },
                "restore" => Action::Restore {
                    quarantine_id: form.path,
                },
                "script" => Action::Script {
                    interpreter: form.interpreter,
                    sha256: protocol::hash(form.script.as_bytes()),
                    script: form.script,
                },
                _ => return Err(WebError("Unknown endpoint action".into())),
            };
            checked(engine.queue_endpoint_action(&form.id, action, form.case_id, now_ms()))?;
        }
        _ => return Err(WebError("Unknown endpoint operation".into())),
    }
    Ok(Redirect::to("/endpoints"))
}

const TARGETS: &[&str] = &[
    "linux-x86_64",
    "linux-aarch64",
    "windows-x86_64",
    "macos-aarch64",
    "macos-x86_64",
];
fn artifact_root() -> std::path::PathBuf {
    std::env::var_os("ATHERNEX_ENDPOINT_ARTIFACTS")
        .map(Into::into)
        .unwrap_or_else(|| ".athernex/endpoint-artifacts".into())
}
fn available_artifacts() -> Vec<String> {
    TARGETS
        .iter()
        .filter(|t| artifact_root().join(format!("{t}.json")).is_file())
        .map(|s| s.to_string())
        .collect()
}
pub use protocol::installer::{Artifact, NativeArtifact};
pub fn installer_bundle(
    root: &FsPath,
    target: &str,
    bootstrap: &protocol::Bootstrap,
) -> LabResult<Vec<u8>> {
    if !TARGETS.contains(&target) {
        return Err("Unsupported endpoint target".into());
    }
    let artifact: Artifact =
        serde_json::from_slice(&std::fs::read(root.join(format!("{target}.json"))).map_err(
            |_| "This platform build is not provisioned. Run the endpoint build pipeline first.",
        )?)?;
    let binary_path = root.join(format!(
        "athernex-endpoint-{target}{}",
        if target.starts_with("windows") {
            ".exe"
        } else {
            ""
        }
    ));
    if std::fs::metadata(&binary_path)?.len() > 64 * 1024 * 1024 {
        return Err("Endpoint artifact exceeds size budget".into());
    }
    use std::io::Read;
    let mut binary = Vec::new();
    std::fs::File::open(binary_path)?
        .take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut binary)?;
    if binary.len() > 64 * 1024 * 1024 {
        return Err("Endpoint artifact exceeds size budget".into());
    }

    if artifact.target != target || protocol::hash(&binary) != artifact.sha256 {
        return Err("Endpoint build checksum mismatch".into());
    }
    let native = if let Some(component) = artifact.native()? {
        use std::io::Read;
        let mut bytes = Vec::new();
        std::fs::File::open(root.join(format!("athernex-endpoint-native-{target}")))?
            .take(64 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        let machine: u32 = if target == "macos-x86_64" {
            0x1000007
        } else {
            0x100000c
        };
        if bytes.len() < 64
            || bytes.len() + binary.len() > 64 * 1024 * 1024
            || bytes[..4] != [0xcf, 0xfa, 0xed, 0xfe]
            || bytes[4..8] != machine.to_le_bytes()
            || protocol::hash(&bytes) != component.sha256
        {
            return Err("Native adapter build integrity or architecture mismatch".into());
        }
        Some(bytes)
    } else {
        None
    };
    let network = if let Some(component) = artifact.network()? {
        let total = (binary.len() as u64)
            .checked_add(native.as_ref().map_or(0, |v| v.len()) as u64)
            .and_then(|n| n.checked_add(component.bytes));
        if total.is_none_or(|n| n > 64 * 1024 * 1024) {
            return Err("Combined endpoint components exceed size budget".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(root.join(format!("athernex-macos-network-{target}.zip")))?
            .take(component.bytes + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 != component.bytes || protocol::hash(&bytes) != component.sha256 {
            return Err("macOS network archive build checksum or size mismatch".into());
        }
        Some(bytes)
    } else {
        None
    };
    let filter = if let Some(component) = artifact.filter()? {
        if (binary.len() as u64)
            .checked_add(component.bytes)
            .is_none_or(|n| n > 64 * 1024 * 1024)
        {
            return Err("Combined endpoint and driver package exceed budget".into());
        }
        let mut bytes = Vec::new();
        std::fs::File::open(root.join(format!("athernex-windows-filter-{target}.axpkg")))?
            .take(component.bytes + 1)
            .read_to_end(&mut bytes)?;
        component.unpack(&bytes)?;
        Some(bytes)
    } else {
        None
    };
    let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .unix_permissions(0o700);
    let mut entry = |name: &str, bytes: &[u8]| -> LabResult<()> {
        writer.start_file(name, options)?;
        writer.write_all(bytes)?;
        Ok(())
    };
    entry(
        if target.starts_with("windows") {
            "athernex-endpoint.exe"
        } else {
            "athernex-endpoint"
        },
        &binary,
    )?;
    entry("bootstrap.json", &serde_json::to_vec_pretty(bootstrap)?)?;
    entry("release.json", &serde_json::to_vec_pretty(&artifact)?)?;
    if let Some(bytes) = &native {
        entry("athernex-endpoint-native", bytes)?;
        entry("native-adapter.required", b"1\n")?;
        entry("native-adapter.txt", b"This bundle contains a signature-verified macOS Endpoint Security adapter. Setup verifies its hash, signature and entitlement, prepares a dedicated scanner account and runtime, and configures the controller to start native services. Signatures must be provisioned or already configured. Existing local protection policy is preserved, including a disabled policy. Endpoint Security authorization, Full Disk Access and native runtime validation are required on the Mac. Protection remains unverified until live blocking is proven.\n")?;
    }
    if let Some(bytes) = &network {
        entry("macos-network.zip", bytes)?;
        entry("macos-network.required", b"1\n")?;
        entry("macos-network.txt", b"Keep this deployment bundle private. Setup verifies the approved macOS network extension archive, signed identities and installed snapshot before changing the owned application. Installation does not activate the extension or enable collection. Activation requires separate user or MDM approval; native acceptance remains unverified. Stopping the agent detaches its consumer and does not stop or uninstall the OS-managed provider.\n")?;
    }
    if let Some(bytes) = &filter {
        entry("windows-filter.axpkg", bytes)?;
        entry("windows-filter.required", b"1\n")?;
        if artifact.filter()?.is_some_and(|d| d.deployment.is_some()) {
            entry("windows-filter.txt",b"Private approved driver deployment. Setup requires an owned LocalSystem coordinator to install the exact approved primitive package and observe its disarmed ABI before installer completion. The journal preserves uncertain native effects and may require explicit recovery or an authorized reboot. This does not attest exact loaded-image bytes, assign altitude, arm protection, or satisfy the native prevention gates.\n")?;
        } else {
            entry("windows-filter.txt",b"Private approved driver package. The Windows installer verifies and durably prepares exact SYS/INF/CAT snapshots using cache-only WHQL catalog policy. Prepared is not Driver Store installation, loading, altitude assignment, live ABI proof, or active protection. Existing production activation refusal and native acceptance requirements remain.\n")?;
        }
    }
    entry("README.txt",b"Athernex endpoint installer\nEnrollment expires in 15 minutes and registers one device. Keep this bundle private.\nWindows: run install.ps1 as Administrator. Linux/macOS: sudo sh install.sh.\nLinux command cleanup requires permitted pidfd_open and close_range syscalls (mainline Linux 5.9 or later); installation checks these before stopping an existing service.\nIf selected in the portal, setup downloads and verifies ClamAV, installs it, and initializes signatures. Linux also configures a separate on-access prevention service for the local scan roots. Check protection health in the portal. Windows/macOS currently provide scheduled and on-demand scans. Existing AV is preserved.\nRead release.json for signing status; do not treat a development build as a signed production release.\n")?;
    if target.starts_with("windows") {
        entry(
            "install.ps1",
            include_bytes!("../../../infrastructure/endpoint/install.ps1"),
        )?;
    } else if target.starts_with("macos") {
        entry(
            "install.sh",
            include_bytes!("../../../infrastructure/endpoint/install-macos.sh"),
        )?;
    } else {
        entry(
            "install.sh",
            include_bytes!("../../../infrastructure/endpoint/install-linux.sh"),
        )?;
    }
    Ok(writer.finish()?.into_inner())
}
#[derive(Deserialize)]
struct InstallerForm {
    csrf: String,
    target: String,
    server: String,
    #[serde(default)]
    antivirus: String,
}
async fn installer(
    State(app): State<App>,
    Form(form): Form<InstallerForm>,
) -> Result<Response, WebError> {
    csrf(&app, &form.csrf)?;
    protocol::server_url(&form.server).map_err(WebError)?;
    let platform = if form.target.starts_with("windows-") {
        Platform::Windows
    } else if form.target.starts_with("macos-") {
        Platform::Macos
    } else {
        Platform::Linux
    };
    let root = artifact_root();
    if !TARGETS.contains(&form.target.as_str())
        || !root.join(format!("{}.json", form.target)).is_file()
    {
        return Err(WebError(
            "This platform build is not provisioned. Run the endpoint build pipeline first.".into(),
        ));
    }
    let token = {
        let engine = app
            .engine
            .lock()
            .map_err(|_| WebError("Engine unavailable".into()))?;
        checked(engine.create_enrollment(platform, now_ms()))?
    };
    let bootstrap = protocol::Bootstrap {
        protocol: protocol::PROTOCOL,
        server: form.server,
        enrollment_token: token,
        platform,
        antivirus: if form.antivirus == "on" {
            let packages: Vec<protocol::AntivirusPackage> = serde_json::from_str(include_str!(
                "../../../infrastructure/endpoint/antivirus-packages.json"
            ))
            .map_err(|e| WebError(e.to_string()))?;
            let arch = if form.target.ends_with("aarch64") {
                "aarch64"
            } else {
                "x86_64"
            };
            packages
                .into_iter()
                .filter(|p| p.platform == platform && (p.arch == arch || p.arch == "universal"))
                .collect()
        } else {
            vec![]
        },
    };
    let target = form.target.clone();
    let bytes = tokio::task::spawn_blocking(move || installer_bundle(&root, &target, &bootstrap))
        .await
        .map_err(|e| WebError(e.to_string()))?;
    let bytes = checked(bytes)?;
    Ok((
        [
            ("content-type", "application/zip".to_owned()),
            (
                "content-disposition",
                format!("attachment; filename=athernex-{}.zip", form.target),
            ),
        ],
        bytes,
    )
        .into_response())
}
