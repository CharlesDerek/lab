//! Browser forms use the same command authorization as the JSON control API.
use crate::{
    control_web::ControlCommand,
    engine::{Engine, LabResult},
    identity::{Actor, Role},
    render::escape,
    web::{App, WebError},
};
use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse, Redirect, Response},
    Extension, Form,
};
use orchestrator::governor::Resources;
use std::{collections::HashMap, fmt::Write};
fn field<'a>(form: &'a HashMap<String, String>, name: &str) -> LabResult<&'a str> {
    form.get(name)
        .map(|v| v.as_str())
        .ok_or_else(|| format!("Missing {name}").into())
}
fn number(form: &HashMap<String, String>, name: &str) -> LabResult<u64> {
    Ok(field(form, name)?.parse()?)
}
fn resources(form: &HashMap<String, String>, prefix: &str) -> LabResult<Resources> {
    let value = |name: &str| number(form, &format!("{prefix}{name}"));
    Ok(Resources {
        cpu_millis: value("cpu_millis")?,
        memory_mib: value("memory_mib")?,
        io_mib: value("io_mib")?,
        gpu_millis: value("gpu_millis")?,
        tokens: value("tokens")?,
        power_watts: value("power_watts")?,
    })
}
fn command(form: &HashMap<String, String>) -> LabResult<ControlCommand> {
    Ok(match field(form, "operation")? {
        "configure_pool" => ControlCommand::ConfigurePool {
            pool: field(form, "pool")?.into(),
            capacity: resources(form, "")?,
            essential_reserve: resources(form, "essential_")?,
        },
        "bind_endpoint" => ControlCommand::BindEndpoint {
            endpoint: field(form, "endpoint")?.into(),
            pool: field(form, "pool")?.into(),
        },
        "background_pool" => ControlCommand::BackgroundPool {
            pool: field(form, "pool")?.into(),
        },
        "issue_operator" => ControlCommand::IssueOperator {
            id: field(form, "id")?.into(),
            role: serde_json::from_value(serde_json::json!(field(form, "role")?))?,
            expires_ms: crate::model::now_ms().saturating_add(
                number(form, "days")?
                    .checked_mul(86_400_000)
                    .ok_or("Invalid credential lifetime")?,
            ),
        },
        "revoke_operator" => ControlCommand::RevokeOperator {
            id: field(form, "id")?.into(),
        },
        "compact_signals" => ControlCommand::CompactSignals,
        "replay_signals" => ControlCommand::ReplaySignals,
        "configure_signals" => ControlCommand::ConfigureSignals {
            policy: crate::signals::SignalPolicy {
                enabled_rules: crate::signals::SIGNAL_RULES
                    .iter()
                    .filter(|r| form.contains_key(r.id))
                    .map(|r| r.id.into())
                    .collect(),
                keep_source_ip: form.contains_key("keep_source_ip"),
                keep_user_agent: form.contains_key("keep_user_agent"),
                history_ms: number(form, "history_minutes")?
                    .checked_mul(60000)
                    .ok_or("Invalid history")?,
                accepted_lateness_ms: number(form, "lateness_minutes")?
                    .checked_mul(60000)
                    .ok_or("Invalid lateness")?,
            },
        },
        "propose_incident" => ControlCommand::ProposeIncident {
            request: crate::ecosystem::IncidentRequest {
                id: field(form, "id")?.into(),
                endpoint: field(form, "endpoint")?.into(),
                evidence_id: number(form, "evidence_id")?,
                replacement_pool: field(form, "pool")?.into(),
                resources: resources(form, "")?,
                expires_ms: number(form, "expires_ms")?,
            },
        },
        _ => return Err("Unknown control operation".into()),
    })
}
pub(crate) async fn submit(
    State(app): State<App>,
    Extension(actor): Extension<Actor>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    if !form
        .get("csrf")
        .is_some_and(|v| crate::gateway::same_secret(v, &app.csrf))
    {
        return StatusCode::FORBIDDEN.into_response();
    }
    let command = match command(&form) {
        Ok(c) => c,
        Err(error) => return WebError(error.to_string()).into_response(),
    };
    if !command.permitted(&actor) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Ok(e) = app.engine.lock() else {
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    };
    match command.execute(&e,&actor){
        Ok(value) if value.get("token").is_some()=>Html(format!("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><link rel=stylesheet href=/assets/app.css><title>Operator credential</title><main class=panel><h1>Operator credential issued</h1><p>Copy this credential to its owner's private credential store. It is shown only in this response. Rotation invalidates previous credentials and sessions.</p><code>{}</code><p><a href=/control>Return to security and capacity</a></p></main>",escape(value["token"].as_str().unwrap_or_default()))).into_response(),
        Ok(_)=>Redirect::to("/control").into_response(),
        Err(error)=>WebError(error.to_string()).into_response()
    }
}
fn begin(html: &mut String, csrf: &str, operation: &str) {
    write!(html,"<form class=control-form method=post action=/control/setup><input type=hidden name=csrf value='{}'><input type=hidden name=operation value='{operation}'>",escape(csrf)).unwrap();
}
fn resource_fields(html: &mut String, prefix: &str, defaults: Resources) {
    for (name, label, value) in [
        ("cpu_millis", "CPU millicores", defaults.cpu_millis),
        ("memory_mib", "Memory MiB", defaults.memory_mib),
        ("io_mib", "I/O MiB per job", defaults.io_mib),
        ("gpu_millis", "GPU milliunits", defaults.gpu_millis),
        ("tokens", "Tokens", defaults.tokens),
        ("power_watts", "Power watts", defaults.power_watts),
    ] {
        write!(html,"<label>{label}<input type=number min=0 max=1000000000 name='{prefix}{name}' value='{value}' required></label>").unwrap();
    }
}
fn pools(html: &mut String, e: &Engine) -> LabResult<()> {
    html.push_str("<label>Resource pool<select name=pool required>");
    for pool in e.resource_pools()? {
        write!(
            html,
            "<option value='{}'>{}</option>",
            escape(&pool.name),
            escape(&pool.name)
        )
        .unwrap();
    }
    html.push_str("</select></label>");
    Ok(())
}
fn endpoints(html: &mut String, e: &Engine) -> LabResult<()> {
    html.push_str("<label>Endpoint<select name=endpoint required>");
    for endpoint in e
        .fleet()?
        .endpoints
        .into_iter()
        .filter(|e| e.state == "active")
    {
        write!(
            html,
            "<option value='{}'>{}</option>",
            escape(&endpoint.id),
            escape(&endpoint.hostname)
        )
        .unwrap();
    }
    html.push_str("</select></label>");
    Ok(())
}
pub(crate) fn render(e: &Engine, actor: &Actor, csrf: &str) -> LabResult<String> {
    let mut html = String::new();
    if actor.role != Role::Viewer {
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Propose containment</h2><p>Select malware evidence from the endpoint's investigation. The reviewed plan will bind the exact file hash, placement hold and replacement reservation.</p>");
        begin(&mut html, csrf, "propose_incident");
        write!(
            html,
            "<input type=hidden name=id value='{}'><input type=hidden name=expires_ms value='{}'>",
            crate::gateway::secret()?,
            crate::model::now_ms() + 900000
        )
        .unwrap();
        endpoints(&mut html, e)?;
        pools(&mut html, e)?;
        html.push_str("<label>Malware evidence ID<input type=number name=evidence_id min=1 required></label><fieldset><legend>Replacement resources</legend>");
        resource_fields(
            &mut html,
            "",
            Resources {
                cpu_millis: 1000,
                memory_mib: 256,
                ..Default::default()
            },
        );
        html.push_str(
            "</fieldset><button class=button>Propose containment plan</button></form></section>",
        );
    }
    if actor.role == Role::Admin {
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Configure capacity</h2><details><summary>Register a resource pool</summary><p>Capacity is an admission contract. Register a new pool when capacity changes. Essential reserves keep detection available while optional work is busy.</p>");
        begin(&mut html, csrf, "configure_pool");
        html.push_str("<label>Pool name<input name=pool required maxlength=64></label><fieldset><legend>Total capacity</legend>");
        resource_fields(
            &mut html,
            "",
            Resources {
                cpu_millis: 4000,
                memory_mib: 4096,
                io_mib: 1024,
                gpu_millis: 1000,
                tokens: 16384,
                power_watts: 500,
            },
        );
        html.push_str("</fieldset><fieldset><legend>Essential reserve</legend>");
        resource_fields(
            &mut html,
            "essential_",
            Resources {
                cpu_millis: 1000,
                memory_mib: 128,
                io_mib: 64,
                ..Default::default()
            },
        );
        html.push_str("</fieldset><button class=button>Register pool</button></form></details><details><summary>Bind endpoint placement</summary>");
        begin(&mut html, csrf, "bind_endpoint");
        endpoints(&mut html, e)?;
        pools(&mut html, e)?;
        html.push_str("<button class=button>Bind endpoint to pool</button></form></details><details><summary>Admit storage and detection work</summary>");
        begin(&mut html, csrf, "background_pool");
        pools(&mut html, e)?;
        html.push_str(
            "<button class=button>Use shared resource pool</button></form></details></section>",
        );
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Detection retention</h2><p>Enabled rules constrain which fields may be discarded. Compaction cannot recover previously discarded fields.</p>");
        begin(&mut html, csrf, "configure_signals");
        let policy = e.signal_policy()?;
        for rule in &crate::signals::SIGNAL_RULES {
            write!(
                html,
                "<label><input type=checkbox name='{}' {}> {} · {}</label>",
                rule.id,
                if policy.enabled_rules.iter().any(|id| id == rule.id) {
                    "checked"
                } else {
                    ""
                },
                rule.id,
                escape(rule.description)
            )
            .unwrap();
        }
        for (name, label, enabled) in [
            ("keep_source_ip", "Retain source IP", policy.keep_source_ip),
            (
                "keep_user_agent",
                "Retain client metadata",
                policy.keep_user_agent,
            ),
        ] {
            write!(
                html,
                "<label><input type=checkbox name='{name}' {}> {label}</label>",
                if enabled { "checked" } else { "" }
            )
            .unwrap();
        }
        write!(html,"<label>Detection history minutes<input type=number min=10 max=43200 name=history_minutes value='{}' required></label><label>Accepted lateness minutes<input type=number min=0 max=43200 name=lateness_minutes value='{}' required></label><button class=button>Save retention policy</button></form>",policy.history_ms/60000,policy.accepted_lateness_ms/60000).unwrap();
        begin(&mut html, csrf, "compact_signals");
        html.push_str("<button class=button>Compact retained signal fields</button></form>");
        begin(&mut html, csrf, "replay_signals");
        html.push_str("<button class=button>Replay versioned detections</button></form></section>");
        html.push_str("<section class='panel controls-panel fleet-panel'><h2>Operator access</h2>");
        for operator in e.operators()? {
            write!(
                html,
                "<p>{} · {:?} · revision {} · {}</p>",
                escape(&operator.id),
                operator.role,
                operator.revision,
                if operator.active { "Active" } else { "Revoked" }
            )
            .unwrap();
            if operator.active {
                begin(&mut html, csrf, "revoke_operator");
                write!(html,"<input type=hidden name=id value='{}'><button class=button>Revoke {}</button></form>",escape(&operator.id),escape(&operator.id)).unwrap();
            }
        }
        begin(&mut html, csrf, "issue_operator");
        html.push_str("<label>Operator name<input name=id maxlength=64 required></label><label>Role<select name=role><option value=viewer>Viewer</option><option value=analyst>Analyst</option><option value=responder>Responder</option><option value=admin>Administrator</option></select></label><label>Credential lifetime days<input type=number name=days min=1 max=90 value=30 required></label><button class=button>Issue or rotate credential</button></form></section>");
    }
    let records = e.background_measurements()?;
    html.push_str("<section class='panel controls-panel fleet-panel'><h2>Measured storage work</h2><p>Process counters include concurrent activity. Physical I/O may be zero when reads are served by cache.</p>");
    if records.is_empty() {
        html.push_str("<p>No measured jobs yet.</p>");
    }
    for record in records.iter().take(8) {
        write!(
            html,
            "<p>{} · {} microseconds · peak process memory {} KiB · {}</p>",
            escape(record["kind"].as_str().unwrap_or("job")),
            record["elapsed_us"],
            record["peak_rss_kib"],
            if record["succeeded"] == true {
                "Completed"
            } else {
                "Failed"
            }
        )
        .unwrap();
    }
    html.push_str("</section>");
    Ok(html)
}
