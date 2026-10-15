use crate::{codec, engine::Snapshot, model::*, web::Filters};
use std::fmt::Write;

pub fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
fn number(n: usize) -> String {
    let digits = n.to_string();
    let mut result = String::new();
    for (i, ch) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            result.push(',');
        }
        result.push(ch);
    }
    result
}
pub(crate) fn size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 {
        format!("{:.2} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}
pub(crate) fn time(ms: u64) -> String {
    let seconds = ms / 1000;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600 % 24,
        seconds / 60 % 60,
        seconds % 60
    )
}
pub(crate) fn age(ms: u64) -> String {
    let seconds = now_ms().saturating_sub(ms) / 1000;
    if seconds < 60 {
        format!("{seconds}s ago")
    } else if seconds < 3600 {
        format!("{}m ago", seconds / 60)
    } else {
        format!("{}h ago", seconds / 3600)
    }
}
pub(crate) fn badge(severity: u8) -> String {
    format!(
        "<span class='badge {}'><span></span>{}</span>",
        severity_label(severity),
        severity_label(severity)
    )
}
pub(crate) fn icon(name: &str) -> String {
    let paths = match name {
        "overview" => "<path d='M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z'/>",
        "cases" => "<path d='M3 7h7l2 2h9v11H3zM3 7V4h7l2 3M8 13h8M8 16h5'/>",
        "sources" => "<path d='M7 3v5m10-5v5M5 8h14v3a7 7 0 0 1-14 0zM12 18v4'/>",
        "investigate" => "<circle cx='10.5' cy='10.5' r='6.5'/><path d='m16 16 5 5'/>",
        "detections" => "<path d='m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6zM8 12l3 3 5-6'/>",
        "workbench" => {
            "<path d='m12 2 2.5 6.5L21 11l-6.5 2.5L12 20l-2.5-6.5L3 11l6.5-2.5zM20 18v4M18 20h4'/>"
        }
        "hive" => "<path d='m12 2 9 5v10l-9 5-9-5V7zM12 8v8M8 10l8 4m-8 0 8-4'/>",
        "retention" => "<ellipse cx='12' cy='5' rx='9' ry='3'/><path d='M3 5v14c0 4 18 4 18 0V5M3 12c0 4 18 4 18 0'/>",
        "research" => "<path d='M9 3h6M10 3v6L4 19q-1 2 2 2h12q3 0 2-2L14 9V3M8 14h8'/>",
        "arrow" => "<path d='M5 12h14m-5-5 5 5-5 5'/>",
        "download" => "<path d='M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5'/>",
        _ => "<path d='M3 12h4l3-7 4 14 3-7h4'/>",
    };
    format!("<svg viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='1.65' stroke-linecap='round' stroke-linejoin='round' aria-hidden='true'>{paths}</svg>")
}

pub(crate) fn button(
    csrf: &str,
    op: &str,
    value: &str,
    label: &str,
    class: &str,
    back: &str,
) -> String {
    format!("<form method=post action=/action class=inline-form><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{}'><input type=hidden name=value value='{}'><input type=hidden name=back value='{}'><button class='{}' type=submit>{}</button></form>",escape(csrf),escape(op),escape(value),escape(back),class,escape(label))
}

fn scenario_menu(csrf: &str, back: &str) -> String {
    let mut html="<details class=scenario-menu><summary class='button primary'>＋ Inject scenario <span>⌄</span></summary><div class=scenario-options><div class=eyebrow>CONTROLLED / SYNTHETIC</div>".to_string();
    for (value, label, description) in [
        (
            "chain",
            "Full attack chain",
            "Auth burst → privilege → egress",
        ),
        (
            "auth",
            "Authentication burst",
            "Nine denied attempts · two-minute window",
        ),
        (
            "policy",
            "Policy boundary",
            "A blocked control-plane request",
        ),
        ("normal", "Baseline traffic", "48 ordinary workload events"),
    ] {
        write!(
            html,
            "<div>{}<small>{description}</small></div>",
            button(csrf, "scenario", value, label, "scenario-choice", back)
        )
        .unwrap();
    }
    html.push_str("</div></details>");
    html
}

pub fn page(
    s: &Snapshot,
    view: &str,
    filters: &Filters,
    selected: Option<i64>,
    csrf: &str,
) -> String {
    let label = match view {
        "cases" | "case" => "Investigations",
        "sources" | "source" => "Source management",
        "investigate" | "event" => "Event explorer",
        "detections" => "Detection engineering",
        "workbench" => "Athernex intelligence",
        "research" => "Research notebook",
        "incident" => "Investigation",
        "hive" | "agent" | "task" => "Agent hive",
        "retention" | "archive" => "Rolling memory",
        _ => "Command overview",
    };
    let mut html=format!("<!doctype html><html lang=en><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><meta name=theme-color content='#06120f'><meta name=description content='Athernex: a Rust SIEM research lab for a datacenter in one rack.'><title>{label} · Athernex</title><link rel=icon href=/favicon.svg><link rel=stylesheet href=/assets/app.css>");
    if (s.live || !s.demo) && view == "overview" {
        html.push_str("<meta http-equiv=refresh content=5>");
    }
    html.push_str("</head><body><a class=skip-link href=#main>Skip to content</a><div class=app><aside class=sidebar><a href=/ class=brand><svg viewBox='0 0 38 40' aria-hidden=true><path d='M3 34 19 5l16 29M10 23h18' fill=none stroke=currentColor stroke-width=3.5/><path d='m15 34 4-8 4 8' fill=currentColor/></svg><span>ATHERNEX<small>SECURITY RESEARCH LAB</small></span></a><div class=workspace><span class=workspace-symbol>⌘</span><div>Single-rack lab<small>Synthetic environment</small></div><span class=workspace-dot></span></div><div class=nav-label>WORKSPACE</div><nav aria-label=Primary>");
    for (id, path, text) in [
        ("overview", "/", "Overview"),
        ("investigate", "/investigate", "Event explorer"),
        ("cases", "/cases", "Investigations"),
        ("sources", "/sources", "Sources"),
        ("detections", "/detections", "Detections"),
        ("hive", "/hive", "Agent hive"),
        ("workbench", "/workbench", "Athernex AI"),
        ("retention", "/retention", "Rolling memory"),
        ("research", "/research", "Research notebook"),
    ] {
        let active = view == id
            || (view == "case" && id == "cases")
            || (view == "source" && id == "sources")
            || (view == "event" && id == "investigate")
            || (view == "incident" && id == "detections")
            || (["agent", "task"].contains(&view) && id == "hive")
            || (view == "archive" && id == "retention");
        write!(
            html,
            "<a href='{path}' aria-label='{text}' class='nav-item {}' {}>{}<span>{text}</span>{}</a>",
            if active { "active" } else { "" },
            if active { "aria-current=page" } else { "" },
            icon(id),
            if id == "workbench" {
                "<span class=nav-tag>R&D</span>"
            } else {
                ""
            }
        )
        .unwrap();
    }
    write!(html,"</nav><div class=sidebar-bottom><div class=engine-status><span class=signal-dot></span>Rust engine online</div><p>One rack.<br>A complete research frontier.</p><div class=sidebar-meter><span>EVENT RETENTION</span><b>{} / 4,096</b><meter min=0 max=4096 value='{}' aria-label='Retained event budget'></meter></div><a href=/research class=sidebar-link>Read the experiment {}</a><div class=version>AEF1 / LAB v0.2.0</div></div></aside><div class=main-wrap><header class=topbar><div class=breadcrumb>CONTROL PLANE <span>/</span> <strong>{label}</strong></div><div class=topbar-right><span class=env-label><span></span> LOCAL LAB</span><a href=/api/export class=icon-link aria-label='Export lab evidence'>{}</a></div></header><main id=main>",number(s.events.len()),s.events.len(),icon("arrow"),icon("download")).unwrap();
    html=html.replacen("</div></header>",&format!("<form method=post action=/logout><input type=hidden name=csrf value='{}'><button class=lock-button aria-label='Lock operator console'>Lock ↗</button></form></div></header>",escape(csrf)),1);
    if !filters.notice.is_empty() {
        write!(html, "<div class=notice>{}</div>", escape(&filters.notice)).unwrap();
    }
    if !s.storage_error.is_empty() {
        write!(
            html,
            "<div class=notice>Storage needs attention: {}</div>",
            escape(&s.storage_error)
        )
        .unwrap();
    }
    match view {
        "sources" => crate::render_ops::sources(&mut html, s, csrf),
        "source" => crate::render_ops::source(&mut html, s, &filters.q, csrf),
        "cases" => crate::render_ops::cases(&mut html, s, filters, csrf),
        "case" => crate::render_ops::case(&mut html, s, selected.unwrap_or(0), csrf),
        "hive" => crate::render_hive::hive(&mut html, s, csrf),
        "agent" => crate::render_hive::agent(&mut html, s, selected.unwrap_or(0), csrf),
        "task" => crate::render_hive::task(&mut html, s, selected.unwrap_or(0), csrf),
        "retention" => crate::render_hive::retention(&mut html, s, csrf),
        "archive" => crate::render_hive::archive(&mut html, s, selected.unwrap_or(0)),
        "investigate" => explorer(&mut html, s, filters, csrf),
        "detections" => detections(&mut html, s, csrf),
        "workbench" => workbench(&mut html, s, csrf),
        "research" => research(&mut html, s, filters),
        "event" => event_detail(&mut html, s, selected.unwrap_or(0), csrf),
        "incident" => incident(&mut html, s, selected.unwrap_or(0), csrf),
        _ => overview(&mut html, s, csrf),
    }
    html.push_str("</main><footer><span><i></i> SYNTHETIC DATA · REAL RUST PIPELINE</span><span>Evidence before action. <b>Always.</b></span><span>UTC timestamps / bounded by design</span></footer></div></div></body></html>");
    if !s.demo {
        html = html
            .replace("Synthetic environment", "Linux operations")
            .replace(
                "SYNTHETIC DATA · REAL RUST PIPELINE",
                "LIVE SOURCES · RUST CONTROL PLANE",
            )
            .replace("LOCAL LAB", "LOCAL OPERATIONS");
    }
    html
}

pub(crate) fn heading(
    html: &mut String,
    eyebrow: &str,
    title: &str,
    description: &str,
    actions: &str,
) {
    write!(html,"<div class=page-heading><div><div class=eyebrow>{eyebrow}</div><h1>{title}</h1><p>{description}</p></div><div class=heading-actions>{actions}</div></div>").unwrap();
}

fn overview(html: &mut String, s: &Snapshot, csrf: &str) {
    let controls = if !s.demo {
        "<a class='button secondary' href=/cases>Investigations ↗</a><a class='button primary' href=/sources>Manage sources ↗</a>".into()
    } else {
        format!(
            "{}{}",
            button(
                csrf,
                "live",
                "",
                if s.live {
                    "Ⅱ Pause stream"
                } else {
                    "▷ Start stream"
                },
                "button secondary",
                "/"
            ),
            scenario_menu(csrf, "/")
        )
    };
    heading(
        html,
        "SECURITY OPERATIONS / 01",
        "Signal over noise.",
        "Your rack, translated into security intelligence.",
        &controls,
    );
    let open = s
        .cases
        .iter()
        .filter(|c| crate::operations::case_open(&c.status))
        .count();
    let critical = s
        .cases
        .iter()
        .filter(|f| crate::operations::case_open(&f.status) && f.severity == 5)
        .count();
    let average = s.payload_bytes as f64 / s.events.len().max(1) as f64;
    let savings = if s.normalized_json_bytes == 0 {
        0.0
    } else {
        100.0 * (1.0 - s.payload_bytes as f64 / s.normalized_json_bytes as f64)
    };
    write!(html,"<div class=metrics><a class=metric href=/investigate><div>Events retained <span class=metric-symbol>↗</span></div><strong>{}</strong><small><b class=mint>{}</b> accepted since creation</small></a><a class=metric href=/cases><div>Open investigations <span class='metric-symbol coral'>◉</span></div><strong>{open}<em>{critical} critical</em></strong><small>Assigned cases · preserved evidence</small></a><a class=metric href=/retention><div>Compact event payload <span class=metric-symbol>⌁</span></div><strong>{average:.1}<em class=unit>bytes / event</em></strong><small><b class=mint>{savings:.1}% smaller</b> payload only · excludes provenance</small></a><a class=metric href=/detections><div>Enabled detections <span class=metric-symbol>◇</span></div><strong>{}<em class=unit>/ 5 rules</em></strong><small>Active rules · explicit field contracts</small></a></div>",number(s.events.len()),number(s.total_received as usize),s.enabled_rules.len()).unwrap();
    html.push_str("<div class=overview-top><section class='panel pulse-panel'><div class=panel-heading><div><h2>Security pulse</h2><p>Normalized events across the last 20 minutes</p></div><div class=legend><span class=legend-cyan></span> Events <span class=legend-coral></span> Findings</div></div>");
    pulse(html, s);
    write!(html,"<div class=chart-caption><span><i class='dot mint-dot'></i>{}</span><span>Overview refreshes every 5 seconds <b>UTC</b></span></div></section><section class='panel sources-panel'><div class=panel-heading><div><h2>{}</h2><p>{}</p></div><a class=text-link href=/sources>Manage ↗</a></div>",if s.demo {"Explicit synthetic demo"}else{"Operational collection"},if s.demo {"Demo source streams"}else{"Connected sources"},if s.demo {"Fixture counts from the retained event window."}else{"Collection health and managed adapters."}).unwrap();
    if s.demo {
        let mut streams = std::collections::BTreeMap::<&str, (usize, u64)>::new();
        for event in &s.events {
            let stream = streams.entry(&event.source_label).or_default();
            stream.0 += 1;
            stream.1 = stream.1.max(event.event.time_ms);
        }
        for (source, (count, last)) in streams {
            write!(html,"<a class=source-row href='/investigate?q={}'><span class=source-glyph>◈</span><div><strong>{}</strong><small>{} · fixture</small></div><div class=source-count>{count}<small>retained</small></div><span class=source-arrow>↗</span></a>",escape(source),escape(source),age(last)).unwrap();
        }
    } else {
        for source in &s.sources {
            write!(html,"<a class=source-row href='/source/{}'><span class=source-glyph>◈</span><div><strong>{}</strong><small>{}</small></div><div class=source-count>{}<small>accepted</small></div><span class=source-arrow>↗</span></a>",escape(&source.id),escape(&source.id),if !source.enabled {"Paused".into()}else if !source.error.is_empty(){"Needs attention".into()}else if source.last_event_ms==0 {"No observations yet".into()}else{age(source.last_event_ms)},source.received).unwrap();
        }
    }
    if !s.demo && !s.sources.iter().any(|x| x.kind != "internal") {
        html.push_str("<div class=empty>No external source is registered. Add a journal or authenticated API source.</div>");
    }
    write!(
        html,
        "<div class=source-note><span>◈</span> {}</div></section></div>",
        if s.demo {
            "Explicit fixtures exercise the same Rust pipeline. No host journal is connected."
        } else {
            "Inspect each source for poll freshness, errors and checkpoint state."
        }
    )
    .unwrap();
    html.push_str("<section class='panel findings-panel'><div class=panel-heading><div><h2>Investigations that matter <span class=inline-label>EVIDENCE ATTACHED</span></h2><p>Follow a signal from its first observation to a reviewable decision.</p></div><a class=text-link href=/cases>Manage investigations ↗</a></div><div class=finding-grid>");
    for finding in s.findings.iter().filter(|f| f.status == "open").take(4) {
        finding_card(html, finding);
    }
    if open == 0 {
        html.push_str("<div class=empty>No open investigations. Incoming detections create cases automatically; you can also open a case manually.</div>");
    }
    html.push_str("</div></section><div class=overview-bottom><section class='panel stream-panel'><div class=panel-heading><div><h2>On the wire</h2><p>Readable Athernex notation over real binary events</p></div><a class=text-link href=/investigate>Explore events ↗</a></div>");
    for event in s.events.iter().rev().take(5) {
        write!(html,"<a class=wire-row href='/event/{}'><time>{}</time><code class='code-{}'>{}{}</code><span>{} <i>→</i> {}</span><b>{} B</b></a>",event.event.id,time(event.event.time_ms),event.event.kind.code(),event.event.kind.code(),event.event.outcome.symbol(),escape(&event.subject_label),escape(&event.object_label),event.encoded_bytes).unwrap();
    }
    write!(html,"</section><section class='panel footprint-panel'><div class=eyebrow>SMALL BY DESIGN</div><h2>Every byte has<br>to earn its place.</h2><div class=footprint-value>{}<span>AEF1 event payloads</span></div><div class=footprint-row><span>Database pages</span><b>{}</b></div><div class=footprint-row><span>Write-ahead log</span><b>{}</b></div><a class=text-link href=/research>See what the numbers include ↗</a></section></div>",size(s.payload_bytes as u64),size(s.database_bytes),size(s.wal_bytes)).unwrap();
}

fn pulse(html: &mut String, s: &Snapshot) {
    let end = now_ms();
    let start = end.saturating_sub(1_200_000);
    let mut bins = [0usize; 40];
    for event in &s.events {
        if event.event.time_ms >= start && event.event.time_ms <= end {
            bins[((event.event.time_ms - start) / 30_000).min(39) as usize] += 1;
        }
    }
    let maximum = *bins.iter().max().unwrap_or(&1).max(&1);
    html.push_str("<svg class=pulse-chart viewBox='0 0 760 230' role=img aria-label='Event volume for the last twenty minutes'><defs><linearGradient id=pulse-fill x1=0 y1=0 x2=0 y2=1><stop offset='0%' stop-color='#64e3eb' stop-opacity='.28'/><stop offset='100%' stop-color='#64e3eb' stop-opacity='.015'/></linearGradient></defs>");
    for i in 0..4 {
        let y = 20 + i * 54;
        write!(
            html,
            "<path class=chart-grid d='M40 {y}H745'/><text class=chart-label x=6 y='{}'>{}</text>",
            y + 4,
            maximum * (3 - i) / 3
        )
        .unwrap();
    }
    let points = bins
        .iter()
        .enumerate()
        .map(|(i, n)| {
            format!(
                "{:.1},{:.1}",
                45.0 + i as f64 * 17.8,
                182.0 - *n as f64 / maximum as f64 * 156.0
            )
        })
        .collect::<Vec<_>>()
        .join(" ");
    write!(html,"<polygon points='45,183 {points} 739.2,183' fill='url(#pulse-fill)'/><polyline points='{points}' fill=none stroke='#64e3eb' stroke-width=2.5 stroke-linejoin=round/>").unwrap();
    for finding in s
        .findings
        .iter()
        .filter(|f| f.time_ms >= start && f.time_ms <= end)
        .take(30)
    {
        let bin = ((finding.time_ms - start) / 30_000).min(39) as usize;
        write!(html,"<circle cx='{:.1}' cy='{:.1}' r=4 fill='#fb927d' stroke='#0a1d18' stroke-width=2><title>{}</title></circle>",45.0+bin as f64*17.8,182.0-bins[bin] as f64/maximum as f64*156.0,escape(&finding.title)).unwrap();
    }
    for i in 0..5 {
        write!(
            html,
            "<text class=chart-label x='{}' y=218>{}</text>",
            40 + i * 168,
            &time(start + i as u64 * 300_000)[..5]
        )
        .unwrap();
    }
    html.push_str("</svg>");
}

fn finding_card(html: &mut String, f: &Finding) {
    write!(html,"<a class=finding-card href='/incident/{}'><div>{}<span class=rule-id>{}</span></div><h3>{}</h3><p>{}</p><div class=finding-card-bottom><span>◈ {} facts</span><span>{} ↗</span></div></a>",f.id,badge(f.severity),escape(&f.rule),escape(&f.title),escape(&f.subject),f.evidence.len(),age(f.time_ms)).unwrap();
}

pub fn filter_events<'a>(events: &'a [DisplayEvent], filters: &Filters) -> Vec<&'a DisplayEvent> {
    let search = filters.q.to_lowercase();
    events
        .iter()
        .rev()
        .filter(|event| {
            let kind = filters.kind.is_empty()
                || event.event.kind.code().eq_ignore_ascii_case(&filters.kind);
            let severity = filters.severity.is_empty()
                || severity_label(event.event.severity) == filters.severity;
            let haystack = format!(
                "{} {} {} {} {} {} {}",
                event.source_label,
                event.subject_label,
                event.object_label,
                event.notation,
                event.event.kind.label(),
                event.event.outcome.label(),
                event.event.id
            )
            .to_lowercase();
            kind && severity
                && search
                    .split_whitespace()
                    .all(|word| haystack.contains(word))
        })
        .collect()
}

pub(crate) fn event_table(html: &mut String, events: &[&DisplayEvent]) {
    html.push_str("<div class=table-scroll><table><thead><tr><th>Time / UTC</th><th>Event</th><th>Subject → object</th><th>Source</th><th>Severity</th><th>Payload</th><th></th></tr></thead><tbody>");
    for event in events {
        write!(html,"<tr><td class=mono>{}<small>#{}</small></td><td><code class='event-code code-{}'>{}{}</code><small>{}</small></td><td><a href='/event/{}'>{}</a><small>→ {}</small></td><td>{}</td><td>{}</td><td class=mono>{} B</td><td><a class=table-arrow href='/event/{}' aria-label='Inspect event {}'>↗</a></td></tr>",time(event.event.time_ms),event.event.id,event.event.kind.code(),event.event.kind.code(),event.event.outcome.symbol(),event.event.kind.label(),event.event.id,escape(&event.subject_label),escape(&event.object_label),escape(&event.source_label),badge(event.event.severity),event.encoded_bytes,event.event.id,event.event.id).unwrap();
    }
    if events.is_empty() {
        html.push_str("<tr><td colspan=7 class=empty>No events match these filters.</td></tr>");
    }
    html.push_str("</tbody></table></div>");
}

fn explorer(html: &mut String, s: &Snapshot, filters: &Filters, csrf: &str) {
    heading(
        html,
        "INVESTIGATION / 02",
        "Follow the evidence.",
        "Search normalized facts. Inspect the exact bytes. Keep the context.",
        &if s.demo {
            scenario_menu(csrf, "/investigate")
        } else {
            "<a class='button primary' href=/sources>Manage sources ↗</a>".into()
        },
    );
    write!(html,"<form class=filter-bar action=/investigate method=get><label class=search-field><span>{}</span><input name=q value='{}' placeholder='Search subject, source, event code…' aria-label='Search events'></label><select name=kind aria-label='Event kind'><option value=''>All event kinds</option>",icon("investigate"),escape(&filters.q)).unwrap();
    for (code, label) in [
        ("AU", "Authentication"),
        ("PX", "Process"),
        ("NF", "Network"),
        ("PL", "Policy"),
        ("HB", "Heartbeat"),
        ("SY", "System"),
    ] {
        write!(
            html,
            "<option value='{code}' {}>{label}</option>",
            if filters.kind == code { "selected" } else { "" }
        )
        .unwrap();
    }
    html.push_str("</select><select name=severity aria-label=Severity><option value=''>All severities</option>");
    for severity in ["critical", "high", "medium", "low", "info"] {
        write!(
            html,
            "<option {}>{severity}</option>",
            if filters.severity == severity {
                "selected"
            } else {
                ""
            }
        )
        .unwrap();
    }
    html.push_str("</select><button class='button primary'>Apply filters</button><a class='button ghost' href=/investigate>Reset</a></form>");
    let matched = filter_events(&s.events, filters);
    let page = filters.page.min(matched.len().saturating_sub(1) / 50);
    write!(html,"<section class=panel><div class=panel-heading><div><h2>Event ledger <span class=small-counter>{}</span></h2><p>AEF1 schema · lossless normalized fields · labels resolved from the dictionary</p></div><a class=text-link href=/api/export>Export evidence ↓</a></div>",number(matched.len())).unwrap();
    event_table(
        html,
        &matched
            .iter()
            .skip(page * 50)
            .take(50)
            .copied()
            .collect::<Vec<_>>(),
    );
    write!(html,"<div class=pagination><span>Page {} of {} · 50 events per page</span><form action=/investigate method=get><input type=hidden name=q value='{}'><input type=hidden name=kind value='{}'><input type=hidden name=severity value='{}'><button class='button secondary' name=page value='{}' {}>← Previous</button><button class='button secondary' name=page value='{}' {}>Next →</button></form></div></section>",page+1,matched.len().div_ceil(50).max(1),escape(&filters.q),escape(&filters.kind),escape(&filters.severity),page.saturating_sub(1),if page==0{"disabled"}else{""},page+1,if (page+1)*50>=matched.len(){"disabled"}else{""}).unwrap();
}

fn detections(html: &mut String, s: &Snapshot, csrf: &str) {
    heading(
        html,
        "DETECTION ENGINEERING / 03",
        "Rules you can explain.",
        "Deterministic correlations, explicit field requirements, inspectable evidence.",
        &scenario_menu(csrf, "/detections"),
    );
    html.push_str("<div class=rule-grid>");
    for rule in &RULES {
        let enabled = s.enabled_rules.iter().any(|id| id == rule.id);
        let count = s.findings.iter().filter(|f| f.rule == rule.id).count();
        write!(html,"<article class='panel rule-card'><div class=rule-top><span class=rule-id>{}</span>{}</div><h2>{}</h2><p>{}</p><div class=rule-fields><small>REQUIRED FACTS</small><code>{}</code></div><div class=rule-footer><span>◷ {}<br><b>{count} retained findings</b></span>{}</div></article>",rule.id,badge(rule.severity),rule.title,rule.description,rule.fields,rule.window,button(csrf,"rule",rule.id,if enabled{"● Enabled"}else{"○ Disabled"},if enabled{"button enabled"}else{"button secondary"},"/detections")).unwrap();
    }
    html.push_str("</div><section class=panel><div class=panel-heading><div><h2>Finding ledger</h2><p>Disabling a rule preserves its existing evidence and audit history.</p></div></div><div class=table-scroll><table><thead><tr><th>Finding</th><th>Subject</th><th>Severity</th><th>Evidence</th><th>Disposition</th><th>Observed</th></tr></thead><tbody>");
    for f in &s.findings {
        write!(html,"<tr><td><a href='/incident/{}'>{}</a><small>{}</small></td><td>{}</td><td>{}</td><td>{} facts</td><td><span class='status {}'>{}</span></td><td class=mono>{}</td></tr>",f.id,escape(&f.title),f.rule,escape(&f.subject),badge(f.severity),f.evidence.len(),f.status,f.status,time(f.time_ms)).unwrap();
    }
    if s.findings.is_empty() {
        html.push_str("<tr><td colspan=6 class=empty>No findings yet. Inject a scenario to test these rules.</td></tr>");
    }
    html.push_str("</tbody></table></div></section>");
}

fn event_detail(html: &mut String, s: &Snapshot, id: i64, csrf: &str) {
    let event = s
        .events
        .iter()
        .find(|e| e.event.id == id as u64)
        .or_else(|| {
            s.findings
                .iter()
                .flat_map(|f| &f.evidence)
                .find(|e| e.event.id == id as u64)
        });
    let event = event.or_else(|| {
        s.cases
            .iter()
            .flat_map(|c| &c.evidence)
            .find(|e| e.event.id == id as u64)
    });
    let Some(event) = event else {
        heading(
            html,
            "EVENT EXPLORER",
            "Event no longer retained.",
            "The bounded event ring has advanced. Finding evidence is retained separately.",
            "<a class='button secondary' href=/investigate>Back to events</a>",
        );
        return;
    };
    heading(
        html,
        "EVENT ANATOMY / AEF1",
        "One event. Every bit.",
        &format!(
            "Event #{} · {} UTC · {}",
            event.event.id,
            time(event.event.time_ms),
            escape(&event.source_label)
        ),
        "<a class='button secondary' href=/investigate>← Event explorer</a>",
    );
    let encoded = codec::encode(&event.event);
    write!(html,"<div class=event-anatomy><section class='panel notation-panel'><div class=eyebrow>ATHERNEX / READABLE NOTATION</div><div class=big-code>{}{}</div><h2>{}</h2><p>{} → {}</p><div class=notation-meta>{}<span>{} B encoded</span><span>{} B normalized JSON</span></div><p class=muted>The short code names the event class and outcome. Identity, timestamps, and context remain in the binary record.</p></section><section class='panel hex-panel'><div class=eyebrow>EXACT ENCODED PAYLOAD / {} BYTES</div><div class=hex-dump>{}</div><div class=hex-legend><span><b>41 45 46 31</b> AEF1 magic</span><span>8 unsigned varints</span><span>3 typed enums</span></div><div class=roundtrip>✓ Decoded from the stored blob · all normalized fields preserved</div></section></div><section class=panel><div class=panel-heading><h2>Decoded facts</h2><span class=inline-label>NO RAW LOG BODY</span></div><dl class=fact-grid>",event.event.kind.code(),event.event.outcome.symbol(),event.event.kind.label(),escape(&event.subject_label),escape(&event.object_label),badge(event.event.severity),encoded.len(),event.json_bytes,encoded.len(),encoded.iter().map(|b|format!("<span>{b:02x}</span>")).collect::<String>()).unwrap();
    for (label, value) in [
        ("Source", event.source_label.clone()),
        ("Subject", event.subject_label.clone()),
        ("Object", event.object_label.clone()),
        ("Event time", event.event.time_ms.to_string()),
        ("Observed time", event.event.observed_ms.to_string()),
        ("Outcome", event.event.outcome.label().to_string()),
        ("Transferred", size(event.event.bytes)),
        ("Trace", event.event.trace.to_string()),
    ] {
        write!(
            html,
            "<div><dt>{label}</dt><dd>{}</dd></div>",
            escape(&value)
        )
        .unwrap();
    }
    html.push_str("</dl></section>");
    crate::render_ops::event_controls(html, s, event, csrf);
}

fn incident(html: &mut String, s: &Snapshot, id: i64, csrf: &str) {
    let Some(f) = s.findings.iter().find(|f| f.id == id) else {
        heading(
            html,
            "INVESTIGATION",
            "Finding unavailable.",
            "This finding is outside the retained research window.",
            "<a href=/detections class=button>All detections</a>",
        );
        return;
    };
    let mut actions = if f.status == "open" {
        format!(
            "{}{}",
            button(
                csrf,
                "resolve",
                &id.to_string(),
                "Mark resolved",
                "button secondary",
                "/detections"
            ),
            button(
                csrf,
                "propose",
                &id.to_string(),
                "◇ Create review plan",
                "button primary",
                "/workbench"
            )
        )
    } else {
        "<span class='status resolved'>Resolved</span>".into()
    };
    if let Some(case) = s.cases.iter().find(|c| c.finding_id == Some(id)) {
        write!(
            actions,
            "<a class='button secondary' href='/case/{}'>Manage investigation ↗</a>",
            case.id
        )
        .unwrap();
    }
    heading(
        html,
        &format!("INVESTIGATION / {} / #{id}", f.rule),
        &escape(&f.title),
        &format!(
            "{} · {} UTC · {} supporting facts",
            escape(&f.subject),
            time(f.time_ms),
            f.evidence.len()
        ),
        &actions,
    );
    write!(html,"<section class='panel incident-summary'><div>{}<span class=rule-id>{}</span></div><h2>Why the engine raised this signal</h2><p>{}</p><div class=evidence-chain>",badge(f.severity),f.rule,escape(&f.explanation)).unwrap();
    for (index, event) in f.evidence.iter().enumerate() {
        write!(html,"{}<a href='/event/{}'><span class='event-code code-{}'>{}{}</span><b>{}</b><small>{}</small></a>",if index>0{"<span class=chain-arrow>→</span>"}else{""},event.event.id,event.event.kind.code(),event.event.kind.code(),event.event.outcome.symbol(),event.event.kind.label(),time(event.event.time_ms)).unwrap();
    }
    write!(html,"</div><div class=evidence-hash><span>Evidence boundary</span>Normalized facts are copied into this finding before the event ring rotates. No raw logs are retained.</div></section><section class=panel><div class=panel-heading><div><h2>Supporting evidence</h2><p>Read the sequence. Verify the context. Decide what happens next.</p></div></div>").unwrap();
    event_table(html, &f.evidence.iter().collect::<Vec<_>>());
    html.push_str("</section>");
}

fn workbench(html: &mut String, s: &Snapshot, csrf: &str) {
    heading(html,"ATHERNEX AI / RESEARCH WORKBENCH","Evidence before action.","A Rust-native alternative to agent sprawl: bounded plans, explicit review, durable decisions.","<span class='mode-chip'>◈ Deterministic planner</span>");
    let pending = s
        .plans
        .iter()
        .filter(|p| p.state == "awaiting_review" || p.state == "approved")
        .count();
    write!(html,"<div class=workbench-banner><div class=intelligence-mark>✳</div><div><h2>Intelligence is a proposal. Authority is a policy.</h2><p>This build uses a deterministic evidence planner. No language model is connected. Operational plans move an investigation to triage and record an evidence-bound review receipt after explicit approval.</p></div><div class=budget-counter><strong>{pending}<span>/ 16</span></strong><small>REVIEW BUDGET</small></div></div><div class=workbench-grid><section><div class=section-heading><h2>Review queue</h2><span>{} plans</span></div>",s.plans.len()).unwrap();
    if s.plans.is_empty() {
        html.push_str("<div class='panel empty-plan'><span>◇</span><h2>Turn a finding into a reviewable plan.</h2><p>Choose an investigation below. Athernex will bind the plan to its evidence, assign a 15-minute lifetime, and hold execution for review.</p></div>");
    }
    for plan in &s.plans {
        write!(html,"<article class='panel plan-card'><div class=plan-top><span class=rule-id>PLAN / {:03}</span><span class='status {}'>{}</span></div><h2>{}</h2><p>{}</p><ol>",plan.id,plan.state,escape(&plan.state.replace('_'," ")),escape(&plan.title),escape(&plan.rationale)).unwrap();
        for step in &plan.steps {
            write!(html, "<li>{}</li>", escape(step)).unwrap();
        }
        write!(html,"</ol><div class=plan-proof><span>EVIDENCE SHA-256</span><code>{}</code><small>Expires {} UTC · tied to finding #{}</small></div><div class=plan-actions>",&plan.evidence_hash[..24],time(plan.expires_ms),plan.finding_id).unwrap();
        match plan.state.as_str() {
            "awaiting_review"=>{html.push_str(&button(csrf,"approve",&plan.id.to_string(),if s.demo {"Approve simulation"}else{"Approve case triage"},"button primary","/workbench"));html.push_str(&button(csrf,"reject",&plan.id.to_string(),"Reject","button secondary","/workbench"));},
            "approved"=>{html.push_str(&button(csrf,if s.demo {"simulate"}else{"execute"},&plan.id.to_string(),if s.demo {"Run response simulation"}else{"Execute case triage"},"button primary","/workbench"));html.push_str(&button(csrf,"reject",&plan.id.to_string(),"Revoke approval","button secondary","/workbench"));},
            "executed"=>html.push_str("<span class=complete-note>✓ Investigation moved to triage. Review receipt committed.</span>"),
            "simulation_complete"=>html.push_str("<span class=complete-note>✓ Simulation recorded. No infrastructure was changed.</span>"),
            _=>html.push_str("<span class=muted>This plan is closed.</span>"),
        }
        write!(
            html,
            "<a class=text-link href='/incident/{}'>Inspect evidence ↗</a></div></article>",
            plan.finding_id
        )
        .unwrap();
    }
    html.push_str("<div class=section-heading><h2>Available investigations</h2></div>");
    for finding in s
        .findings
        .iter()
        .filter(|f| f.status == "open" && !s.plans.iter().any(|p| p.finding_id == f.id))
        .take(8)
    {
        write!(html,"<div class=available-finding><div>{}<strong>{}</strong><small>{}</small></div>{}</div>",badge(finding.severity),escape(&finding.title),escape(&finding.subject),button(csrf,"propose",&finding.id.to_string(),"Draft plan ↗","button secondary","/workbench")).unwrap();
    }
    html.push_str("</section><aside class='panel audit-panel'><div class=panel-heading><div><h2>Decision trail</h2><p>Most recent 40 audit records</p></div></div><div class=audit-list role=region tabindex=0 aria-label='Decision audit records'>");
    for audit in &s.audit {
        write!(html,"<div class=audit-item><span class=audit-dot></span><time>{}</time><strong>{}</strong><p>{}</p></div>",time(audit.time_ms),escape(&audit.action),escape(&audit.detail)).unwrap();
    }
    html.push_str("</div></aside></div>");
}

fn research(html: &mut String, s: &Snapshot, filters: &Filters) {
    heading(
        html,
        "RESEARCH NOTEBOOK / 04",
        "Show the work.",
        "Measurements over marketing. Hypotheses with a way to prove them wrong.",
        "<a class='button secondary' href=/api/export>↓ Export lab evidence</a>",
    );
    projection(html, s, filters);
    let savings = if s.normalized_json_bytes == 0 {
        0.0
    } else {
        100.0 * (1.0 - s.payload_bytes as f64 / s.normalized_json_bytes as f64)
    };
    write!(html,"<div class=research-hero><div><div class=eyebrow>EXPERIMENT 001 / SEMANTIC COMPACTION</div><h2>Smaller events.<br><span>Same selected facts.</span></h2><p>AEF1 stores typed values and dictionary references. It removes repeated syntax, while the readable Athernex notation helps an analyst scan the stream.</p><div class=research-measure><strong>{savings:.1}%</strong><span>event payload reduction<br>vs equivalent normalized JSON</span></div></div><div class=encoding-compare><div class=encoding-label><span>NORMALIZED JSON</span><b>{}</b></div><pre>{{ &quot;kind&quot;: &quot;authentication&quot;,<br>  &quot;outcome&quot;: &quot;deny&quot;,<br>  &quot;subject&quot;: 18, ... }}</pre><div class=encoding-arrow>↓ TYPED VALUES + VARINTS</div><div class=encoding-label><span>AEF1 PAYLOAD</span><b>{}</b></div><div class=encoding-token>AU− <span>s3:18→4</span></div><small>The notation is a view, not the complete stored event.</small></div></div>",size(s.normalized_json_bytes as u64),size(s.payload_bytes as u64)).unwrap();
    html.push_str("<div class=research-grid><section class=panel><div class=panel-heading><div><h2>The honest storage bill</h2><p>Payload savings do not equal whole-system savings.</p></div></div><dl class=storage-ledger>");
    for (label, value) in [
        ("Retained AEF1 event payloads", size(s.payload_bytes as u64)),
        (
            "Equivalent normalized JSON",
            size(s.normalized_json_bytes as u64),
        ),
        ("Allocated database pages", size(s.database_bytes)),
        ("Current WAL file", size(s.wal_bytes)),
        ("Identity dictionary entries", number(s.dictionary_entries)),
        ("Event retention ceiling", "4,096 events".into()),
        ("Finding retention ceiling", "128 findings".into()),
        ("SQLite page ceiling", "16 MiB at 4 KiB/page".into()),
    ] {
        write!(html, "<div><dt>{label}</dt><dd>{value}</dd></div>").unwrap();
    }
    html.push_str("</dl><p class=panel-note>Database pages include indexes, copied finding evidence, plans, and audit records. WAL size varies with checkpointing. Shared-memory files and filesystem allocation add overhead.</p></section><section class=panel><div class=panel-heading><div><h2>Compression baseline</h2><p>4,096 synthetic events per corpus · Zstandard level 3</p></div></div><div class=table-scroll><table class=benchmark-table><thead><tr><th>Corpus</th><th>JSON + Zstd</th><th>Binary + Zstd</th></tr></thead><tbody><tr><td>Repetitive</td><td>14,195 B</td><td class=mint>12,184 B</td></tr><tr><td>Mixed</td><td>75,760 B</td><td class=mint>45,250 B</td></tr><tr><td>High cardinality</td><td>171,216 B</td><td class=mint>120,727 B</td></tr></tbody></table></div><div class=benchmark-verdict><span>↗</span><p><strong>14–40% smaller after compression.</strong>The standalone AXP0 probe compares the same normalized fields. It is a separate experimental format, not an AEF1 production benchmark.</p></div><code class=run-command>make research-siem</code><p class=panel-note>Measured 2026-10-14 · Zstd 1.5.7 · fixed seed · exact round trips. No indexes, identity dictionaries, WAL, replication, encryption, or throughput included.</p></section></div>");
    html.push_str("<section class='panel hypothesis-panel'><div class=panel-heading><div><h2>Where Athernex can be different</h2><p>Research proposals. These benefits remain unproven.</p></div></div><div class=hypothesis-grid>");
    for (n,title,description,gate) in [("01","Detection-aware retention","Compile each rule's field requirements into a retention contract. Keep what a supported detection needs; explicitly mark unsupported investigations.","Gate: identical alerts and evidence across reference and compact traces."),("02","One budget for the whole rack","Admit security analysis, AI work, compaction, and batch jobs against shared CPU, memory, storage, and power budgets.","Gate: burst traffic must preserve detection latency while background work yields."),("03","Evidence-bound intelligence","Allow a model to propose explanations and plans. Rust verifies citations, resource budgets, freshness, and approval before any action.","Gate: fabricated citations and stale approvals always stop at the boundary.")] {write!(html,"<article><span class=hypothesis-number>{n}</span><h3>{title}</h3><p>{description}</p><small>{gate}</small></article>").unwrap();}
    html.push_str("</div></section><div class=research-footnote><strong>Research boundary</strong><p>Compact encoding cannot recover discarded raw context. This lab demonstrates bounded security facts and five explicit rule contracts and live Linux collection. The deployable single-host service remains an R&amp;D system; no trained AI model or rack-wide performance claim is implied.</p></div>");
}

fn projection(html: &mut String, s: &Snapshot, filters: &Filters) {
    let omitted = if crate::research::FIELDS.contains(&filters.omit.as_str()) {
        filters.omit.as_str()
    } else {
        ""
    };
    let unsupported = crate::research::unsupported_rules(omitted).unwrap_or_default();
    let blocked = unsupported
        .iter()
        .filter(|id| s.enabled_rules.iter().any(|enabled| enabled == **id))
        .count();
    html.push_str("<section class='panel projection-panel'><div class=panel-heading><div><div class=eyebrow>INTERACTIVE EXPERIMENT / RETENTION CONTRACTS</div><h2>What breaks when you keep less?</h2><p>Propose removing a field. Rust checks each enabled rule before accepting the projection.</p></div></div><form method=get action=/research class=projection-controls><label for=omit>Proposed field removal</label><select name=omit id=omit><option value=''>Keep every normalized field</option>");
    for field in crate::research::FIELDS {
        write!(
            html,
            "<option value='{field}' {}>Remove {field}</option>",
            if omitted == field { "selected" } else { "" }
        )
        .unwrap();
    }
    html.push_str("</select><button class='button primary'>Check detection impact</button></form><div class=projection-results>");
    for rule in &RULES {
        let enabled = s.enabled_rules.iter().any(|id| id == rule.id);
        let compatible = !unsupported.contains(&rule.id);
        let (class, label) = if !enabled {
            ("muted", "disabled")
        } else if compatible {
            ("mint", "supported")
        } else {
            ("coral", "unsupported")
        };
        write!(html,"<div><span class=rule-id>{}</span><strong>{}</strong><span class='{class}'>{label}</span></div>",rule.id,rule.title).unwrap();
    }
    write!(html,"</div><div class='projection-verdict {}'><strong>{}</strong><span>{}</span></div></section>",if blocked>0 {"projection-blocked"}else{"projection-supported"},if blocked>0 {"Projection refused"}else{"Contract check passed"},if blocked>0 {format!("{blocked} enabled rule(s) require this field. Missing evidence must never look like zero matches.")}else{"All enabled rule contracts retain their required fields. This is a preflight experiment; no data was modified.".into()}).unwrap();
}

pub fn grant_reveal(
    s: &Snapshot,
    grant: &crate::gateway::IssuedGrant,
    task: i64,
    csrf: &str,
) -> String {
    let html = page(s, "task", &Filters::default(), Some(task), csrf);
    let reveal=format!("<section class=secret-reveal><div class=eyebrow>ONE-TIME CREDENTIAL / GRANT {}</div><h2>Your capability is ready.</h2><p>Copy it now. Only its SHA-256 digest is stored. Use this token in the Authorization: Bearer header at the gateway.</p><code>{}</code><p>Expires at {} UTC. This credential cannot open the operator console.</p></section>",grant.id,escape(&grant.token),time(grant.expires_ms));
    html.replacen("<main id=main>", &format!("<main id=main>{reveal}"), 1)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn escapes_untrusted_markup() {
        assert_eq!(escape("<script>\"&'"), "&lt;script&gt;&quot;&amp;&#39;");
    }
    #[test]
    fn filters_are_applied_to_real_events() {
        let mut engine = crate::engine::Engine::memory().unwrap();
        engine.scenario("chain", now_ms()).unwrap();
        let events = engine.events().unwrap();
        let filters = Filters {
            kind: "NF".into(),
            severity: "critical".into(),
            ..Default::default()
        };
        let found = filter_events(&events, &filters);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].event.bytes, 32 * 1024 * 1024);
    }
}
