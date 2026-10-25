//! Server-rendered operational menus. All changes pass through authenticated POSTs.
use crate::{
    engine::Snapshot,
    model::*,
    operations::{case_open, Source, CASE_STATES},
    render::{age, badge, escape, event_table, heading},
    web::Filters,
};
use std::fmt::Write;
fn form(csrf: &str, endpoint: &str, op: &str) -> String {
    format!("<form method=post action='{endpoint}' class=control-form><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{op}'>",escape(csrf))
}
fn status(s: &Source) -> &str {
    if !s.enabled {
        "Paused"
    } else if !s.error.is_empty() {
        "Needs attention"
    } else if s.kind == "internal" {
        "Enforced"
    } else if s.kind == "api" {
        "Accepting requests"
    } else if s.last_poll_ms == 0 {
        "Awaiting data"
    } else if s.kind == "journal" && now_ms().saturating_sub(s.last_poll_ms) > 120_000 {
        "Collector stale"
    } else {
        "Connected"
    }
}
pub fn sources(html: &mut String, s: &Snapshot, csrf: &str) {
    heading(html,"COLLECTION / SOURCES","Connect the evidence.","Registered adapters, scoped credentials, durable checkpoints. Inspect and manage each source.","<a class='button primary' href='#add-source'>＋ Add source</a>");
    html.push_str("<section class='panel source-registry'><div class=panel-heading><div><h2>Source registry</h2><p>Collection status is based on adapter reads, not an invented uptime score.</p></div></div>");
    for source in &s.sources {
        write!(html,"<a class=source-row href='/source/{}'><span class=source-glyph>◈</span><div><strong>{}</strong><small>{} · {}</small></div><div class=source-count>{}<small>accepted</small></div><span class=state-pill>{}</span><span>↗</span></a>",escape(&source.id),escape(&source.id),source.kind,if source.selector.is_empty(){"All available records".into()}else{escape(&source.selector)},source.received,status(source)).unwrap();
    }
    write!(html,"</section><section class='panel controls-panel' id=add-source><div class=eyebrow>ADD AN ADAPTER</div><h2>Make the source explicit.</h2><p>Journal sources read this Linux host. API sources receive normalized facts using a source-specific token. A single all-unit journal source avoids duplicate collection.</p>{}<label>Source ID<input name=id required maxlength=48 pattern='[A-Za-z0-9_-]+' placeholder=application-api></label><label>Adapter<select name=kind><option value=api>Authenticated event API</option><option value=journal>Local systemd journal</option></select></label><label>Exact systemd unit (journal only; optional)<input name=selector maxlength=96 placeholder=ssh.service></label><button class='button primary'>Register source →</button></form></section>",form(csrf,"/sources/action","create")).unwrap();
}
pub fn source(html: &mut String, s: &Snapshot, id: &str, csrf: &str) {
    let Some(source) = s.sources.iter().find(|s| s.id == id) else {
        heading(
            html,
            "SOURCES",
            "Source not found.",
            "Select a registered adapter.",
            "<a href=/sources class=button>Sources</a>",
        );
        return;
    };
    heading(
        html,
        "COLLECTION / SOURCE",
        &escape(id),
        "Inspect collection state and manage the boundary.",
        "<a class='button secondary' href=/sources>← Sources</a>",
    );
    write!(html,"<section class='panel controls-panel'><div class=section-heading><h2>{}</h2><span class=state-pill>{}</span></div><dl class=fact-grid>",escape(&source.kind),status(source)).unwrap();
    for (label, value) in [
        ("Accepted", source.received.to_string()),
        ("Skipped records", source.rejected.to_string()),
        (
            "Last receipt",
            if source.last_event_ms == 0 {
                "None".into()
            } else {
                age(source.last_event_ms)
            },
        ),
        (
            if source.kind == "api" {
                "Last request"
            } else {
                "Last poll"
            },
            if source.last_poll_ms == 0 {
                "None".into()
            } else {
                age(source.last_poll_ms)
            },
        ),
        (
            "Unit filter",
            if source.kind != "journal" {
                "Not applicable".into()
            } else if source.selector.is_empty() {
                "All available units".into()
            } else {
                source.selector.clone()
            },
        ),
        (
            "Checkpoint",
            if source.kind != "journal" {
                "Source idempotency keys".into()
            } else if source.cursor.is_empty() {
                "No cursor yet".into()
            } else {
                "Tracked; committed with archive flush".into()
            },
        ),
    ] {
        write!(
            html,
            "<div><dt>{label}</dt><dd>{}</dd></div>",
            escape(&value)
        )
        .unwrap();
    }
    html.push_str("</dl>");
    if !source.error.is_empty() {
        write!(html, "<div class=notice>{}</div>", escape(&source.error)).unwrap();
    }
    write!(
        html,
        "<a class=text-link href='/investigate?q={}'>Explore this source’s events ↗</a></section>",
        escape(id)
    )
    .unwrap();
    if source.kind != "internal" {
        html.push_str("<section class='panel controls-panel'><h2>Source controls</h2><div class=heading-actions>");
        for (op, label) in [
            (
                if source.enabled { "pause" } else { "resume" },
                if source.enabled {
                    "Pause collection"
                } else {
                    "Resume collection"
                },
            ),
            (
                if source.kind == "api" {
                    "rotate_token"
                } else {
                    "reset_cursor"
                },
                if source.kind == "api" {
                    "Rotate credential"
                } else {
                    "Reset cursor · last 5 minutes"
                },
            ),
        ] {
            write!(html,"{}<input type=hidden name=id value='{}'><button class='button secondary'>{label}</button></form>",form(csrf,"/sources/action",op),escape(id)).unwrap();
        }
        html.push_str("</div><p>Pause stops new ingestion; retained evidence remains. Journal reset starts a fresh five-minute lookback and may replay records already outside the deduplication window. Credential rotation immediately invalidates the previous token.</p></section>");
    }
    if source.kind == "api" {
        write!(html,"<section class='panel controls-panel'><h2>Integration contract</h2><p>POST a JSON array to <code>/api/ingest/{}</code> with <code>Authorization: Bearer YOUR_SOURCE_TOKEN</code>. Use this exact source ID in each event. Maximum 256 events / 256 KiB per request. Collector provenance fields are reserved.</p><pre class=raw-message>[{{\"time_ms\": CURRENT_EPOCH_MS, \"source\": \"{}\",\n  \"subject\": \"service-user\", \"object\": \"resource\",\n  \"kind\": \"authentication\", \"outcome\": \"deny\", \"severity\": 3,\n  \"bytes\": 0, \"trace\": 0, \"idempotency_key\": \"unique-source-event-id\"}}]</pre><p>Acknowledgement means accepted into the RAM buffer. Rolling memory shows pending records and the durable archive. Resend with the same key after a connection failure.</p></section>",escape(id),escape(id)).unwrap();
    }
    if source.kind == "journal" {
        html.push_str("<section class='panel controls-panel'><h2>Journal adapter contract</h2><p>Reads a bounded batch every three seconds. On first connection: five-minute lookback. Afterward: resume at the retained journal cursor. Authentication classification requires trusted executable metadata. Generic records remain system observations.</p><p>Raw MESSAGE bodies are never archived. Host, program, PID, UID, classification and cursor accompany each compact event. An operator can retrieve the original message while journald still retains it.</p><p>Journal access is inherited from the service account. A collector error or stale poll marks readiness degraded. Records older than 24 hours are counted as skipped; this adapter is for live collection.</p></section>");
    }
}
pub fn cases(html: &mut String, s: &Snapshot, f: &Filters, csrf: &str) {
    heading(
        html,
        "INVESTIGATIONS / CASE MANAGEMENT",
        "Follow through.",
        "Assign ownership, retain evidence, document decisions and close the loop.",
        "<a class='button primary' href='#new-case'>＋ New investigation</a>",
    );
    write!(html,"<form method=get action=/cases class=filter-bar><input name=q aria-label='Search investigations' placeholder='Search title or owner' value='{}'><select name=kind aria-label='Investigation state'><option value=''>All states</option>",escape(&f.q)).unwrap();
    for state in CASE_STATES {
        write!(
            html,
            "<option value='{state}' {}>{}</option>",
            if f.kind == *state { "selected" } else { "" },
            state.replace('_', " ")
        )
        .unwrap();
    }
    html.push_str("</select><button class='button secondary'>Filter</button></form><section class='panel case-list'>");
    let search = f.q.to_lowercase();
    let mut count = 0;
    for case in s.cases.iter().filter(|c| {
        (f.kind.is_empty() || c.status == f.kind)
            && format!("{} {} {}", c.title, c.owner, c.id)
                .to_lowercase()
                .contains(&search)
    }) {
        count += 1;
        write!(html,"<a href='/case/{}' class=case-row><span class=rule-id>CASE {:04}</span><div><strong>{}</strong><small>{} · {} facts · updated {}</small></div>{}<span class=state-pill>{}</span><span>↗</span></a>",case.id,case.id,escape(&case.title),if case.owner.is_empty(){"Unassigned".into()}else{escape(&case.owner)},case.evidence.len(),age(case.updated_ms),badge(case.severity),case.status.replace('_'," ")).unwrap();
    }
    if count == 0 {
        html.push_str("<div class=empty>No investigations match. Detections open cases automatically; you can also create one and attach observed events.</div>");
    }
    write!(html,"</section><section class='panel controls-panel' id=new-case><div class=eyebrow>ANALYST INITIATED</div><h2>Open an investigation.</h2>{}<label>Title<input name=title required maxlength=160 placeholder='Describe what needs investigating'></label><label>Severity<select name=severity><option value=1>Informational</option><option value=2>Low</option><option value=3 selected>Medium</option><option value=4>High</option><option value=5>Critical</option></select></label><button class='button primary'>Create investigation →</button></form><p>256 retained cases maximum. Evidence survives rolling event retention. Export and explicitly remove closed cases when the budget fills.</p></section>",form(csrf,"/cases/action","create")).unwrap();
}
pub fn case(html: &mut String, s: &Snapshot, id: i64, csrf: &str) {
    let Some(c) = s.cases.iter().find(|c| c.id == id) else {
        heading(
            html,
            "INVESTIGATIONS",
            "Case not found.",
            "Choose a retained investigation.",
            "<a class=button href=/cases>Investigations</a>",
        );
        return;
    };
    heading(html,&format!("INVESTIGATION / CASE {id:04}"),&escape(&c.title),"Copied evidence and analyst decisions persist independently of the event ring.",&format!("<a class='button secondary' href=/cases>← Investigations</a><a class='button primary' href='/api/cases/{id}/export'>Export case ↓</a>"));
    write!(html,"<div class=control-columns><section class='panel controls-panel'><div class=section-heading><h2>Manage investigation</h2>{}</div>{}<input type=hidden name=id value='{id}'><input type=hidden name=version value='{}'><label>Assigned analyst<input name=owner maxlength=64 value='{}' placeholder='Analyst name'></label><label>Status<select name=status>",badge(c.severity),form(csrf,"/cases/action","update"),c.version,escape(&c.owner)).unwrap();
    for state in CASE_STATES {
        write!(
            html,
            "<option value='{state}' {}>{}</option>",
            if c.status == *state { "selected" } else { "" },
            state.replace('_', " ")
        )
        .unwrap();
    }
    html.push_str("</select></label><label>Severity<select name=severity>");
    for n in 1..=5 {
        write!(
            html,
            "<option value='{n}' {}>{}</option>",
            if c.severity == n { "selected" } else { "" },
            severity_label(n)
        )
        .unwrap();
    }
    html.push_str("</select></label><label>Decision note (optional)<textarea name=note maxlength=2000 rows=4 placeholder='Record your evidence, reasoning and next step'></textarea></label><button class='button primary'>Save investigation</button></form><p>Concurrent edits are checked against this case’s revision. A stale form cannot overwrite newer work.</p></section><section class='panel controls-panel'><div class=eyebrow>ANALYST NOTEBOOK</div><h2>Decision history</h2>");
    if c.notes.is_empty() {
        html.push_str("<p>No notes yet. Add the context behind your decision.</p>");
    }
    for note in &c.notes {
        write!(
            html,
            "<article class=case-note><small>{}</small><p>{}</p></article>",
            age(note.time_ms),
            escape(&note.text)
        )
        .unwrap();
    }
    if let Some(f) = c.finding_id {
        if s.findings.iter().any(|v| v.id == f) {
            write!(
                html,
                "<a class=text-link href='/incident/{f}'>Inspect originating detection ↗</a>"
            )
            .unwrap();
        }
    }
    html.push_str("</section></div><section class=panel><div class=panel-heading><div><h2>Preserved evidence</h2><p>Attach additional facts from an event’s detail page, including retained archive blocks.</p></div><a class=text-link href=/investigate>Find evidence ↗</a></div>");
    event_table(html, &c.evidence.iter().collect::<Vec<_>>());
    html.push_str("</section>");
    if !case_open(&c.status) {
        write!(html,"<details class='panel control-drawer'><summary>Remove a closed investigation</summary><p>This permanently removes this case, its notes, its associated review plan. The resolved detection stays in the bounded finding ledger. Download the case export first.</p>{}<input type=hidden name=id value='{id}'><input type=hidden name=version value='{}'><label class=checkbox-label><input type=checkbox name=exported value=yes required>I saved the case export and want to delete this closed case.</label><button class='button secondary'>Delete closed case</button></form></details>",form(csrf,"/cases/action","delete"),c.version).unwrap();
    }
}
pub fn event_controls(html: &mut String, s: &Snapshot, event: &DisplayEvent, csrf: &str) {
    if let Some(context) = &event.context {
        html.push_str("<section class='panel controls-panel'><div class=eyebrow>COLLECTOR PROVENANCE</div><h2>Where this fact came from.</h2><dl class=fact-grid>");
        for (key, value) in [
            ("Host", context.host.clone()),
            ("Program", context.program.clone()),
            (
                "PID",
                context
                    .pid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "Unknown".into()),
            ),
            (
                "UID",
                context
                    .uid
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "Unknown".into()),
            ),
            ("Classification", context.summary.clone()),
        ] {
            write!(html, "<div><dt>{key}</dt><dd>{}</dd></div>", escape(&value)).unwrap();
        }
        html.push_str("</dl>");
        if event.source_label == "endpoint" {
            write!(html,"<a class='button secondary' href='/endpoints/{}'>Open original device evidence ↗</a><p>Retained endpoint observations preserve their typed source reports.</p>",escape(&context.host)).unwrap();
        } else if !context.journal_cursor.is_empty() {
            write!(html,"<a class='button secondary' href='/event/{}/original{}'>Retrieve original journal message ↗</a><p>Available only while the OS journal retains the exact record. Loaded on demand, never copied into the SIEM archive.</p>",event.event.id,s.selected_archive.map(|b|format!("?block={b}")).unwrap_or_default()).unwrap();
        }
        html.push_str("</section>");
    }
    write!(html,"<section class='panel controls-panel'><h2>Attach to an investigation</h2>{}<input type=hidden name=event value='{}'>",form(csrf,"/cases/action","attach"),event.event.id).unwrap();
    if let Some(block) = s.selected_archive {
        write!(html, "<input type=hidden name=block value='{block}'>").unwrap();
    }
    html.push_str("<label>Investigation<select name=target required>");
    let mut options = 0;
    for c in s.cases.iter().filter(|c| {
        case_open(&c.status) && !c.evidence.iter().any(|e| e.event.id == event.event.id)
    }) {
        options += 1;
        write!(
            html,
            "<option value='{}:{}'>CASE {:04} · {}</option>",
            c.id,
            c.version,
            c.id,
            escape(&c.title)
        )
        .unwrap();
    }
    html.push_str("</select></label>");
    if options > 0 {
        html.push_str("<button class='button primary'>Preserve this event</button>");
    }
    html.push_str(
        "</form><a class=text-link href='/cases#new-case'>Open a new investigation ↗</a></section>",
    );
}
