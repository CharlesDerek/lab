use crate::{
    engine::Snapshot,
    gateway::*,
    render::{button, escape, event_table, heading, size, time},
};
use std::fmt::Write;
fn state(value: &str) -> String {
    format!(
        "<span class='state-pill {}'><i></i>{}</span>",
        if ["active", "allowed"].contains(&value) {
            "good"
        } else if ["quarantined", "denied", "revoked"].contains(&value) {
            "bad"
        } else {
            "quiet"
        },
        escape(value)
    )
}
fn start_form(csrf: &str, op: &str, id: i64) -> String {
    format!("<form method=post action=/hive/action class=control-form><input type=hidden name=csrf value='{}'><input type=hidden name=op value='{op}'><input type=hidden name=id value='{id}'>",escape(csrf))
}
fn action(csrf: &str, op: &str, id: i64, label: &str, class: &str) -> String {
    format!(
        "{}<button class='button {class}'>{}</button></form>",
        start_form(csrf, op, id),
        escape(label)
    )
}
fn metrics(html: &mut String, items: &[(&str, String, &str)]) {
    html.push_str("<div class=metrics>");
    for (label, value, note) in items {
        write!(html,"<article class=metric><div>{label}<span class=metric-symbol>◇</span></div><strong>{value}</strong><small>{note}</small></article>").unwrap();
    }
    html.push_str("</div>");
}
fn decisions(html: &mut String, s: &Snapshot, agent: Option<i64>, task: Option<i64>) {
    write!(html,"<section class='panel decision-panel'><div class=panel-heading><div><h2>Access decision trail</h2><p>Identity → task → capability → resource. Every boundary is inspectable.</p></div><span class=inline-label>{}</span></div><div class=decision-list>",if s.retention.persistent {"DURABLE / IMMEDIATE"} else {"MEMORY-ONLY SESSION"}).unwrap();
    let rows: Vec<_> = s
        .hive
        .decisions
        .iter()
        .filter(|d| {
            agent.is_none_or(|a| d.agent_id == Some(a)) && task.is_none_or(|t| d.task_id == Some(t))
        })
        .take(12)
        .collect();
    if rows.is_empty() {
        html.push_str("<div class=empty>No access requests yet. Issue a scoped task grant to connect an agent.</div>");
    }
    for d in rows {
        write!(html,"<details class=decision><summary><span class='decision-glyph {}'>{}</span><div><strong>{}:<b>{}</b></strong><small>{}</small></div><span class=decision-identity>{}</span>{}<time>{}</time><span class=chevron>⌄</span></summary><div class=decision-detail><dl><dt>Decision</dt><dd>#{}</dd><dt>Grant</dt><dd>{}</dd><dt>Task</dt><dd>{}</dd><dt>Policy result</dt><dd><code>{}</code></dd></dl><p>Authorization checks identity state, grant revocation, task state, both deadlines, exact scope and the remaining use budget.</p>{}</div></details>",if d.allowed{"good"}else{"bad"},if d.allowed{"↗"}else{"⊘"},escape(&d.action),escape(&d.resource),escape(&d.reason.replace('_'," ")),d.agent_id.map(|id|format!("<a href='/agent/{id}'>agent-{id} ↗</a>")).unwrap_or_else(||"unrecognized".into()),state(if d.allowed{"allowed"}else{"denied"}),time(d.time_ms),d.id,d.grant_id.map(|v|format!("G-{v:04}")).unwrap_or_else(||"none".into()),d.task_id.map(|v|format!("<a href='/task/{v}'>T-{v:04} ↗</a>")).unwrap_or_else(||"none".into()),escape(&d.reason),d.agent_id.map(|v|format!("<a class=text-link href='/investigate?q=agent-{v}'>Follow the normalized SIEM events ↗</a>")).unwrap_or_default()).unwrap();
    }
    html.push_str("</div></section>");
}
pub fn hive(html: &mut String, s: &Snapshot, csrf: &str) {
    heading(
        html,
        "AGENT AUTHORITY / 05",
        "Intelligence, with boundaries.",
        "A hive of identities. Task-sized access. One security control plane.",
        "<a href='#register' class='button primary'>＋ Register identity</a>",
    );
    metrics(
        html,
        &[
            (
                "Registered identities",
                s.hive.agents.len().to_string(),
                "Operator-owned · 32-identity ceiling",
            ),
            (
                "Active task grants",
                s.hive
                    .grants
                    .iter()
                    .filter(|g| g.state == "active")
                    .count()
                    .to_string(),
                "Scoped to one task and one resource",
            ),
            (
                "Denied requests",
                s.hive
                    .decisions
                    .iter()
                    .filter(|d| !d.allowed)
                    .count()
                    .to_string(),
                "In the latest 100 decisions",
            ),
            (
                "Quarantined",
                s.hive
                    .agents
                    .iter()
                    .filter(|a| a.state == "quarantined")
                    .count()
                    .to_string(),
                "Three denials / 60s → revoke all grants",
            ),
        ],
    );
    html.push_str("<div class=hive-layout><section class='panel hive-map'><div class=panel-heading><div><h2>The authority fabric</h2><p>Click an identity to follow its work and access.</p></div><span class=live-label><i></i> POLICY ENFORCED</span></div><div class=fabric><div class=fabric-orbit></div><div class=fabric-orbit-inner></div><div class=fabric-core><span>Λ</span><strong>ATHERNEX</strong><small>SIEM + AUTHORITY</small><b>Task-bound trust</b></div><div class=fabric-agents>");
    for (n, a) in s.hive.agents.iter().take(4).enumerate() {
        write!(html,"<a href='/agent/{}' class='fabric-agent node-{} {}'><span class=agent-symbol>{}</span><div><strong>{}</strong><small>{}</small></div>{}</a>",a.id,n+1,if a.state=="quarantined"{"quarantined"}else{""},["◎","◇","▤","✧"][n],escape(&a.name),escape(&a.role),state(&a.state)).unwrap();
    }
    if s.hive.agents.is_empty() {
        html.push_str("<p class=empty>Register an identity to begin.</p>");
    }
    html.push_str("</div><div class=fabric-caption><span>Identity</span><i>→</i><span>Task</span><i>→</i><span>Expiring grant</span><i>→</i><span>Resource</span></div></div></section><aside class='panel authority-panel'><div class=eyebrow>THE CAPABILITY CONTRACT</div><h2>Access ends<br>when the work does.</h2><p>Every token is a small, revocable permission. The model never decides its own authority.</p><ol class=contract-steps><li><span>01</span><div><strong>Bind the purpose</strong><small>One owner, task and exact resource.</small></div></li><li><span>02</span><div><strong>Constrain the window</strong><small>Task deadline ∩ grant lifetime.</small></div></li><li><span>03</span><div><strong>Meter every operation</strong><small>Use budget and a durable decision.</small></div></li><li><span>04</span><div><strong>Close the boundary</strong><small>Complete, revoke, expire or quarantine.</small></div></li></ol><div class=authority-note>256-bit opaque tokens<br><b>Issued grants store SHA-256 digests.</b></div></aside></div>");
    decisions(html, s, None, None);
    html.push_str("<section class='panel roster-panel'><div class=panel-heading><div><h2>Identity roster</h2><p>Agent identities describe workers; this lab does not launch autonomous processes.</p></div></div><div class=roster>");
    for a in &s.hive.agents {
        write!(html,"<a href='/agent/{}'><span class=agent-symbol>◈</span><div><strong>{}</strong><small>{}</small></div>{}<span>↗</span></a>",a.id,escape(&a.name),escape(&a.role),state(&a.state)).unwrap();
    }
    write!(html,"</div><details class=control-drawer id=register><summary>＋ Register an agent identity</summary>{}<label>Name<input name=name required maxlength=48 placeholder=analyst-05 pattern='[A-Za-z0-9-]+'></label><label>Role<input name=role required maxlength=96 placeholder='Evidence analyst'></label><button class='button primary'>Register identity</button></form></details></section>",start_form(csrf,"register",0)).unwrap();
}
pub fn agent(html: &mut String, s: &Snapshot, id: i64, csrf: &str) {
    let Some(a) = s.hive.agents.iter().find(|a| a.id == id) else {
        heading(
            html,
            "HIVE",
            "Identity not found.",
            "Select a registered identity.",
            "<a href=/hive>Back to hive</a>",
        );
        return;
    };
    heading(
        html,
        "AGENT HIVE / IDENTITY",
        &escape(&a.name),
        &escape(&a.role),
        &format!(
            "<a class='button secondary' href=/hive>← Agent hive</a>{}",
            action(
                csrf,
                if a.state == "active" {
                    "quarantine"
                } else {
                    "restore"
                },
                id,
                if a.state == "active" {
                    "Quarantine identity"
                } else {
                    "Restore identity"
                },
                "secondary"
            )
        ),
    );
    write!(html,"<section class='panel identity-banner'><div class=identity-avatar>◈</div><div><div class=eyebrow>IDENTITY A-{id:04}</div><h2>Purpose before permission.</h2><p>Tokens never grant access to the operator console. Restoring an identity does not revive its revoked grants.</p></div>{}</section>",state(&a.state)).unwrap();
    html.push_str("<div class=task-grid>");
    for t in s.hive.tasks.iter().filter(|t| t.agent_id == id) {
        write!(html,"<a href='/task/{}' class='panel task-card'><div><code>T-{:04}</code>{}</div><h3>{}</h3><p>{}:{}</p><footer><span>Deadline {} UTC</span><b>Inspect task ↗</b></footer></a>",t.id,t.id,state(&t.state),escape(&t.title),escape(&t.action),escape(&t.resource),time(t.expires_ms)).unwrap();
    }
    html.push_str("</div>");
    decisions(html, s, Some(id), None);
    html.push_str("<div class=control-columns><section class='panel controls-panel'><div class=panel-heading><div><h2>Assign a scoped task</h2><p>The scope is fixed at creation. New purpose, new task.</p></div></div>");
    write!(html,"{}<label>Task title<input name=title required maxlength=120 placeholder='Investigate an evidence chain'></label><label>Resource<select name=resource>",start_form(csrf,"task",id)).unwrap();
    for (res, act, _) in RESOURCES {
        write!(html, "<option value='{res}'>{act}:{res}</option>").unwrap();
    }
    for finding in &s.findings {
        write!(
            html,
            "<option value='finding-{}'>read:finding-{} · {}</option>",
            finding.id,
            finding.id,
            escape(&finding.title)
        )
        .unwrap();
    }
    html.push_str("</select></label><label>Deadline in minutes<input name=minutes type=number min=1 max=1440 value=30 required></label><button class='button primary'>Create task →</button></form></section>");
    if s.demo {
        html.push_str("<section class='panel controls-panel'><div class=eyebrow>CONTROLLED EXERCISE</div><h2>Test the boundary.</h2><p>Creates a synthetic task and verifies automatic quarantine after three out-of-scope reads.</p>");
        write!(
            html,
            "{}</section>",
            action(csrf, "exercise", id, "Run boundary exercise", "secondary")
        )
        .unwrap();
    } else {
        html.push_str("<section class='panel controls-panel'><div class=eyebrow>LIVE GATEWAY</div><h2>Connect a worker.</h2><p>Create a scoped task, issue its token, and call the task’s gateway endpoint. Access expires at the earlier of the token or task deadline. Completion and quarantine revoke active grants immediately.</p><p>The gateway enforces its own evidence and note resources. It does not sandbox arbitrary host processes or filesystem access.</p></section>");
    }
    html.push_str("</div>");
}
pub fn task(html: &mut String, s: &Snapshot, id: i64, csrf: &str) {
    let Some(t) = s.hive.tasks.iter().find(|t| t.id == id) else {
        heading(
            html,
            "AGENT HIVE",
            "Task not found.",
            "Select an existing task.",
            "<a href=/hive>Back to hive</a>",
        );
        return;
    };
    heading(
        html,
        &format!("AGENT HIVE / TASK T-{id:04}"),
        &escape(&t.title),
        "A capability inherits its task’s scope and cannot outlive its deadline.",
        &format!(
            "<a class='button secondary' href='/agent/{}'>← Identity</a>{}",
            t.agent_id,
            if t.state == "active" {
                action(csrf, "complete", id, "Complete & revoke", "secondary")
            } else {
                String::new()
            }
        ),
    );
    write!(html,"<section class='panel scope-panel'><div><div class=eyebrow>AUTHORIZED SCOPE</div><code><span>{}</span>:{}</code><p>Gateway audience: athernex-local / exact match</p></div><div><div class=eyebrow>OWNER</div><a href='/agent/{}'>agent-{} ↗</a><p>Task deadline {} UTC</p></div>{}</section>",escape(&t.action),escape(&t.resource),t.agent_id,t.agent_id,time(t.expires_ms),state(&t.state)).unwrap();
    html.push_str("<section class='panel grant-panel'><div class=panel-heading><div><h2>Capability leases</h2><p>Plaintext credentials appear once at issuance. There is no reveal-again endpoint.</p></div></div><div class=grant-list>");
    for g in s.hive.grants.iter().filter(|g| g.task_id == id) {
        write!(html,"<div class=grant-row><code>G-{:04}</code><div><strong>{} / {} uses</strong><small>Expires {} UTC</small></div><meter min=0 max='{}' value='{}' aria-label='Grant use budget'></meter>{}{}</div>",g.id,g.uses,g.max_uses,time(g.expires_ms),g.max_uses,g.uses,state(&g.state),if g.state=="active"{action(csrf,"revoke",g.id,"Revoke","secondary small")}else{String::new()}).unwrap();
    }
    write!(html,"</div><details class=control-drawer open><summary>Issue a task-bound token</summary>{}<label>Lifetime in seconds<input name=seconds type=number min=1 max=3600 value=300 required></label><label>Maximum operations<input name=uses type=number min=1 max=1000 value=10 required></label><button class='button primary'>Issue token →</button><p>Effective expiry is the earlier of this lifetime and the task deadline. Completed, expired or quarantined work cannot receive a token.</p></form></details></section>",start_form(csrf,"grant",id)).unwrap();
    decisions(html, s, None, Some(id));
}
pub fn retention(html: &mut String, s: &Snapshot, csrf: &str) {
    let r = &s.retention;
    heading(
        html,
        "STORAGE CONTROL / 06",
        "A rolling memory.",
        "Keep the signal close. Compress the past. Give history a fixed budget.",
        &button(
            csrf,
            "flush",
            "",
            "Flush to archive",
            "button primary",
            "/retention",
        ),
    );
    metrics(
        html,
        &[
            (
                "Hot event payload",
                size(r.hot_bytes),
                "Time and capacity bounded query window",
            ),
            (
                "Awaiting flush",
                r.pending_events.to_string(),
                "Archive pending · evidence already committed",
            ),
            (
                "Compressed history",
                size(r.archive_bytes),
                "AXR2 blocks with labels, provenance and replay metadata",
            ),
            (
                "Rotated observations",
                r.rotated_events.to_string(),
                "Oldest blocks yield to time or capacity",
            ),
        ],
    );
    write!(html,"<div class=memory-layout><section class='panel memory-map'><div class=panel-heading><div><h2>The lifecycle of a signal</h2><p>General infrastructure and agent activity share the same pipeline.</p></div><span class=inline-label>{}</span></div><div class=memory-flow><div class='memory-stage ram'><span class=memory-icon>⌁</span><div class=eyebrow>01 / HOT RAM</div><h3>Observe & correlate</h3><strong>{}</strong><p>AEF1 facts<br>Bounded query window</p></div><div class=flow-arrow><span>→</span><small>{}s flush<br>or 512 events</small></div><div class='memory-stage archive'><span class=memory-icon>▤</span><div class=eyebrow>02 / COMPRESSED</div><h3>Preserve & investigate</h3><strong>{}</strong><p>AXR2 + DEFLATE<br>Self-contained dictionaries</p></div><div class=flow-arrow><span>→</span><small>oldest first<br>time ∪ size</small></div><div class='memory-stage rotate'><span class=memory-icon>↻</span><div class=eyebrow>03 / ROTATE</div><h3>Make room</h3><strong>{}</strong><p>Archive blocks rotate<br>Evidence references remain</p></div></div><div class=durability-strip><span>◆</span><div><strong>Evidence and permissions commit together.</strong><p>Normalized evidence, source checkpoints, grant issuance and access decisions commit immediately. The archive flush is a separate storage optimization.</p></div></div></section><section class='panel allocation-panel'><div class=eyebrow>ARCHIVE ALLOCATION</div><div class=allocation-number>{}<small>of {} payload capacity</small></div><meter min=0 max='{}' value='{}' aria-label='Archive allocation used'></meter><dl><dt>Time horizon</dt><dd>{}</dd><dt>Stored observations</dt><dd>{}</dd><dt>Last flush</dt><dd>{}</dd><dt>SQLite pages</dt><dd>{}</dd><dt>WAL right now</dt><dd>{}</dd></dl><p>Archive quota counts compressed blobs. SQLite pages, indexes and the bounded security ledger are additional overhead; the main database has a separate 16 MiB ceiling.</p></section></div>",if r.persistent{"DISK ENABLED"}else{"MEMORY-ONLY RUN"},s.events.len(),r.flush_seconds,r.archived_events,if r.days==0{"Size only".into()}else{format!("{} days",r.days)},size(r.archive_bytes),size(r.cap_bytes),r.cap_bytes,r.archive_bytes,if r.days==0{"Size only".into()}else{format!("{} days maximum",r.days)},r.archived_events,if r.last_flush_ms==0{"Not yet".into()}else{format!("{} UTC",time(r.last_flush_ms))},size(s.database_bytes),size(s.wal_bytes)).unwrap();
    write!(html,"<section class='panel retention-controls'><div><div class=eyebrow>YOUR HISTORY BUDGET</div><h2>Set the horizon.</h2><p>Whichever limit arrives first wins. Lowering capacity rotates oldest blocks immediately. Time is measured from observation; the RAM query window is smaller than the archive.</p></div><form method=post action=/retention/configure class=control-form><input type=hidden name=csrf value='{}'><label>Maximum days <small>0 = size only</small><input name=days type=number min=0 max=365 value='{}' required></label><label>Archive capacity · KiB<input name=cap_kib type=number min=64 max=8192 value='{}' required></label><label>Flush interval · seconds<input name=seconds type=number min=1 max=60 value='{}' required></label><button class='button primary'>Apply retention policy</button></form></section>",escape(csrf),r.days,r.cap_bytes/1024,r.flush_seconds).unwrap();
    html.push_str("<section class='panel block-panel'><div class=panel-heading><div><h2>Archive reels</h2><p>Latest 48 blocks · click to decompress and investigate one bounded block.</p></div><span class=inline-label>CHECKSUM VERIFIED ON READ</span></div><div class=block-grid>");
    for b in &r.blocks {
        write!(html,"<a href='/archive/{}' class=archive-block><div><span>ARCHIVE / {:04}</span><b>↗</b></div><div class=reel-bars aria-hidden=true><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i><i></i></div><strong>{} events</strong><p>{} → {} UTC</p><footer><b>{}</b><span>{} before compression</span></footer></a>",b.id,b.id,b.events,time(b.first_ms),time(b.last_ms),size(b.compressed_bytes),size(b.decoded_bytes)).unwrap();
    }
    if r.blocks.is_empty() {
        html.push_str("<div class=empty>No archived blocks yet. Flush the hot buffer to create the first reel.</div>");
    }
    html.push_str("</div></section>");
}
pub fn archive(html: &mut String, s: &Snapshot, id: i64) {
    heading(html,&format!("ROLLING MEMORY / ARCHIVE BLOCK {id:04}"),"A moment, preserved.","Decoded on demand from a checksum-verified block. Normalized facts, labels and original event IDs survive together.","<a class='button secondary' href=/retention>← Rolling memory</a>");
    let mut table = String::new();
    event_table(&mut table, &s.events.iter().rev().collect::<Vec<_>>());
    html.push_str(&table.replace("href='/event/", &format!("href='/archive/{id}/event/")));
}
