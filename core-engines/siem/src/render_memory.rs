use crate::{
    engine::Snapshot,
    render::{escape, heading, size},
};
use std::fmt::Write;
pub(crate) fn memory(html: &mut String, s: &Snapshot, csrf: &str) {
    let m = &s.memory;
    heading(html,"INVESTIGATIVE MEMORY","Connected evidence","New detections retrieve relevant historical facts. Every promoted event keeps its original timestamp.","<a class=button href=/api/memory>Export context</a>");
    write!(html,"<section class=panel><h2>Memory budgets</h2><p>{} hot events · {} hot bytes · {} durable references · {} graph relationships · {} preserved object bytes</p><form method=post action=/memory/configure><input type=hidden name=csrf value='{}'><label>Hot retention (hours)<input name=hot_hours type=number min=1 max=8760 value='{}'></label><label>Hot event limit<input name=hot_events type=number min=1 max=4096 value='{}'></label><label>Investigation event limit<input name=context_events type=number min=1 max=512 value='{}'></label><button class=button>Save budgets</button></form><p>Active investigation: {} events / {}. Context expires after {} minutes. Capacity can demote events before the time limit.</p></section>",m.hot_events,size(m.hot_bytes),m.references,m.graph_links,size(m.object_bytes),escape(csrf),m.config.hot_ms/3_600_000,m.config.hot_events,m.config.context_events,m.context.len(),size(m.context_bytes),m.config.context_ms/60_000).unwrap();
    html.push_str("<section class=panel><h2>Active investigation context</h2><table><thead><tr><th>Evidence</th><th>Original timestamp (ms)</th><th>Identity / endpoint</th><th>Relevance and relationship path</th><th>Verification / expiry (ms)</th></tr></thead><tbody>");
    for c in &m.context {
        let e = &c.evidence;
        let r = &c.relevance;
        write!(html,"<tr><td><a href='/event/{}'>Event {}</a><br>{}</td><td>{}</td><td>{}<br>{}</td><td>Score {} · trigger {}<br>Path {}<ul>",e.event.id,e.event.id,e.event.kind.label(),e.event.time_ms,escape(&e.subject_label),escape(e.context.as_ref().map(|c|c.host.as_str()).unwrap_or(&e.source_label)),r.score,r.trigger_id,escape(&r.path.iter().map(u64::to_string).collect::<Vec<_>>().join(" → "))).unwrap();
        for reason in &r.reasons {
            write!(html, "<li>{}</li>", escape(reason)).unwrap();
        }
        write!(
            html,
            "</ul></td><td>{}<br>{}</td></tr>",
            escape(&r.status),
            c.expires_ms
        )
        .unwrap();
    }
    html.push_str("</tbody></table></section><section class=panel><h2>Recent relevance decisions</h2><p>Unavailable evidence is never shown as verified.</p><ul>");
    for r in &m.recent_relevance {
        write!(
            html,
            "<li>Event {} · trigger {} · score {} · {}</li>",
            r.event_id,
            r.trigger_id,
            r.score,
            escape(&r.status)
        )
        .unwrap();
    }
    html.push_str("</ul><a href=/api/evidence-audit>Retrieval audit</a></section>");
}
