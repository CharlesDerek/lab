//! Single-operator local authentication. Agent capabilities never pass this gate.
use crate::{
    engine::LabResult,
    gateway::{digest, same_secret, secret},
    model::now_ms,
};
use axum::http::HeaderMap;
use std::sync::Mutex;
struct Session {
    hash: String,
    expires: u64,
}
pub struct OperatorAuth {
    key: String,
    sessions: Mutex<Vec<Session>>,
}
impl OperatorAuth {
    pub fn new(key: &str) -> LabResult<Self> {
        if key.len() < 24 {
            return Err("Operator key must contain at least 24 characters".into());
        }
        Ok(Self {
            key: digest(key),
            sessions: Mutex::new(Vec::new()),
        })
    }
    pub fn login(&self, key: &str) -> LabResult<String> {
        if !same_secret(&digest(key), &self.key) {
            return Err("Operator key rejected".into());
        }
        let token = secret()?;
        let mut sessions = self.sessions.lock().map_err(|_| "Sessions unavailable")?;
        sessions.retain(|s| s.expires > now_ms());
        if sessions.len() >= 16 {
            sessions.remove(0);
        }
        sessions.push(Session {
            hash: digest(&token),
            expires: now_ms() + 3_600_000,
        });
        Ok(token)
    }
    pub fn authorized(&self, headers: &HeaderMap) -> bool {
        if let Some(value) = headers
            .get("authorization")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.strip_prefix("Bearer "))
        {
            return same_secret(&digest(value), &self.key);
        }
        let Some(token) = cookie(headers) else {
            return false;
        };
        let Ok(sessions) = self.sessions.lock() else {
            return false;
        };
        sessions
            .iter()
            .any(|s| s.expires > now_ms() && same_secret(&digest(token), &s.hash))
    }
    pub fn logout(&self, headers: &HeaderMap) {
        if let (Some(token), Ok(mut sessions)) = (cookie(headers), self.sessions.lock()) {
            let hash = digest(token);
            sessions.retain(|s| s.hash != hash);
        }
    }
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .map(str::trim)
        .find_map(|v| v.strip_prefix("athernex_operator="))
}
pub fn login_page(error: &str) -> String {
    format!("<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'><link rel=stylesheet href=/assets/app.css><title>Operator access · Athernex</title><main class=login-shell><div class=login-orbit aria-hidden=true>Λ</div><div class=eyebrow>ATHERNEX / OPERATOR ACCESS</div><h1>Enter the control plane.</h1><p>Your agents have capabilities.<br>You hold the authority.</p><form method=post action=/login><label for=key>Operator key</label><input id=key name=key type=password minlength=24 required autocomplete=current-password autofocus placeholder='Your private operator key'><button class='button primary' type=submit>Unlock console →</button></form><p class=login-error>{}</p><small>Local control plane · 1-hour session · Rust authority boundary</small></main>",crate::render::escape(error))
}
