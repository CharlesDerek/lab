//! Portable validation for the Windows scanner's durable launch authority.
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Launch {
    Prepared {},
    Owned {
        pid: u32,
        created: u64,
        logon: String,
    },
}
impl Launch {
    pub(super) fn validate(&self) -> Result<(), &'static str> {
        if let Self::Owned {
            pid,
            created,
            logon,
        } = self
        {
            if *pid <= 4 || *created == 0 || !valid_logon(logon) {
                return Err("Invalid Windows scanner recovery owner");
            }
        }
        Ok(())
    }
}
fn valid_logon(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("S-1-5-5-") else {
        return false;
    };
    let parts: Vec<_> = rest.split('-').collect();
    parts.len() == 2
        && parts.iter().all(|s| {
            !s.is_empty()
                && s.len() <= 10
                && s.bytes().all(|b| b.is_ascii_digit())
                && s.parse::<u32>().is_ok()
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn only_complete_known_launch_states_decode() {
        for value in [
            json!({}),
            json!({"state":"unknown"}),
            json!({"state":"prepared", "pid":42}),
            json!({"state":"owned", "pid":42, "created":1}),
            json!({"state":"owned", "pid":42, "created":1, "logon":"S-1-5-5-1-2", "extra":true}),
        ] {
            assert!(serde_json::from_value::<Launch>(value).is_err());
        }
        for value in [
            json!({"state":"prepared"}),
            json!({"state":"owned", "pid":42, "created":1, "logon":"S-1-5-5-1-2"}),
        ] {
            let launch: Launch = serde_json::from_value(value.clone()).unwrap();
            launch.validate().unwrap();
            assert_eq!(serde_json::to_value(launch).unwrap(), value);
        }
    }

    #[test]
    fn recovery_authority_requires_a_full_process_and_logon_identity() {
        for (pid, created, logon) in [
            (0, 1, "S-1-5-5-1-2"),
            (4, 1, "S-1-5-5-1-2"),
            (42, 0, "S-1-5-5-1-2"),
            (42, 1, "S-1-5-19"),
            (42, 1, "S-1-5-5-4294967296-1"),
            (42, 1, "S-1-5-5-1-2-3"),
            (42, 1, "S-1-5-5--1"),
            (42, 1, "S-1-5-5-1-+2"),
        ] {
            let launch = Launch::Owned {
                pid,
                created,
                logon: logon.into(),
            };
            assert!(launch.validate().is_err());
        }
    }
}
