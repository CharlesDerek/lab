//! Supported sudo syslog envelopes. Command text is opaque, never a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SudoOutcome {
    PasswordDenied { attempts: u32 },
    PolicyDenied,
    CommandAuthorized,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SudoReport<'a> {
    /// Invoking account reported by sudo, not the USER= target or an OS UID.
    pub claimed_user: &'a str,
    pub outcome: SudoOutcome,
}

/// Parse the default English sudoers envelope. Localized/custom messages,
/// continuations, truncation and unfamiliar field layouts remain unsupported.
pub fn sudo_report(message: &str) -> Option<SudoReport<'_>> {
    if !super::bounded(message, 4096) {
        return None;
    }
    let (user, rest) = message.trim_start_matches(' ').split_once(" : ")?;
    if user.is_empty() || user.len() > 256 || user.chars().any(|ch| ch.is_whitespace() || ch == ':')
    {
        return None;
    }
    let (reason, fields) = if rest.starts_with("TTY=") || rest.starts_with("PWD=") {
        ("", rest)
    } else {
        rest.split_once(" ; ")?
    };
    // COMMAND is last and can contain arbitrary arguments, including strings
    // that resemble fields or rejection reasons. Never parse its contents.
    let (fields, command) = fields
        .split_once(" ; COMMAND=")
        .map_or((fields, None), |(fields, command)| (fields, Some(command)));
    let mut fields = fields.split(" ; ").peekable();
    if fields.peek().is_some_and(|field| field.starts_with("TTY="))
        && fields.next()?.strip_prefix("TTY=")?.is_empty()
    {
        return None;
    }
    for key in ["PWD=", "USER="] {
        let value = fields.next()?.strip_prefix(key)?;
        if value.is_empty() {
            return None;
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    for field in fields {
        let (key, value) = field.split_once('=')?;
        if !["GROUP", "TSID", "ENV"].contains(&key) || value.is_empty() || !seen.insert(key) {
            return None;
        }
    }
    let outcome = if reason.is_empty() {
        command.filter(|command| !command.is_empty())?;
        SudoOutcome::CommandAuthorized
    } else if [
        "user NOT in sudoers",
        "user NOT authorized on host",
        "command not allowed",
    ]
    .contains(&reason)
    {
        SudoOutcome::PolicyDenied
    } else {
        let (count, suffix) = reason.split_once(' ')?;
        let attempts: u32 = count.parse().ok()?;
        if attempts == 0
            || attempts.to_string() != count
            || suffix
                != if attempts == 1 {
                    "incorrect password attempt"
                } else {
                    "incorrect password attempts"
                }
        {
            return None;
        }
        SudoOutcome::PasswordDenied { attempts }
    };
    Some(SudoReport {
        claimed_user: user,
        outcome,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const FIELDS: &str = "TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true";

    #[test]
    fn sudo_denial_counts_are_reports_not_target_identities_or_command_success() {
        for attempts in [1, 2, 3, u32::MAX] {
            let plural = if attempts == 1 { "" } else { "s" };
            let line =
                format!("  alice : {attempts} incorrect password attempt{plural} ; {FIELDS}");
            assert_eq!(
                sudo_report(&line),
                Some(SudoReport {
                    claimed_user: "alice",
                    outcome: SudoOutcome::PasswordDenied { attempts }
                })
            );
        }
        for reason in [
            "user NOT in sudoers",
            "user NOT authorized on host",
            "command not allowed",
        ] {
            assert_eq!(
                sudo_report(&format!("alice : {reason} ; {FIELDS}"))
                    .unwrap()
                    .outcome,
                SudoOutcome::PolicyDenied
            );
        }
    }

    #[test]
    fn command_arguments_cannot_change_a_sudo_decision() {
        for text in [
            "authentication failure",
            "user NOT in sudoers",
            "command not allowed",
            "not allowed to execute",
            "1 incorrect password attempt ; TTY=evil ; USER=other",
        ] {
            let line = format!(
                "alice : TTY=unknown ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/printf {text}"
            );
            assert_eq!(
                sudo_report(&line).unwrap().outcome,
                SudoOutcome::CommandAuthorized
            );
        }
        assert_eq!(
            sudo_report("alice : PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true")
                .unwrap()
                .outcome,
            SudoOutcome::CommandAuthorized
        );
        assert_eq!(sudo_report("alice : 1 incorrect password attempt ; PWD=/fixture ; USER=root ; COMMAND=/usr/bin/true").unwrap().outcome,
            SudoOutcome::PasswordDenied { attempts: 1 });
    }

    #[test]
    fn incomplete_ambiguous_or_custom_sudo_reports_are_not_guessed() {
        for reason in [
            "0 incorrect password attempts",
            "01 incorrect password attempt",
            "+1 incorrect password attempt",
            "1 incorrect password attempts",
            "2 incorrect password attempt",
            "4294967296 incorrect password attempts",
            "custom failure",
            "1 mot de passe incorrect",
        ] {
            assert!(sudo_report(&format!("alice : {reason} ; {FIELDS}")).is_none());
        }
        for line in [
            "alice : COMMAND=/usr/bin/true",
            "alice : TTY=unknown ; PWD=/ ; USER=root",
            "alice : TTY=unknown ; PWD=/ ; USER=root ; COMMAND=",
            "alice : TTY=unknown ; PWD=/ ; USER=root ; USER=other ; COMMAND=/bin/true",
            "alice : TTY=unknown ; PWD=/ ; USER=root ; OTHER=unknown ; COMMAND=/bin/true",
            "alice extra : 1 incorrect password attempt ; TTY=unknown ; PWD=/ ; USER=root",
            "alice : 1 incorrect password attempt ; TTY=unknown ; PWD=/",
            "alice : 1 incorrect password attempt ; TTY=unknown\n ; PWD=/ ; USER=root",
        ] {
            assert!(sudo_report(line).is_none(), "{line}");
        }
    }
}
