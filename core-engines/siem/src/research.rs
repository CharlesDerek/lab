//! Preflight a proposed field deletion against declared detection contracts.
//! This never changes the persisted AEF1 schema or silently disables a rule.
use crate::model::RULES;

pub const FIELDS: [&str; 7] = [
    "bytes",
    "outcome",
    "time",
    "subject",
    "severity",
    "kind",
    "provenance",
];

pub fn unsupported_rules(omitted: &str) -> Result<Vec<&'static str>, &'static str> {
    if omitted.is_empty() {
        return Ok(Vec::new());
    }
    if !FIELDS.contains(&omitted) {
        return Err("Unknown projection field");
    }
    Ok(RULES
        .iter()
        .filter(|rule| rule.fields.split('·').any(|field| field.trim() == omitted))
        .map(|rule| rule.id)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn byte_removal_preserves_authentication_but_blocks_egress_detection() {
        assert_eq!(unsupported_rules("bytes").unwrap(), vec!["AX-003"]);
        assert!(!unsupported_rules("severity").unwrap().contains(&"AX-001"));
        assert_eq!(unsupported_rules("kind").unwrap().len(), 5);
        assert_eq!(unsupported_rules("outcome").unwrap().len(), 5);
        assert_eq!(unsupported_rules("provenance").unwrap(), vec!["AX-005"]);
        assert!(unsupported_rules("command-line").is_err());
    }
}
