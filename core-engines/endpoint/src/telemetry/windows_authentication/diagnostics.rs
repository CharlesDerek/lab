//! Test-only diagnostics. Only fixed categories and native numeric codes leave
//! the private host; errors and source values are never copied into markers.
pub(super) fn source(category: &str) {
    if matches!(
        category,
        "connection_ready"
            | "worker_entered"
            | "durable_state_ready"
            | "initial_health_saved"
            | "reader_opened"
            | "log_opened"
            | "log_identity_ready"
            | "audit_policy_checked"
            | "channel_health_checked"
            | "baseline_query_ready"
            | "baseline_record_ready"
            | "baseline_identity_ready"
            | "baseline_bookmark_ready"
            | "baseline_committed"
            | "worker_ready"
            | "collector_started"
            | "startup_timeout"
            | "startup_disconnected"
            | "startup_failed"
            | "health_read_failed"
            | "health_missing"
            | "health_incomplete"
            | "worker_failed"
            | "invalid_property_type"
            | "invalid_native_identity"
            | "invalid_render_size"
            | "invalid_render_text"
            | "invalid_log_metadata"
            | "invalid_bookmark"
            | "empty_baseline"
            | "source_error_other"
            | "controlled_queue_empty"
            | "controlled_queue_partial"
            | "controlled_queue_extra"
            | "queue_wait_timeout"
            | "capture_health_timeout"
            | "health_has_rejections"
            | "health_has_loss"
            | "health_has_error"
            | "health_state_inactive"
            | "health_backpressure"
            | "health_not_caught_up"
            | "rejected_xml"
            | "rejected_provenance"
            | "rejected_missing_field"
            | "rejected_numeric_field"
            | "rejected_text_field"
            | "rejected_identity_mismatch"
            | "rejected_other"
            | "loss_policy_health_transition"
            | "loss_log_identity_changed"
            | "loss_bookmark_anchor_missing"
            | "loss_record_sequence"
            | "loss_eventlog_marker"
            | "loss_per_user_policy_marker"
            | "loss_system_policy_marker"
            | "loss_policy_scope_unknown"
            | "setup_barrier_timeout"
            | "setup_barrier_continuity"
            | "setup_barrier_scope_invalid"
            | "setup_barrier_subject_invalid"
            | "setup_barrier_changes_invalid"
            | "setup_barrier_delta_unexpected"
            | "setup_barrier_budget"
            | "setup_policy_provider_mismatch"
            | "setup_policy_version_missing"
            | "setup_policy_version_1"
            | "setup_policy_version_other"
            | "setup_policy_guid_invalid"
            | "setup_scope_guid"
            | "setup_scope_string"
            | "setup_scope_null"
            | "setup_scope_array"
            | "setup_scope_other"
    ) {
        println!("\nATHERNEX_AUTH_SOURCE={category}");
    }
}
pub(super) fn rejection(error: &dyn std::error::Error) {
    // Classification inspects the private error locally. Only a fixed category
    // is printed, never the error, field name, XML or source value.
    let text = error.to_string();
    let category = match text.as_str() {
        "Windows logon XML differs from its native System identity" => "rejected_identity_mismatch",
        "Unsupported Windows authentication provenance or version"
        | "Unsupported Windows logon type" => "rejected_provenance",
        "Missing Windows authentication field"
        | "Missing Windows XML field"
        | "Missing Windows XML attribute" => "rejected_missing_field",
        "Invalid Windows decimal field"
        | "Windows decimal field overflow"
        | "Invalid Windows hexadecimal field"
        | "Windows hexadecimal field overflow"
        | "Invalid Windows caller PID"
        | "Invalid Windows authentication status" => "rejected_numeric_field",
        "Invalid Windows event text field" => "rejected_text_field",
        _ if text.contains("XML") => "rejected_xml",
        _ => "rejected_other",
    };
    source(category);
}
pub(super) fn native(operation: &str, code: u32) {
    if matches!(
        operation,
        "source_api" | "source_next" | "source_seek" | "source_render_probe"
    ) {
        println!("\nATHERNEX_AUTH_DIAGNOSTIC={operation}:{code}");
    }
}
pub(super) fn render(
    stage: &str,
    flags: u32,
    succeeded: bool,
    used: u32,
    capacity: u32,
    count: u32,
) {
    if flags == 2 && matches!(stage, "bookmark_probe" | "bookmark_result") {
        println!(
            "\nATHERNEX_AUTH_RENDER={stage}:{flags}:{}:{used}:{capacity}:{count}",
            u32::from(succeeded)
        );
    }
}
pub(super) fn classify(error: &dyn std::error::Error) {
    let text = error.to_string();
    let category = match text.as_str() {
        "Unexpected Windows Security property type" | "Invalid Windows Security property index" => {
            "invalid_property_type"
        }
        "Invalid native Windows Security event identity" => "invalid_native_identity",
        "Invalid Windows Security property rendering size"
        | "Windows Security property count changed"
        | "Windows Security text exceeds its rendering budget"
        | "Invalid Windows Security rendered text size" => "invalid_render_size",
        "Invalid Windows Security text termination"
        | "Windows Security text exceeds its UTF-8 budget"
        | "Invalid Windows Security string pointer"
        | "Windows Security string exceeds its buffer"
        | "Windows Security property exceeds its text budget"
        | "Windows Security string is unterminated"
        | "Invalid Windows Security GUID pointer" => "invalid_render_text",
        "Windows Security log creation identity is unavailable"
        | "Windows Security log metadata has an unexpected type"
        | "Windows Security channel configuration has an unexpected type" => "invalid_log_metadata",
        "Invalid durable Windows Security bookmark" => "invalid_bookmark",
        "Windows Security log has no baseline record" => "empty_baseline",
        _ => "source_error_other",
    };
    source(category);
}
