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
    ) {
        println!("\nATHERNEX_AUTH_SOURCE={category}");
    }
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
