use std::env;

#[derive(Debug)]
struct OrchestratorConfig {
    kafka_bootstrap_servers: String,
    localstack_endpoint: String,
    paperclip_endpoint: String,
    max_in_flight: u32,
    retry_limit: u32,
}

impl OrchestratorConfig {
    fn from_env() -> Self {
        Self {
            kafka_bootstrap_servers: read_env("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092"),
            localstack_endpoint: read_env("LOCALSTACK_ENDPOINT", "http://127.0.0.1:4566"),
            paperclip_endpoint: read_env("PAPERCLIP_ENDPOINT", "http://127.0.0.1:8088"),
            max_in_flight: read_u32_env("AGENT_MAX_IN_FLIGHT", 8),
            retry_limit: read_u32_env("AGENT_RETRY_LIMIT", 3),
        }
    }
}

#[derive(Debug)]
enum WorkflowState {
    Received,
    Validated,
    Scheduled,
    Running,
    Reviewing,
    Accepted,
    Retrying,
    Quarantined,
    Deadlettered,
}

fn main() {
    let config = OrchestratorConfig::from_env();

    println!("orchestrator preparation mode");
    println!("kafka_bootstrap_servers={}", config.kafka_bootstrap_servers);
    println!("localstack_endpoint={}", config.localstack_endpoint);
    println!("paperclip_endpoint={}", config.paperclip_endpoint);
    println!("max_in_flight={}", config.max_in_flight);
    println!("retry_limit={}", config.retry_limit);
    println!("workflow_states={:?}", workflow_states());
}

fn workflow_states() -> [WorkflowState; 9] {
    [
        WorkflowState::Received,
        WorkflowState::Validated,
        WorkflowState::Scheduled,
        WorkflowState::Running,
        WorkflowState::Reviewing,
        WorkflowState::Accepted,
        WorkflowState::Retrying,
        WorkflowState::Quarantined,
        WorkflowState::Deadlettered,
    ]
}

fn read_env(key: &str, default: &str) -> String {
    env::var(key).unwrap_or_else(|_| default.to_string())
}

fn read_u32_env(key: &str, default: u32) -> u32 {
    env::var(key)
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(default)
}
