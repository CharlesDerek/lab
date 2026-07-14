use std::env;

#[derive(Debug)]
struct OrchestratorConfig {
    project_name: String,
    control_plane_role: String,
    scheduler_mode: String,
    local_capacity_slots: u32,
    remote_wake_threshold_slots: u32,
    idle_powerdown_after_seconds: u32,
    kafka_bootstrap_servers: String,
    localstack_endpoint: String,
    paperclip_endpoint: String,
    max_in_flight: u32,
    retry_limit: u32,
}

impl OrchestratorConfig {
    fn from_env() -> Self {
        Self {
            project_name: read_env("ATHERNEX_PROJECT_NAME", "Project Athernex"),
            control_plane_role: read_env("ATHERNEX_CONTROL_PLANE_ROLE", "local-control-plane"),
            scheduler_mode: read_env("ATHERNEX_SCHEDULER_MODE", "contract-only"),
            local_capacity_slots: read_u32_env("ATHERNEX_LOCAL_CAPACITY_SLOTS", 2),
            remote_wake_threshold_slots: read_u32_env("ATHERNEX_REMOTE_WAKE_THRESHOLD_SLOTS", 3),
            idle_powerdown_after_seconds: read_u32_env(
                "ATHERNEX_IDLE_POWERDOWN_AFTER_SECONDS",
                900,
            ),
            kafka_bootstrap_servers: read_env("KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092"),
            localstack_endpoint: read_env("LOCALSTACK_ENDPOINT", "http://127.0.0.1:4566"),
            paperclip_endpoint: read_env("PAPERCLIP_ENDPOINT", "http://127.0.0.1:3100"),
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

#[derive(Debug)]
struct JobRequest {
    run_id: &'static str,
    required_slots: u32,
    priority: JobPriority,
    allows_remote_capacity: bool,
}

#[derive(Debug)]
enum JobPriority {
    Interactive,
    Batch,
    Maintenance,
}

#[derive(Debug)]
struct CapacitySnapshot {
    local_available_slots: u32,
    remote_online_slots: u32,
    remote_powering_slots: u32,
    idle_seconds: u32,
}

#[derive(Debug)]
enum SchedulingDecision {
    RunHere {
        run_id: &'static str,
        slots: u32,
    },
    DispatchRemote {
        run_id: &'static str,
        slots: u32,
    },
    RequestPowerOn {
        run_id: &'static str,
        target_group: &'static str,
        slots: u32,
    },
    Hold {
        run_id: &'static str,
        reason: &'static str,
    },
    RequestPowerOff {
        target_group: &'static str,
        idle_seconds: u32,
    },
}

fn main() {
    let config = OrchestratorConfig::from_env();

    println!("athernex orchestrator preparation mode");
    println!("project_name={}", config.project_name);
    println!("control_plane_role={}", config.control_plane_role);
    println!("scheduler_mode={}", config.scheduler_mode);
    println!("local_capacity_slots={}", config.local_capacity_slots);
    println!(
        "remote_wake_threshold_slots={}",
        config.remote_wake_threshold_slots
    );
    println!(
        "idle_powerdown_after_seconds={}",
        config.idle_powerdown_after_seconds
    );
    println!("kafka_bootstrap_servers={}", config.kafka_bootstrap_servers);
    println!("localstack_endpoint={}", config.localstack_endpoint);
    println!("paperclip_endpoint={}", config.paperclip_endpoint);
    println!("max_in_flight={}", config.max_in_flight);
    println!("retry_limit={}", config.retry_limit);
    println!("workflow_states={:?}", workflow_states());
    println!("kafka_topics={:?}", kafka_topics());
    for decision in sample_scheduling_decisions(&config) {
        println!(
            "sample_scheduling_decision={}",
            describe_decision(&decision)
        );
    }

    if let Some(decision) = decide_idle_action(
        &CapacitySnapshot {
            local_available_slots: config.local_capacity_slots,
            remote_online_slots: 4,
            remote_powering_slots: 0,
            idle_seconds: config.idle_powerdown_after_seconds + 1,
        },
        &config,
    ) {
        println!("sample_idle_decision={}", describe_decision(&decision));
    }
}

fn sample_scheduling_decisions(config: &OrchestratorConfig) -> [SchedulingDecision; 3] {
    [
        decide_capacity_action(
            &JobRequest {
                run_id: "interactive-local-001",
                required_slots: 1,
                priority: JobPriority::Interactive,
                allows_remote_capacity: false,
            },
            &CapacitySnapshot {
                local_available_slots: config.local_capacity_slots,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config,
        ),
        decide_capacity_action(
            &JobRequest {
                run_id: "batch-remote-001",
                required_slots: 4,
                priority: JobPriority::Batch,
                allows_remote_capacity: true,
            },
            &CapacitySnapshot {
                local_available_slots: config.local_capacity_slots,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config,
        ),
        decide_capacity_action(
            &JobRequest {
                run_id: "maintenance-001",
                required_slots: 1,
                priority: JobPriority::Maintenance,
                allows_remote_capacity: false,
            },
            &CapacitySnapshot {
                local_available_slots: config.local_capacity_slots,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config,
        ),
    ]
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

fn kafka_topics() -> [&'static str; 10] {
    [
        "agent.commands",
        "agent.observations",
        "agent.results",
        "agent.review",
        "agent.deadletter",
        "scheduler.capacity",
        "power.commands",
        "power.observations",
        "security.findings",
        "agent.audit",
    ]
}

fn decide_capacity_action(
    job: &JobRequest,
    capacity: &CapacitySnapshot,
    config: &OrchestratorConfig,
) -> SchedulingDecision {
    match job.priority {
        JobPriority::Interactive if job.required_slots <= capacity.local_available_slots => {
            return SchedulingDecision::RunHere {
                run_id: job.run_id,
                slots: job.required_slots,
            };
        }
        JobPriority::Maintenance => {
            return SchedulingDecision::Hold {
                run_id: job.run_id,
                reason: "maintenance jobs require an explicit promotion window",
            };
        }
        _ => {}
    }

    if job.required_slots <= capacity.local_available_slots {
        return SchedulingDecision::RunHere {
            run_id: job.run_id,
            slots: job.required_slots,
        };
    }

    if !job.allows_remote_capacity {
        return SchedulingDecision::Hold {
            run_id: job.run_id,
            reason: "job does not allow remote worker capacity",
        };
    }

    if job.required_slots <= capacity.remote_online_slots {
        return SchedulingDecision::DispatchRemote {
            run_id: job.run_id,
            slots: job.required_slots,
        };
    }

    if capacity.remote_powering_slots > 0 {
        return SchedulingDecision::Hold {
            run_id: job.run_id,
            reason: "remote worker group is already powering on",
        };
    }

    if job.required_slots >= config.remote_wake_threshold_slots {
        return SchedulingDecision::RequestPowerOn {
            run_id: job.run_id,
            target_group: "worker-group-a",
            slots: job.required_slots,
        };
    }

    SchedulingDecision::Hold {
        run_id: job.run_id,
        reason: "below remote wake threshold",
    }
}

fn decide_idle_action(
    capacity: &CapacitySnapshot,
    config: &OrchestratorConfig,
) -> Option<SchedulingDecision> {
    if capacity.remote_online_slots > 0
        && capacity.idle_seconds >= config.idle_powerdown_after_seconds
    {
        return Some(SchedulingDecision::RequestPowerOff {
            target_group: "worker-group-a",
            idle_seconds: capacity.idle_seconds,
        });
    }

    None
}

fn describe_decision(decision: &SchedulingDecision) -> String {
    match decision {
        SchedulingDecision::RunHere { run_id, slots } => {
            format!("run_here run_id={run_id} slots={slots}")
        }
        SchedulingDecision::DispatchRemote { run_id, slots } => {
            format!("dispatch_remote run_id={run_id} slots={slots}")
        }
        SchedulingDecision::RequestPowerOn {
            run_id,
            target_group,
            slots,
        } => format!("request_power_on run_id={run_id} target_group={target_group} slots={slots}"),
        SchedulingDecision::Hold { run_id, reason } => {
            format!("hold run_id={run_id} reason={reason}")
        }
        SchedulingDecision::RequestPowerOff {
            target_group,
            idle_seconds,
        } => format!("request_power_off target_group={target_group} idle_seconds={idle_seconds}"),
    }
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
