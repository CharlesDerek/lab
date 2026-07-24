use std::env;
use std::fmt;
use std::str;
use std::time::{Duration, Instant};

use rdkafka::config::ClientConfig;
use rdkafka::consumer::{BaseConsumer, Consumer};
use rdkafka::error::KafkaError;
use rdkafka::message::{Header, Headers, Message, OwnedHeaders};
use rdkafka::producer::{BaseProducer, BaseRecord, Producer};

const DEFAULT_MAX_DELIVERY_ATTEMPTS: u32 = 3;

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

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KafkaTopic {
    AgentCommands,
    AgentObservations,
    AgentResults,
    AgentReview,
    AgentDeadletter,
    SchedulerCapacity,
    PowerCommands,
    PowerObservations,
    SecurityFindings,
    AgentAudit,
}

impl KafkaTopic {
    fn as_str(self) -> &'static str {
        match self {
            KafkaTopic::AgentCommands => "agent.commands",
            KafkaTopic::AgentObservations => "agent.observations",
            KafkaTopic::AgentResults => "agent.results",
            KafkaTopic::AgentReview => "agent.review",
            KafkaTopic::AgentDeadletter => "agent.deadletter",
            KafkaTopic::SchedulerCapacity => "scheduler.capacity",
            KafkaTopic::PowerCommands => "power.commands",
            KafkaTopic::PowerObservations => "power.observations",
            KafkaTopic::SecurityFindings => "security.findings",
            KafkaTopic::AgentAudit => "agent.audit",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "agent.commands" => Some(KafkaTopic::AgentCommands),
            "agent.observations" => Some(KafkaTopic::AgentObservations),
            "agent.results" => Some(KafkaTopic::AgentResults),
            "agent.review" => Some(KafkaTopic::AgentReview),
            "agent.deadletter" => Some(KafkaTopic::AgentDeadletter),
            "scheduler.capacity" => Some(KafkaTopic::SchedulerCapacity),
            "power.commands" => Some(KafkaTopic::PowerCommands),
            "power.observations" => Some(KafkaTopic::PowerObservations),
            "security.findings" => Some(KafkaTopic::SecurityFindings),
            "agent.audit" => Some(KafkaTopic::AgentAudit),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MessageEnvelope {
    topic: KafkaTopic,
    idempotency_key: String,
    correlation_id: String,
    workflow_state: WorkflowState,
    attempt: u32,
    max_attempts: u32,
    payload: String,
}

impl MessageEnvelope {
    fn new(
        topic: KafkaTopic,
        run_id: &str,
        workflow_state: WorkflowState,
        payload: String,
        config: &OrchestratorConfig,
    ) -> Self {
        Self {
            topic,
            idempotency_key: format!("{run_id}:{}", topic.as_str()),
            correlation_id: run_id.to_string(),
            workflow_state,
            attempt: 1,
            max_attempts: config.retry_limit.max(DEFAULT_MAX_DELIVERY_ATTEMPTS),
            payload,
        }
    }

    fn with_delivery_failure(&self, topic: KafkaTopic, reason: &str) -> Self {
        Self {
            topic,
            idempotency_key: format!("{}:{}", self.correlation_id, topic.as_str()),
            correlation_id: self.correlation_id.clone(),
            workflow_state: WorkflowState::Deadlettered,
            attempt: self.attempt,
            max_attempts: self.max_attempts,
            payload: format!(
                "delivery_failed source_topic={} reason={} payload={}",
                self.topic.as_str(),
                reason,
                self.payload
            ),
        }
    }
}

impl WorkflowState {
    fn as_str(&self) -> &'static str {
        match self {
            WorkflowState::Received => "received",
            WorkflowState::Validated => "validated",
            WorkflowState::Scheduled => "scheduled",
            WorkflowState::Running => "running",
            WorkflowState::Reviewing => "reviewing",
            WorkflowState::Accepted => "accepted",
            WorkflowState::Retrying => "retrying",
            WorkflowState::Quarantined => "quarantined",
            WorkflowState::Deadlettered => "deadlettered",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        match value {
            "received" => Some(WorkflowState::Received),
            "validated" => Some(WorkflowState::Validated),
            "scheduled" => Some(WorkflowState::Scheduled),
            "running" => Some(WorkflowState::Running),
            "reviewing" => Some(WorkflowState::Reviewing),
            "accepted" => Some(WorkflowState::Accepted),
            "retrying" => Some(WorkflowState::Retrying),
            "quarantined" => Some(WorkflowState::Quarantined),
            "deadlettered" => Some(WorkflowState::Deadlettered),
            _ => None,
        }
    }
}

trait MessageProducer {
    fn publish(&mut self, envelope: MessageEnvelope);
}

trait MessageConsumer {
    fn drain_topic(&mut self, topic: KafkaTopic) -> Vec<MessageEnvelope>;
}

#[derive(Debug, Default)]
struct InMemoryBroker {
    envelopes: Vec<MessageEnvelope>,
}

impl MessageProducer for InMemoryBroker {
    fn publish(&mut self, envelope: MessageEnvelope) {
        self.envelopes.push(envelope);
    }
}

impl MessageConsumer for InMemoryBroker {
    fn drain_topic(&mut self, topic: KafkaTopic) -> Vec<MessageEnvelope> {
        let mut matched = Vec::new();
        let mut remaining = Vec::new();

        for envelope in self.envelopes.drain(..) {
            if envelope.topic == topic {
                matched.push(envelope);
            } else {
                remaining.push(envelope);
            }
        }

        self.envelopes = remaining;
        matched
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KafkaAdapterConfig {
    bootstrap_servers: String,
    client_id: String,
    consumer_group: String,
    max_poll_records: u32,
    max_delivery_attempts: u32,
}

impl KafkaAdapterConfig {
    fn from_orchestrator_config(config: &OrchestratorConfig) -> Self {
        Self {
            bootstrap_servers: config.kafka_bootstrap_servers.clone(),
            client_id: format!(
                "{}-orchestrator",
                sanitize_kubernetes_label(&config.control_plane_role)
            ),
            consumer_group: format!(
                "{}-scheduler",
                sanitize_kubernetes_label(&config.control_plane_role)
            ),
            max_poll_records: config.max_in_flight.max(1),
            max_delivery_attempts: config.retry_limit.max(DEFAULT_MAX_DELIVERY_ATTEMPTS),
        }
    }

    fn bootstrap_servers(&self) -> Vec<&str> {
        self.bootstrap_servers
            .split(',')
            .map(str::trim)
            .filter(|server| !server.is_empty())
            .collect()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct KafkaRecord {
    topic: String,
    key: String,
    headers: Vec<(String, String)>,
    payload: String,
}

impl KafkaRecord {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum KafkaRecordError {
    UnknownTopic,
    MissingHeader(&'static str),
    InvalidWorkflowState,
    InvalidAttempt,
    InvalidMaxAttempts,
}

#[derive(Debug)]
struct KafkaBrokerAdapter {
    config: KafkaAdapterConfig,
    records: Vec<KafkaRecord>,
}

impl KafkaBrokerAdapter {
    fn new(config: KafkaAdapterConfig) -> Self {
        Self {
            config,
            records: Vec::new(),
        }
    }

    fn publish_record(&mut self, record: KafkaRecord) {
        self.records.push(record);
    }
}

impl MessageProducer for KafkaBrokerAdapter {
    fn publish(&mut self, envelope: MessageEnvelope) {
        self.records.push(kafka_record_from_envelope(&envelope));
    }
}

impl MessageConsumer for KafkaBrokerAdapter {
    fn drain_topic(&mut self, topic: KafkaTopic) -> Vec<MessageEnvelope> {
        let mut matched = Vec::new();
        let mut remaining = Vec::new();
        let mut deadletters = Vec::new();

        for record in self.records.drain(..) {
            if record.topic == topic.as_str() {
                match envelope_from_kafka_record(&record) {
                    Ok(envelope) => matched.push(envelope),
                    Err(error) => deadletters.push(kafka_record_from_envelope(
                        &deadletter_for_malformed_record(&record, &error, &self.config),
                    )),
                }
            } else {
                remaining.push(record);
            }
        }

        remaining.extend(deadletters);
        self.records = remaining;
        matched
    }
}

#[derive(Debug)]
enum LiveKafkaError {
    Client(String),
    Produce(String),
    Consume(String),
    Decode(KafkaRecordError),
    Utf8(String),
}

impl fmt::Display for LiveKafkaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiveKafkaError::Client(error) => write!(formatter, "Kafka client error: {error}"),
            LiveKafkaError::Produce(error) => write!(formatter, "Kafka produce error: {error}"),
            LiveKafkaError::Consume(error) => write!(formatter, "Kafka consume error: {error}"),
            LiveKafkaError::Decode(error) => {
                write!(formatter, "Kafka record decode error: {error:?}")
            }
            LiveKafkaError::Utf8(error) => write!(formatter, "Kafka UTF-8 error: {error}"),
        }
    }
}

struct LiveKafkaBroker {
    config: KafkaAdapterConfig,
    producer: BaseProducer,
    consumer: BaseConsumer,
}

impl LiveKafkaBroker {
    fn connect(config: KafkaAdapterConfig) -> Result<Self, LiveKafkaError> {
        let producer: BaseProducer = ClientConfig::new()
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("client.id", &config.client_id)
            .set("message.timeout.ms", "5000")
            .set("queue.buffering.max.ms", "10")
            .create()
            .map_err(|error| LiveKafkaError::Client(error.to_string()))?;
        let consumer: BaseConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("client.id", format!("{}-consumer", config.client_id))
            .set("group.id", &config.consumer_group)
            .set("enable.auto.commit", "true")
            .set("auto.offset.reset", "earliest")
            .set("session.timeout.ms", "6000")
            .create()
            .map_err(|error| LiveKafkaError::Client(error.to_string()))?;

        Ok(Self {
            config,
            producer,
            consumer,
        })
    }

    fn try_publish(&self, envelope: &MessageEnvelope) -> Result<(), LiveKafkaError> {
        let record = kafka_record_from_envelope(envelope);
        self.try_publish_record(&record)
    }

    fn try_publish_record(&self, record: &KafkaRecord) -> Result<(), LiveKafkaError> {
        self.producer
            .send(
                BaseRecord::to(record.topic.as_str())
                    .key(record.key.as_str())
                    .payload(record.payload.as_str())
                    .headers(owned_headers_from_kafka_record(record)),
            )
            .map_err(|(error, _)| LiveKafkaError::Produce(error.to_string()))?;
        self.producer.poll(Duration::from_millis(0));
        self.producer
            .flush(Duration::from_secs(5))
            .map_err(|error| LiveKafkaError::Produce(error.to_string()))
    }

    fn try_drain_topic(&self, topic: KafkaTopic) -> Result<Vec<MessageEnvelope>, LiveKafkaError> {
        self.consumer
            .subscribe(&[topic.as_str()])
            .map_err(|error| LiveKafkaError::Consume(error.to_string()))?;

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut envelopes = Vec::new();

        while envelopes.len() < self.config.max_poll_records as usize && Instant::now() < deadline {
            match self.consumer.poll(Duration::from_millis(100)) {
                Some(Ok(message)) => {
                    let record = kafka_record_from_message(&message)?;
                    let envelope =
                        envelope_from_kafka_record(&record).map_err(LiveKafkaError::Decode)?;
                    envelopes.push(envelope);
                }
                Some(Err(KafkaError::PartitionEOF(_))) | None => {
                    if !envelopes.is_empty() {
                        break;
                    }
                }
                Some(Err(error)) => return Err(LiveKafkaError::Consume(error.to_string())),
            }
        }

        self.consumer.unsubscribe();
        Ok(envelopes)
    }
}

impl MessageProducer for LiveKafkaBroker {
    fn publish(&mut self, envelope: MessageEnvelope) {
        if let Err(error) = self.try_publish(&envelope) {
            let deadletter =
                envelope.with_delivery_failure(KafkaTopic::AgentDeadletter, &error.to_string());
            let _ = self.try_publish(&deadletter);
        }
    }
}

impl MessageConsumer for LiveKafkaBroker {
    fn drain_topic(&mut self, topic: KafkaTopic) -> Vec<MessageEnvelope> {
        match self.try_drain_topic(topic) {
            Ok(envelopes) => envelopes,
            Err(error) => vec![MessageEnvelope {
                topic: KafkaTopic::AgentDeadletter,
                idempotency_key: format!(
                    "live-kafka-consume-error:{}",
                    KafkaTopic::AgentDeadletter.as_str()
                ),
                correlation_id: "live-kafka-consume-error".to_string(),
                workflow_state: WorkflowState::Deadlettered,
                attempt: 1,
                max_attempts: self.config.max_delivery_attempts,
                payload: format!(
                    "live_kafka_consume_failed source_topic={} error={}",
                    topic.as_str(),
                    error
                ),
            }],
        }
    }
}

fn kafka_record_from_envelope(envelope: &MessageEnvelope) -> KafkaRecord {
    KafkaRecord {
        topic: envelope.topic.as_str().to_string(),
        key: envelope.idempotency_key.clone(),
        headers: vec![
            (
                "correlation_id".to_string(),
                envelope.correlation_id.clone(),
            ),
            (
                "workflow_state".to_string(),
                envelope.workflow_state.as_str().to_string(),
            ),
            ("attempt".to_string(), envelope.attempt.to_string()),
            (
                "max_attempts".to_string(),
                envelope.max_attempts.to_string(),
            ),
        ],
        payload: envelope.payload.clone(),
    }
}

fn owned_headers_from_kafka_record(record: &KafkaRecord) -> OwnedHeaders {
    let mut headers = OwnedHeaders::new_with_capacity(record.headers.len());
    for (key, value) in &record.headers {
        headers = headers.insert(Header {
            key,
            value: Some(value.as_str()),
        });
    }
    headers
}

fn kafka_record_from_message(message: &impl Message) -> Result<KafkaRecord, LiveKafkaError> {
    let key = message
        .key()
        .map(str::from_utf8)
        .transpose()
        .map_err(|error| LiveKafkaError::Utf8(error.to_string()))?
        .unwrap_or_default()
        .to_string();
    let payload = message
        .payload()
        .map(str::from_utf8)
        .transpose()
        .map_err(|error| LiveKafkaError::Utf8(error.to_string()))?
        .unwrap_or_default()
        .to_string();
    let mut headers = Vec::new();

    if let Some(message_headers) = message.headers() {
        for index in 0..message_headers.count() {
            let header = message_headers.get(index);
            let value = header
                .value
                .map(str::from_utf8)
                .transpose()
                .map_err(|error| LiveKafkaError::Utf8(error.to_string()))?
                .unwrap_or_default()
                .to_string();
            headers.push((header.key.to_string(), value));
        }
    }

    Ok(KafkaRecord {
        topic: message.topic().to_string(),
        key,
        headers,
        payload,
    })
}

fn envelope_from_kafka_record(record: &KafkaRecord) -> Result<MessageEnvelope, KafkaRecordError> {
    let topic = KafkaTopic::from_str(&record.topic).ok_or(KafkaRecordError::UnknownTopic)?;
    let correlation_id = required_header(record, "correlation_id")?.to_string();
    let workflow_state = WorkflowState::from_str(required_header(record, "workflow_state")?)
        .ok_or(KafkaRecordError::InvalidWorkflowState)?;
    let attempt = required_header(record, "attempt")?
        .parse::<u32>()
        .map_err(|_| KafkaRecordError::InvalidAttempt)?;
    let max_attempts = required_header(record, "max_attempts")?
        .parse::<u32>()
        .map_err(|_| KafkaRecordError::InvalidMaxAttempts)?;

    Ok(MessageEnvelope {
        topic,
        idempotency_key: record.key.clone(),
        correlation_id,
        workflow_state,
        attempt,
        max_attempts,
        payload: record.payload.clone(),
    })
}

fn required_header<'a>(
    record: &'a KafkaRecord,
    name: &'static str,
) -> Result<&'a str, KafkaRecordError> {
    record
        .header(name)
        .ok_or(KafkaRecordError::MissingHeader(name))
}

fn deadletter_for_malformed_record(
    record: &KafkaRecord,
    error: &KafkaRecordError,
    config: &KafkaAdapterConfig,
) -> MessageEnvelope {
    let correlation_id = record
        .header("correlation_id")
        .unwrap_or("unknown-correlation")
        .to_string();

    MessageEnvelope {
        topic: KafkaTopic::AgentDeadletter,
        idempotency_key: format!("{correlation_id}:{}", KafkaTopic::AgentDeadletter.as_str()),
        correlation_id,
        workflow_state: WorkflowState::Deadlettered,
        attempt: 1,
        max_attempts: config.max_delivery_attempts,
        payload: format!(
            "malformed_kafka_record source_topic={} key={} error={error:?}",
            record.topic, record.key
        ),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum DeliveryFailure {
    Transient(&'static str),
    Permanent(&'static str),
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

#[derive(Debug, PartialEq, Eq)]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KubernetesNodeLifecycleAction {
    AdmitRemoteCapacity,
    CordonRemoteCapacity,
}

impl KubernetesNodeLifecycleAction {
    fn as_str(self) -> &'static str {
        match self {
            KubernetesNodeLifecycleAction::AdmitRemoteCapacity => "admit_remote_capacity",
            KubernetesNodeLifecycleAction::CordonRemoteCapacity => "cordon_remote_capacity",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct KubernetesNodeLifecycleEvent {
    namespace: String,
    service_account: String,
    action: KubernetesNodeLifecycleAction,
    target_group: &'static str,
    correlation_id: String,
    required_slots: u32,
    public_reason: String,
}

impl KubernetesNodeLifecycleEvent {
    fn payload(&self) -> String {
        format!(
            "kubernetes_node_lifecycle namespace={} service_account={} action={} target_group={} correlation_id={} required_slots={} reason={}",
            self.namespace,
            self.service_account,
            self.action.as_str(),
            self.target_group,
            self.correlation_id,
            self.required_slots,
            self.public_reason
        )
    }
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
    println!("sample_kafka_contract={:?}", sample_kafka_contract(&config));
    println!("kafka_adapter={}", kafka_adapter_summary(&config));
    println!(
        "sample_kafka_adapter_contract={:?}",
        sample_kafka_adapter_contract(&config)
    );
    if let Some(result) = live_kafka_smoke_from_env(&config) {
        println!("live_kafka_smoke={result}");
    }
    for decision in sample_scheduling_decisions(&config) {
        println!(
            "sample_scheduling_decision={}",
            describe_decision(&decision)
        );
    }
    for event in sample_kubernetes_lifecycle_events(&config) {
        println!("sample_kubernetes_lifecycle_event={}", event.payload());
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

fn sample_kafka_contract(config: &OrchestratorConfig) -> Vec<MessageEnvelope> {
    let mut broker = InMemoryBroker::default();
    let power_command = publish_scheduling_observation(
        &mut broker,
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
        config,
    );
    let mut exhausted_command = power_command.clone();
    exhausted_command.attempt = exhausted_command.max_attempts;
    broker.publish(next_delivery_attempt(
        &exhausted_command,
        DeliveryFailure::Transient("sample broker timeout"),
    ));
    broker.publish(next_delivery_attempt(
        &power_command,
        DeliveryFailure::Permanent("sample invalid envelope"),
    ));

    let mut sample = broker.drain_topic(KafkaTopic::PowerCommands);
    sample.extend(broker.drain_topic(KafkaTopic::AgentDeadletter));
    sample
}

fn live_kafka_smoke_from_env(config: &OrchestratorConfig) -> Option<String> {
    if env::var("ATHERNEX_LIVE_KAFKA_SMOKE").ok().as_deref() != Some("1") {
        return None;
    }

    let adapter_config = KafkaAdapterConfig::from_orchestrator_config(config);
    let broker = match LiveKafkaBroker::connect(adapter_config) {
        Ok(broker) => broker,
        Err(error) => return Some(format!("failed stage=connect error={error}")),
    };
    let envelope = MessageEnvelope::new(
        KafkaTopic::AgentAudit,
        "live-kafka-smoke",
        WorkflowState::Scheduled,
        "live_kafka_smoke source=orchestrator_preparation".to_string(),
        config,
    );

    if let Err(error) = broker.try_publish(&envelope) {
        return Some(format!("failed stage=publish error={error}"));
    }

    match broker.try_drain_topic(KafkaTopic::AgentAudit) {
        Ok(envelopes) if envelopes.iter().any(|candidate| candidate == &envelope) => {
            Some("ok topic=agent.audit".to_string())
        }
        Ok(envelopes) => Some(format!("failed stage=consume observed={}", envelopes.len())),
        Err(error) => Some(format!("failed stage=consume error={error}")),
    }
}

fn kafka_adapter_summary(config: &OrchestratorConfig) -> String {
    let adapter_config = KafkaAdapterConfig::from_orchestrator_config(config);
    format!(
        "bootstrap_servers={:?} client_id={} consumer_group={} max_poll_records={} max_delivery_attempts={}",
        adapter_config.bootstrap_servers(),
        adapter_config.client_id,
        adapter_config.consumer_group,
        adapter_config.max_poll_records,
        adapter_config.max_delivery_attempts
    )
}

fn sample_kafka_adapter_contract(config: &OrchestratorConfig) -> Vec<MessageEnvelope> {
    let adapter_config = KafkaAdapterConfig::from_orchestrator_config(config);
    let mut adapter = KafkaBrokerAdapter::new(adapter_config);
    let power_command = MessageEnvelope::new(
        KafkaTopic::PowerCommands,
        "adapter-sample-001",
        WorkflowState::Scheduled,
        "request_power_on run_id=adapter-sample-001 target_group=worker-group-a slots=4"
            .to_string(),
        config,
    );

    adapter.publish(power_command);
    adapter.publish_record(KafkaRecord {
        topic: KafkaTopic::PowerCommands.as_str().to_string(),
        key: "adapter-malformed-sample".to_string(),
        headers: vec![
            (
                "correlation_id".to_string(),
                "adapter-malformed-sample".to_string(),
            ),
            ("workflow_state".to_string(), "scheduled".to_string()),
            ("attempt".to_string(), "not-a-number".to_string()),
            (
                "max_attempts".to_string(),
                config
                    .retry_limit
                    .max(DEFAULT_MAX_DELIVERY_ATTEMPTS)
                    .to_string(),
            ),
        ],
        payload: "malformed sample payload omitted from dead letter".to_string(),
    });

    let mut sample = adapter.drain_topic(KafkaTopic::PowerCommands);
    sample.extend(adapter.drain_topic(KafkaTopic::AgentDeadletter));
    sample
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
            config,
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
            config,
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
            config,
        ),
    ]
}

fn sample_kubernetes_lifecycle_events(
    config: &OrchestratorConfig,
) -> Vec<KubernetesNodeLifecycleEvent> {
    let mut events = Vec::new();

    for decision in sample_scheduling_decisions(config) {
        if let Some(event) = kubernetes_lifecycle_event_for_decision(&decision, config) {
            events.push(event);
        }
    }

    if let Some(decision) = decide_idle_action(
        &CapacitySnapshot {
            local_available_slots: config.local_capacity_slots,
            remote_online_slots: 4,
            remote_powering_slots: 0,
            idle_seconds: config.idle_powerdown_after_seconds + 1,
        },
        config,
    ) {
        if let Some(event) = kubernetes_lifecycle_event_for_decision(&decision, config) {
            events.push(event);
        }
    }

    events
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
        KafkaTopic::AgentCommands.as_str(),
        KafkaTopic::AgentObservations.as_str(),
        KafkaTopic::AgentResults.as_str(),
        KafkaTopic::AgentReview.as_str(),
        KafkaTopic::AgentDeadletter.as_str(),
        KafkaTopic::SchedulerCapacity.as_str(),
        KafkaTopic::PowerCommands.as_str(),
        KafkaTopic::PowerObservations.as_str(),
        KafkaTopic::SecurityFindings.as_str(),
        KafkaTopic::AgentAudit.as_str(),
    ]
}

fn kubernetes_lifecycle_event_for_decision(
    decision: &SchedulingDecision,
    config: &OrchestratorConfig,
) -> Option<KubernetesNodeLifecycleEvent> {
    match decision {
        SchedulingDecision::RequestPowerOn {
            run_id,
            target_group,
            slots,
        } => Some(KubernetesNodeLifecycleEvent {
            namespace: kubernetes_namespace_for_config(config),
            service_account: "athernex-orchestrator".to_string(),
            action: KubernetesNodeLifecycleAction::AdmitRemoteCapacity,
            target_group,
            correlation_id: (*run_id).to_string(),
            required_slots: *slots,
            public_reason: "remote capacity requested by scheduler threshold".to_string(),
        }),
        SchedulingDecision::RequestPowerOff {
            target_group,
            idle_seconds,
        } => Some(KubernetesNodeLifecycleEvent {
            namespace: kubernetes_namespace_for_config(config),
            service_account: "athernex-orchestrator".to_string(),
            action: KubernetesNodeLifecycleAction::CordonRemoteCapacity,
            target_group,
            correlation_id: format!("idle-remote-capacity-{idle_seconds}"),
            required_slots: 0,
            public_reason: format!("remote capacity idle for {idle_seconds} seconds"),
        }),
        SchedulingDecision::RunHere { .. }
        | SchedulingDecision::DispatchRemote { .. }
        | SchedulingDecision::Hold { .. } => None,
    }
}

fn kubernetes_namespace_for_config(config: &OrchestratorConfig) -> String {
    format!(
        "{}-scheduler",
        sanitize_kubernetes_label(&config.control_plane_role)
    )
}

fn sanitize_kubernetes_label(value: &str) -> String {
    let mut label = String::new();
    let mut previous_dash = false;

    for character in value.chars().flat_map(char::to_lowercase) {
        let next = if character.is_ascii_lowercase() || character.is_ascii_digit() {
            Some(character)
        } else if character == '-' || character == '_' || character == '.' || character == ' ' {
            Some('-')
        } else {
            None
        };

        if let Some(character) = next {
            if character == '-' {
                if !label.is_empty() && !previous_dash {
                    label.push(character);
                    previous_dash = true;
                }
            } else {
                label.push(character);
                previous_dash = false;
            }
        }
    }

    let sanitized = label.trim_matches('-');
    if sanitized.is_empty() {
        "control-plane".to_string()
    } else {
        sanitized.chars().take(50).collect()
    }
}

fn publish_scheduling_observation(
    producer: &mut impl MessageProducer,
    job: &JobRequest,
    capacity: &CapacitySnapshot,
    config: &OrchestratorConfig,
) -> MessageEnvelope {
    let decision = decide_capacity_action(job, capacity, config);
    let envelope = envelope_for_decision(job.run_id, &decision, config);

    producer.publish(envelope.clone());
    envelope
}

fn envelope_for_decision(
    run_id: &str,
    decision: &SchedulingDecision,
    config: &OrchestratorConfig,
) -> MessageEnvelope {
    let topic = match decision {
        SchedulingDecision::RunHere { .. } | SchedulingDecision::DispatchRemote { .. } => {
            KafkaTopic::AgentCommands
        }
        SchedulingDecision::RequestPowerOn { .. } | SchedulingDecision::RequestPowerOff { .. } => {
            KafkaTopic::PowerCommands
        }
        SchedulingDecision::Hold { .. } => KafkaTopic::SchedulerCapacity,
    };

    MessageEnvelope::new(
        topic,
        run_id,
        WorkflowState::Scheduled,
        describe_decision(decision),
        config,
    )
}

fn next_delivery_attempt(envelope: &MessageEnvelope, failure: DeliveryFailure) -> MessageEnvelope {
    match failure {
        DeliveryFailure::Permanent(reason) => {
            envelope.with_delivery_failure(KafkaTopic::AgentDeadletter, reason)
        }
        DeliveryFailure::Transient(reason) if envelope.attempt >= envelope.max_attempts => {
            envelope.with_delivery_failure(KafkaTopic::AgentDeadletter, reason)
        }
        DeliveryFailure::Transient(reason) => {
            let mut retry = envelope.clone();
            retry.workflow_state = WorkflowState::Retrying;
            retry.attempt += 1;
            retry.payload = format!(
                "retry source_topic={} reason={} payload={}",
                envelope.topic.as_str(),
                reason,
                envelope.payload
            );
            retry
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> OrchestratorConfig {
        OrchestratorConfig {
            project_name: "Project Athernex".to_string(),
            control_plane_role: "local-control-plane".to_string(),
            scheduler_mode: "contract-only".to_string(),
            local_capacity_slots: 2,
            remote_wake_threshold_slots: 3,
            idle_powerdown_after_seconds: 900,
            kafka_bootstrap_servers: "127.0.0.1:9092".to_string(),
            localstack_endpoint: "http://127.0.0.1:4566".to_string(),
            paperclip_endpoint: "http://127.0.0.1:3100".to_string(),
            max_in_flight: 8,
            retry_limit: 3,
        }
    }

    #[test]
    fn interactive_jobs_prefer_available_local_capacity() {
        let decision = decide_capacity_action(
            &JobRequest {
                run_id: "interactive-local-001",
                required_slots: 1,
                priority: JobPriority::Interactive,
                allows_remote_capacity: false,
            },
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 4,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        assert_eq!(
            decision,
            SchedulingDecision::RunHere {
                run_id: "interactive-local-001",
                slots: 1
            }
        );
    }

    #[test]
    fn oversized_remote_allowed_jobs_request_power_on_at_threshold() {
        let decision = decide_capacity_action(
            &JobRequest {
                run_id: "batch-remote-001",
                required_slots: 4,
                priority: JobPriority::Batch,
                allows_remote_capacity: true,
            },
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        assert_eq!(
            decision,
            SchedulingDecision::RequestPowerOn {
                run_id: "batch-remote-001",
                target_group: "worker-group-a",
                slots: 4
            }
        );
    }

    #[test]
    fn maintenance_jobs_hold_for_promotion_window() {
        let decision = decide_capacity_action(
            &JobRequest {
                run_id: "maintenance-001",
                required_slots: 1,
                priority: JobPriority::Maintenance,
                allows_remote_capacity: false,
            },
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        assert_eq!(
            decision,
            SchedulingDecision::Hold {
                run_id: "maintenance-001",
                reason: "maintenance jobs require an explicit promotion window"
            }
        );
    }

    #[test]
    fn idle_remote_workers_request_power_off_after_threshold() {
        let decision = decide_idle_action(
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 4,
                remote_powering_slots: 0,
                idle_seconds: 901,
            },
            &config(),
        );

        assert_eq!(
            decision,
            Some(SchedulingDecision::RequestPowerOff {
                target_group: "worker-group-a",
                idle_seconds: 901
            })
        );
    }

    #[test]
    fn workflow_state_count_matches_public_contract() {
        assert_eq!(workflow_states().len(), 9);
        assert!(workflow_states().contains(&WorkflowState::Deadlettered));
    }

    #[test]
    fn kafka_topics_include_review_and_audit_paths() {
        let topics = kafka_topics();

        assert!(topics.contains(&"agent.review"));
        assert!(topics.contains(&"agent.audit"));
        assert!(topics.contains(&"agent.deadletter"));
    }

    #[test]
    fn power_on_decisions_publish_to_power_commands() {
        let mut broker = InMemoryBroker::default();
        let envelope = publish_scheduling_observation(
            &mut broker,
            &JobRequest {
                run_id: "batch-remote-001",
                required_slots: 4,
                priority: JobPriority::Batch,
                allows_remote_capacity: true,
            },
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        let power_commands = broker.drain_topic(KafkaTopic::PowerCommands);

        assert_eq!(envelope.topic, KafkaTopic::PowerCommands);
        assert_eq!(power_commands.len(), 1);
        assert_eq!(power_commands[0].correlation_id, "batch-remote-001");
        assert!(power_commands[0].payload.contains("request_power_on"));
        assert!(broker.drain_topic(KafkaTopic::AgentCommands).is_empty());
    }

    #[test]
    fn hold_decisions_publish_to_scheduler_capacity() {
        let mut broker = InMemoryBroker::default();
        let envelope = publish_scheduling_observation(
            &mut broker,
            &JobRequest {
                run_id: "small-remote-001",
                required_slots: 2,
                priority: JobPriority::Batch,
                allows_remote_capacity: true,
            },
            &CapacitySnapshot {
                local_available_slots: 0,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        assert_eq!(envelope.topic, KafkaTopic::SchedulerCapacity);
        assert_eq!(
            broker.drain_topic(KafkaTopic::SchedulerCapacity)[0].payload,
            "hold run_id=small-remote-001 reason=below remote wake threshold"
        );
    }

    #[test]
    fn transient_delivery_failure_retries_on_original_topic() {
        let envelope = MessageEnvelope::new(
            KafkaTopic::AgentCommands,
            "interactive-local-001",
            WorkflowState::Scheduled,
            "run_here run_id=interactive-local-001 slots=1".to_string(),
            &config(),
        );

        let retry = next_delivery_attempt(&envelope, DeliveryFailure::Transient("broker timeout"));

        assert_eq!(retry.topic, KafkaTopic::AgentCommands);
        assert_eq!(retry.workflow_state, WorkflowState::Retrying);
        assert_eq!(retry.attempt, 2);
        assert_eq!(retry.correlation_id, envelope.correlation_id);
        assert!(retry.payload.contains("broker timeout"));
    }

    #[test]
    fn exhausted_transient_failure_routes_to_deadletter() {
        let mut envelope = MessageEnvelope::new(
            KafkaTopic::PowerCommands,
            "batch-remote-001",
            WorkflowState::Scheduled,
            "request_power_on run_id=batch-remote-001 target_group=worker-group-a slots=4"
                .to_string(),
            &config(),
        );
        envelope.attempt = envelope.max_attempts;

        let deadletter =
            next_delivery_attempt(&envelope, DeliveryFailure::Transient("broker timeout"));

        assert_eq!(deadletter.topic, KafkaTopic::AgentDeadletter);
        assert_eq!(deadletter.workflow_state, WorkflowState::Deadlettered);
        assert_eq!(deadletter.correlation_id, "batch-remote-001");
        assert!(deadletter.payload.contains("source_topic=power.commands"));
    }

    #[test]
    fn permanent_delivery_failure_routes_to_deadletter_immediately() {
        let envelope = MessageEnvelope::new(
            KafkaTopic::SchedulerCapacity,
            "maintenance-001",
            WorkflowState::Scheduled,
            "hold run_id=maintenance-001 reason=promotion window required".to_string(),
            &config(),
        );

        let deadletter =
            next_delivery_attempt(&envelope, DeliveryFailure::Permanent("invalid envelope"));

        assert_eq!(deadletter.topic, KafkaTopic::AgentDeadletter);
        assert_eq!(deadletter.workflow_state, WorkflowState::Deadlettered);
        assert_eq!(deadletter.attempt, 1);
        assert!(deadletter.payload.contains("invalid envelope"));
    }

    #[test]
    fn kafka_adapter_config_sanitizes_client_and_group_names() {
        let mut config = config();
        config.control_plane_role = "Control Plane__Review.Stage!!".to_string();
        config.kafka_bootstrap_servers = "127.0.0.1:9092, kafka.local:9092 ".to_string();

        let adapter_config = KafkaAdapterConfig::from_orchestrator_config(&config);

        assert_eq!(
            adapter_config.client_id,
            "control-plane-review-stage-orchestrator"
        );
        assert_eq!(
            adapter_config.consumer_group,
            "control-plane-review-stage-scheduler"
        );
        assert_eq!(
            adapter_config.bootstrap_servers(),
            vec!["127.0.0.1:9092", "kafka.local:9092"]
        );
        assert_eq!(adapter_config.max_poll_records, 8);
    }

    #[test]
    fn kafka_record_round_trip_preserves_typed_envelope_metadata() {
        let envelope = MessageEnvelope::new(
            KafkaTopic::PowerCommands,
            "batch-remote-001",
            WorkflowState::Scheduled,
            "request_power_on run_id=batch-remote-001 target_group=worker-group-a slots=4"
                .to_string(),
            &config(),
        );

        let record = kafka_record_from_envelope(&envelope);
        let decoded =
            envelope_from_kafka_record(&record).expect("adapter record should decode cleanly");

        assert_eq!(record.topic, "power.commands");
        assert_eq!(record.key, "batch-remote-001:power.commands");
        assert_eq!(record.header("correlation_id"), Some("batch-remote-001"));
        assert_eq!(record.header("workflow_state"), Some("scheduled"));
        assert_eq!(decoded, envelope);
    }

    #[test]
    fn kafka_broker_adapter_implements_existing_message_traits() {
        let mut adapter =
            KafkaBrokerAdapter::new(KafkaAdapterConfig::from_orchestrator_config(&config()));

        let envelope = publish_scheduling_observation(
            &mut adapter,
            &JobRequest {
                run_id: "batch-remote-001",
                required_slots: 4,
                priority: JobPriority::Batch,
                allows_remote_capacity: true,
            },
            &CapacitySnapshot {
                local_available_slots: 2,
                remote_online_slots: 0,
                remote_powering_slots: 0,
                idle_seconds: 0,
            },
            &config(),
        );

        let drained = adapter.drain_topic(KafkaTopic::PowerCommands);

        assert_eq!(drained, vec![envelope]);
        assert!(adapter.drain_topic(KafkaTopic::PowerCommands).is_empty());
    }

    #[test]
    fn malformed_kafka_record_routes_to_deadletter_without_payload_echo() {
        let mut adapter =
            KafkaBrokerAdapter::new(KafkaAdapterConfig::from_orchestrator_config(&config()));
        adapter.publish_record(KafkaRecord {
            topic: "power.commands".to_string(),
            key: "unsafe-private-record".to_string(),
            headers: vec![
                (
                    "correlation_id".to_string(),
                    "malformed-record-001".to_string(),
                ),
                ("workflow_state".to_string(), "scheduled".to_string()),
                ("attempt".to_string(), "not-a-number".to_string()),
                ("max_attempts".to_string(), "3".to_string()),
            ],
            payload: "rack=private ipmi=private payload must not be copied".to_string(),
        });

        assert!(adapter.drain_topic(KafkaTopic::PowerCommands).is_empty());

        let deadletters = adapter.drain_topic(KafkaTopic::AgentDeadletter);
        assert_eq!(deadletters.len(), 1);
        assert_eq!(deadletters[0].topic, KafkaTopic::AgentDeadletter);
        assert_eq!(deadletters[0].correlation_id, "malformed-record-001");
        assert!(deadletters[0].payload.contains("InvalidAttempt"));
        assert!(!deadletters[0].payload.contains("ipmi=private"));
        assert!(!deadletters[0].payload.contains("rack=private"));
    }

    #[test]
    fn live_kafka_error_display_names_operation() {
        assert_eq!(
            LiveKafkaError::Produce("broker timeout".to_string()).to_string(),
            "Kafka produce error: broker timeout"
        );
        assert_eq!(
            LiveKafkaError::Decode(KafkaRecordError::InvalidAttempt).to_string(),
            "Kafka record decode error: InvalidAttempt"
        );
    }

    #[test]
    fn live_kafka_broker_round_trips_against_local_kafka_when_enabled() {
        if env::var("ATHERNEX_KAFKA_INTEGRATION").ok().as_deref() != Some("1") {
            return;
        }

        let mut config = config();
        let run_id = format!(
            "live-kafka-smoke-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("system clock should be after UNIX epoch")
                .as_millis()
        );
        config.kafka_bootstrap_servers =
            env::var("KAFKA_BOOTSTRAP_SERVERS").unwrap_or_else(|_| "127.0.0.1:9092".to_string());
        config.max_in_flight = 50;

        let mut adapter_config = KafkaAdapterConfig::from_orchestrator_config(&config);
        adapter_config.consumer_group = format!("{}-group", run_id);
        let broker = LiveKafkaBroker::connect(adapter_config)
            .expect("local Kafka broker should accept live client connections");
        let envelope = MessageEnvelope::new(
            KafkaTopic::AgentAudit,
            &run_id,
            WorkflowState::Scheduled,
            format!("live_kafka_smoke correlation_id={run_id}"),
            &config,
        );

        broker
            .try_publish(&envelope)
            .expect("live Kafka publish should succeed");

        let drained = broker
            .try_drain_topic(KafkaTopic::AgentAudit)
            .expect("live Kafka consume should succeed");

        assert!(drained.iter().any(|candidate| candidate == &envelope));
    }

    #[test]
    fn power_on_decision_creates_sanitized_kubernetes_admission_handoff() {
        let decision = SchedulingDecision::RequestPowerOn {
            run_id: "batch-remote-001",
            target_group: "worker-group-a",
            slots: 4,
        };

        let event = kubernetes_lifecycle_event_for_decision(&decision, &config())
            .expect("power-on decisions should hand off to the Kubernetes adapter");

        assert_eq!(event.namespace, "local-control-plane-scheduler");
        assert_eq!(event.service_account, "athernex-orchestrator");
        assert_eq!(
            event.action,
            KubernetesNodeLifecycleAction::AdmitRemoteCapacity
        );
        assert_eq!(event.target_group, "worker-group-a");
        assert_eq!(event.correlation_id, "batch-remote-001");
        assert_eq!(event.required_slots, 4);
        assert_public_safe_payload(&event.payload());
    }

    #[test]
    fn idle_power_off_decision_creates_cordon_handoff_without_private_node_names() {
        let decision = SchedulingDecision::RequestPowerOff {
            target_group: "worker-group-a",
            idle_seconds: 901,
        };

        let event = kubernetes_lifecycle_event_for_decision(&decision, &config())
            .expect("power-off decisions should hand off to the Kubernetes adapter");

        assert_eq!(
            event.action,
            KubernetesNodeLifecycleAction::CordonRemoteCapacity
        );
        assert_eq!(event.correlation_id, "idle-remote-capacity-901");
        assert_eq!(event.required_slots, 0);
        assert!(event.payload().contains("remote capacity idle"));
        assert_public_safe_payload(&event.payload());
    }

    #[test]
    fn local_dispatch_and_hold_decisions_do_not_create_node_lifecycle_handoffs() {
        let run_here = SchedulingDecision::RunHere {
            run_id: "interactive-local-001",
            slots: 1,
        };
        let dispatch_remote = SchedulingDecision::DispatchRemote {
            run_id: "batch-remote-002",
            slots: 2,
        };
        let hold = SchedulingDecision::Hold {
            run_id: "maintenance-001",
            reason: "maintenance jobs require an explicit promotion window",
        };

        assert_eq!(
            kubernetes_lifecycle_event_for_decision(&run_here, &config()),
            None
        );
        assert_eq!(
            kubernetes_lifecycle_event_for_decision(&dispatch_remote, &config()),
            None
        );
        assert_eq!(
            kubernetes_lifecycle_event_for_decision(&hold, &config()),
            None
        );
    }

    #[test]
    fn kubernetes_namespace_contract_collapses_unsuitable_public_input() {
        let mut config = config();
        config.control_plane_role = "Control Plane__Review.Stage!!".to_string();

        assert_eq!(
            kubernetes_namespace_for_config(&config),
            "control-plane-review-stage-scheduler"
        );
    }

    fn assert_public_safe_payload(payload: &str) {
        assert!(!payload.contains("ipmi"));
        assert!(!payload.contains("bmc"));
        assert!(!payload.contains("rack"));
        assert!(!payload.contains("192.168."));
        assert!(!payload.contains("10."));
        assert!(!payload.contains("172.16."));
        assert!(!payload.contains("node-"));
        assert!(!payload.contains("mac="));
    }
}
