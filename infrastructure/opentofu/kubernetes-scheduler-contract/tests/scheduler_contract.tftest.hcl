run "default_contract_renders_kubernetes_manifests" {
  command = plan

  assert {
    condition     = output.namespace == "athernex-staging"
    error_message = "default namespace changed unexpectedly"
  }

  assert {
    condition     = output.kubernetes_manifests.namespace.kind == "Namespace"
    error_message = "namespace manifest must render as a Kubernetes Namespace"
  }

  assert {
    condition     = output.kubernetes_manifests.service_account.automountServiceAccountToken == false
    error_message = "orchestrator service account must not automount credentials in the public contract"
  }

  assert {
    condition     = output.scheduler_config.ATHERNEX_SCHEDULER_MODE == "contract-only"
    error_message = "default scheduler mode must stay contract-only"
  }

  assert {
    condition     = output.scheduler_config.ATHERNEX_REMOTE_WAKE_THRESHOLD_SLOTS == "3"
    error_message = "default wake threshold should match the Rust orchestrator default"
  }
}

run "remote_enabled_contract_is_explicit" {
  command = plan

  variables {
    namespace                   = "athernex-remote"
    scheduler_mode              = "remote-enabled"
    local_capacity_slots        = 4
    remote_wake_threshold_slots = 5
  }

  assert {
    condition     = output.namespace == "athernex-remote"
    error_message = "namespace variable was not reflected in outputs"
  }

  assert {
    condition     = output.scheduler_config.ATHERNEX_SCHEDULER_MODE == "remote-enabled"
    error_message = "remote-enabled scheduler mode was not propagated"
  }

  assert {
    condition     = output.scheduler_config.ATHERNEX_LOCAL_CAPACITY_SLOTS == "4"
    error_message = "local capacity slots must be stringified for Kubernetes ConfigMap data"
  }
}
