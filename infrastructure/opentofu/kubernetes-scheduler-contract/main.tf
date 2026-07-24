locals {
  common_labels = {
    "app.kubernetes.io/name"       = "athernex-orchestrator"
    "app.kubernetes.io/component"  = "scheduler-contract"
    "app.kubernetes.io/managed-by" = "opentofu"
  }

  scheduler_config = {
    ATHERNEX_SCHEDULER_MODE                  = var.scheduler_mode
    ATHERNEX_LOCAL_CAPACITY_SLOTS            = tostring(var.local_capacity_slots)
    ATHERNEX_REMOTE_WAKE_THRESHOLD_SLOTS     = tostring(var.remote_wake_threshold_slots)
    ATHERNEX_IDLE_POWERDOWN_AFTER_SECONDS    = tostring(var.idle_powerdown_after_seconds)
    ATHERNEX_KUBERNETES_CONTRACT_GENERATION  = "opentofu"
    ATHERNEX_KUBERNETES_PRIVATE_DATA_OMITTED = "true"
  }

  manifests = {
    namespace = {
      apiVersion = "v1"
      kind       = "Namespace"
      metadata = {
        name   = var.namespace
        labels = local.common_labels
      }
    }

    service_account = {
      apiVersion = "v1"
      kind       = "ServiceAccount"
      metadata = {
        name      = "athernex-orchestrator"
        namespace = var.namespace
        labels    = local.common_labels
      }
      automountServiceAccountToken = false
    }

    config_map = {
      apiVersion = "v1"
      kind       = "ConfigMap"
      metadata = {
        name      = "athernex-scheduler-contract"
        namespace = var.namespace
        labels    = local.common_labels
      }
      data = local.scheduler_config
    }
  }
}
