variable "namespace" {
  description = "Kubernetes namespace used by the public scheduler contract."
  type        = string
  default     = "athernex-staging"

  validation {
    condition     = can(regex("^[a-z0-9]([-a-z0-9]*[a-z0-9])?$", var.namespace))
    error_message = "namespace must be a DNS-1123 label."
  }
}

variable "scheduler_mode" {
  description = "Scheduler behavior exposed to the Rust orchestrator."
  type        = string
  default     = "contract-only"

  validation {
    condition     = contains(["contract-only", "local-first", "remote-enabled"], var.scheduler_mode)
    error_message = "scheduler_mode must be contract-only, local-first, or remote-enabled."
  }
}

variable "local_capacity_slots" {
  description = "Number of local worker slots advertised to the orchestrator."
  type        = number
  default     = 2

  validation {
    condition     = var.local_capacity_slots >= 1 && var.local_capacity_slots <= 32
    error_message = "local_capacity_slots must be between 1 and 32."
  }
}

variable "remote_wake_threshold_slots" {
  description = "Minimum requested slots before remote capacity can be powered on."
  type        = number
  default     = 3

  validation {
    condition     = var.remote_wake_threshold_slots >= 1 && var.remote_wake_threshold_slots <= 64
    error_message = "remote_wake_threshold_slots must be between 1 and 64."
  }
}

variable "idle_powerdown_after_seconds" {
  description = "Idle remote capacity duration before a power-down decision is allowed."
  type        = number
  default     = 900

  validation {
    condition     = var.idle_powerdown_after_seconds >= 300 && var.idle_powerdown_after_seconds <= 86400
    error_message = "idle_powerdown_after_seconds must be between 300 and 86400."
  }
}
