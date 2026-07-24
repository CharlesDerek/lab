output "namespace" {
  description = "Namespace for the generated public Kubernetes contract."
  value       = var.namespace
}

output "scheduler_config" {
  description = "Environment contract consumed by the Rust orchestrator."
  value       = local.scheduler_config
}

output "kubernetes_manifests" {
  description = "Sanitized Kubernetes resources suitable for review or downstream apply tooling."
  value       = local.manifests
}
