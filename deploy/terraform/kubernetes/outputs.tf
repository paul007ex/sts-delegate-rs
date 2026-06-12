output "namespace" {
  description = "Namespace created by the module."
  value       = kubernetes_namespace_v1.this.metadata[0].name
}

output "service_name" {
  description = "ClusterIP service name for sts-delegate-rs."
  value       = kubernetes_service_v1.this.metadata[0].name
}

output "readiness_path" {
  description = "HTTP readiness path."
  value       = "/.well-known/oauth-authorization-server"
}

output "jwks_path" {
  description = "HTTP JWKS/liveness path."
  value       = "/jwks"
}
