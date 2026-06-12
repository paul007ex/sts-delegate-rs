variable "namespace" {
  description = "Kubernetes namespace for sts-delegate-rs."
  type        = string
  default     = "sts-delegate-rs"
}

variable "name" {
  description = "Base Kubernetes resource name."
  type        = string
  default     = "sts-delegate-rs"
}

variable "image" {
  description = "Container image for sts-cli serve."
  type        = string
  default     = "sts-delegate-rs:local"
}

variable "replicas" {
  description = "Replica count. Keep at 1 until a shared replay backend is enabled."
  type        = number
  default     = 1

  validation {
    condition     = var.replicas == 1
    error_message = "The reference deployment keeps replicas=1 until shared replay is configured."
  }
}

variable "idp_issuer" {
  description = "OIDC issuer that signs subject tokens."
  type        = string
}

variable "expected_subject_aud" {
  description = "Expected audience on incoming subject tokens."
  type        = string
}

variable "sts_issuer" {
  description = "Public issuer URL for this STS."
  type        = string
}

variable "actor_ids" {
  description = "Comma-separated actor identities accepted by this deployment."
  type        = string
  default     = "chat-mcp"
}

variable "target_policy_json" {
  description = "Target policy JSON using allowed_scopes/default_scopes entries."
  type        = string
  default     = <<-EOT
    {
      "api://databricks-mcp": {
        "allowed_scopes": ["databricks.read"],
        "default_scopes": ["databricks.read"]
      },
      "api://servicenow-mcp": {
        "allowed_scopes": ["servicenow.read"],
        "default_scopes": ["servicenow.read"]
      }
    }
  EOT
}

variable "obo_sts_private_key_json" {
  description = "Private STS signing JWK JSON. Provide from a secret manager or sensitive tfvars."
  type        = string
  sensitive   = true
}

variable "actor_jwks_json" {
  description = "Public actor JWKS JSON."
  type        = string
  sensitive   = true
}

variable "client_jwks_json" {
  description = "Public client JWKS JSON."
  type        = string
  sensitive   = true
}

variable "idp_jwks_json" {
  description = "Public IdP JWKS JSON for offline bootstrap."
  type        = string
  sensitive   = true
}

variable "ingress_host" {
  description = "Ingress host. Leave empty to skip Ingress."
  type        = string
  default     = ""
}

variable "ingress_tls_secret_name" {
  description = "TLS secret for ingress_host."
  type        = string
  default     = "sts-delegate-rs-tls"
}
