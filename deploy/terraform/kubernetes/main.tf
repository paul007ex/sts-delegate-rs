locals {
  labels = {
    "app.kubernetes.io/name" = var.name
  }

  sts_secret_mount = "/run/secrets/sts"
}

resource "kubernetes_namespace_v1" "this" {
  metadata {
    name   = var.namespace
    labels = local.labels
  }
}

resource "kubernetes_config_map_v1" "this" {
  metadata {
    name      = "${var.name}-config"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }

  data = {
    IDP_ISSUER               = var.idp_issuer
    EXPECTED_SUBJECT_AUD     = var.expected_subject_aud
    OBO_STS_ISSUER           = var.sts_issuer
    ACTOR_IDS                = var.actor_ids
    STS_TOKEN_EXCHANGE_MODE  = "delegation"
    STS_HTTP_ADDR            = "0.0.0.0:8888"
    ALLOW_INSECURE_HTTP_BIND = "true"
    STS_ENABLE_METRICS       = "true"
    LOG_FORMAT               = "json"
    TARGET_POLICY_JSON       = var.target_policy_json
  }
}

resource "kubernetes_secret_v1" "this" {
  metadata {
    name      = "${var.name}-secrets"
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }

  data = {
    "obo_sts_private_key.json" = var.obo_sts_private_key_json
    "actor_jwks.json"          = var.actor_jwks_json
    "client_jwks.json"         = var.client_jwks_json
    "idp_jwks.json"            = var.idp_jwks_json
  }
}

resource "kubernetes_deployment_v1" "this" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }

  spec {
    replicas = var.replicas

    selector {
      match_labels = local.labels
    }

    template {
      metadata {
        labels = local.labels
      }

      spec {
        security_context {
          run_as_non_root = true

          seccomp_profile {
            type = "RuntimeDefault"
          }
        }

        container {
          name              = "sts"
          image             = var.image
          image_pull_policy = "IfNotPresent"
          args              = ["serve"]

          port {
            name           = "http"
            container_port = 8888
          }

          env_from {
            config_map_ref {
              name = kubernetes_config_map_v1.this.metadata[0].name
            }
          }

          env {
            name  = "OBO_STS_KEY_FILE"
            value = "${local.sts_secret_mount}/obo_sts_private_key.json"
          }

          env {
            name  = "ACTOR_JWKS_FILE"
            value = "${local.sts_secret_mount}/actor_jwks.json"
          }

          env {
            name  = "CLIENT_JWKS_FILE"
            value = "${local.sts_secret_mount}/client_jwks.json"
          }

          env {
            name  = "IDP_JWKS_FILE"
            value = "${local.sts_secret_mount}/idp_jwks.json"
          }

          volume_mount {
            name       = "sts-secrets"
            mount_path = local.sts_secret_mount
            read_only  = true
          }

          readiness_probe {
            http_get {
              path = "/.well-known/oauth-authorization-server"
              port = "http"
            }
            initial_delay_seconds = 3
            period_seconds        = 10
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          liveness_probe {
            http_get {
              path = "/jwks"
              port = "http"
            }
            initial_delay_seconds = 10
            period_seconds        = 30
            timeout_seconds       = 2
            failure_threshold     = 3
          }

          resources {
            requests = {
              cpu    = "50m"
              memory = "128Mi"
            }
            limits = {
              cpu    = "500m"
              memory = "512Mi"
            }
          }

          security_context {
            allow_privilege_escalation = false
            read_only_root_filesystem  = true

            capabilities {
              drop = ["ALL"]
            }
          }
        }

        volume {
          name = "sts-secrets"

          secret {
            secret_name  = kubernetes_secret_v1.this.metadata[0].name
            default_mode = "0400"
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "this" {
  metadata {
    name      = var.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
  }

  spec {
    type     = "ClusterIP"
    selector = local.labels

    port {
      name        = "http"
      port        = 8888
      target_port = "http"
    }
  }
}

resource "kubernetes_ingress_v1" "this" {
  count = var.ingress_host == "" ? 0 : 1

  metadata {
    name      = var.name
    namespace = kubernetes_namespace_v1.this.metadata[0].name
    labels    = local.labels
    annotations = {
      "nginx.ingress.kubernetes.io/force-ssl-redirect" = "true"
    }
  }

  spec {
    tls {
      hosts       = [var.ingress_host]
      secret_name = var.ingress_tls_secret_name
    }

    rule {
      host = var.ingress_host

      http {
        path {
          path      = "/"
          path_type = "Prefix"

          backend {
            service {
              name = kubernetes_service_v1.this.metadata[0].name

              port {
                name = "http"
              }
            }
          }
        }
      }
    }
  }
}
