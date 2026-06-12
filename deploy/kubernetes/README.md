# Kubernetes Reference Deployment Draft

This draft is for issue #42. It is a starting point for a Kubernetes reference
deployment of `sts-cli serve`; it is not a production hardening claim.

The manifests keep runtime configuration and key material outside the image:

- non-secret runtime values are supplied by `sts-delegate-rs-config`;
- private signing key and trust-anchor JWKS files are mounted from
  `sts-delegate-rs-secrets`;
- the container binds on `0.0.0.0:8888` inside the Pod, so the deployment sets
  `ALLOW_INSECURE_HTTP_BIND=true`; external traffic must terminate TLS before it
  reaches the Service;
- readiness probes call discovery metadata and liveness probes call `/jwks`.

The current product still uses the in-process replay backend and file-backed STS
signing key. Multi-replica deployments need #44 before replay is correct across
replicas, and higher-assurance key custody needs #43.

## Configure

Create the namespace and non-secret config:

```bash
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl apply -f deploy/kubernetes/configmap.yaml
```

Create the secret from local files. Do not commit the rendered secret:

```bash
kubectl -n sts-delegate-rs create secret generic sts-delegate-rs-secrets \
  --from-file=obo_sts_private_key.json=secrets/obo_sts_private_key.json \
  --from-file=actor_jwks.json=secrets/actor_jwks.json \
  --from-file=client_jwks.json=secrets/client_jwks.json \
  --from-file=idp_jwks.json=secrets/idp_jwks.json
```

If live IdP JWKS retrieval is intended instead of `IDP_JWKS_FILE`, remove the
`IDP_JWKS_FILE` env entry and set `IDP_JWKS_URI` in the ConfigMap.

## Render And Apply

```bash
kubectl apply --dry-run=client -f deploy/kubernetes/
kubectl apply -f deploy/kubernetes/
kubectl -n sts-delegate-rs rollout status deployment/sts-delegate-rs
```

## Smoke

```bash
kubectl -n sts-delegate-rs port-forward service/sts-delegate-rs 8888:8888
curl -fsS http://127.0.0.1:8888/.well-known/oauth-authorization-server
curl -fsS http://127.0.0.1:8888/jwks
```

Do not print bearer tokens, assertions, private JWK members, raw JWTs, raw `jti`
values, or Okta tenant secrets in deployment logs or issue evidence.
