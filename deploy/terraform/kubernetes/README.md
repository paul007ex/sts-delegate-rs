# Terraform Kubernetes Reference Deployment

This module is a reference deployment for `sts-cli serve`. It is intentionally
small and keeps runtime configuration, trust anchors, and signing material outside
the image.

Current safety scope:

- `replicas` defaults to `1` until a shared replay backend is merged and enabled.
- signing uses the file-backed STS private JWK path unless an external signer PR is
  merged and configured separately.
- ingress TLS is expected at the cluster edge; the Pod binds HTTP only inside the
  cluster.
- secret values are sensitive Terraform variables and must not be committed.

## Validate

```bash
terraform -chdir=deploy/terraform/kubernetes fmt -check
terraform -chdir=deploy/terraform/kubernetes init -backend=false
terraform -chdir=deploy/terraform/kubernetes validate
```

## Example Plan

```bash
terraform -chdir=deploy/terraform/kubernetes plan \
  -var='idp_issuer=https://your-idp.example.invalid/oauth2/default' \
  -var='expected_subject_aud=api://chat-mcp' \
  -var='sts_issuer=https://sts.example.invalid' \
  -var='obo_sts_private_key_json=<redacted>' \
  -var='actor_jwks_json=<redacted>' \
  -var='client_jwks_json=<redacted>' \
  -var='idp_jwks_json=<redacted>'
```

Do not paste real bearer tokens, assertions, private JWK members, Authorization
headers, raw JWTs, raw `jti` values, or tenant secrets into issue evidence.
