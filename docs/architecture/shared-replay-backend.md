# Shared Replay Backend Draft

This draft supports issue #44. It is not implemented on `main`.

## Current Boundary

`sts-replay` owns replay behavior. `ReplayPolicy` wraps a `ReplayStore`, and
`sts-http` currently builds:

```rust
ReplayPolicy::new(InMemoryReplayStore::new(config.max_seen_jti, 256))
```

This is correct for one process. It does not prevent replay when two STS replicas
receive the same actor/client assertion `jti` or DPoP holder-key replay key.

## Backend Direction

Add an operator-selectable backend:

```text
STS_REPLAY_BACKEND=memory | redis
STS_REPLAY_REDIS_URL=rediss://...
STS_REPLAY_REDIS_KEY_PREFIX=sts-delegate-rs:
STS_REPLAY_FAIL_CLOSED=true
```

The first implementation should keep the current in-memory behavior as the default
and add a Redis-backed store for production-style multi-replica deployments.

## Redis Semantics

Use one atomic conditional write per replay key:

```text
SET <namespace:key> 1 EX <ttl_seconds> NX
```

Expected mapping:

- command returns success: first use, record accepted;
- command returns nil/not-set: replay detected;
- Redis unavailable, timeout, invalid TTL, or serialization failure: fail closed as
  `service_unavailable`;
- TTL is derived from the credential/proof expiration already computed by the caller.

Replay keys must remain bounded. DPoP already uses `sha256(jkt || NUL || jti)` via
`dpop_replay_key`; actor/client assertion keys should continue to be namespaced and
bounded before they reach the backend.

## Acceptance Tests

- two logical HTTP states sharing one backend accept first use and reject second use;
- DPoP replay across two logical states returns `invalid_dpop_proof`;
- actor/client assertion replay across two logical states returns the existing OAuth
  failure class;
- backend outage maps to fail-closed `service_unavailable` without leaking tokens or
  raw replay IDs;
- Redis keys are namespaced and do not store raw subject tokens, actor tokens,
  assertions, raw DPoP proofs, or raw `jti` values when a digest namespace is possible;
- metrics distinguish current in-memory cache size from shared backend health.

## Open Design Choice

The current `ReplayStore` trait is synchronous. Redis clients are normally async in a
Tokio server. The implementation PR should either make replay checks async through the
HTTP path or isolate any blocking Redis client behind a small bounded executor. Do not
block the async runtime on network I/O.
