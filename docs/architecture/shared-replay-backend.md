# Shared Replay Backend

This page supports issue #44. The current implementation ships an operator-selectable
file-backed shared replay backend. Redis or another networked backend can be added
later without changing the `ReplayStore` ownership boundary.

## Current Boundary

`sts-replay` owns replay behavior. `ReplayPolicy` wraps a `ReplayStore`, and
`sts-http` selects the configured backend during bootstrap:

```text
STS_REPLAY_BACKEND=memory
STS_REPLAY_BACKEND=file
STS_REPLAY_DIR=/var/lib/sts-delegate/replay
```

`memory` remains the local/single-replica default. `file` uses a shared POSIX
directory and atomic `create_new` recording so two replicas sharing the same directory
accept the first use and reject the second use.

## File Backend Semantics

The file backend hashes the caller-controlled replay key before it becomes a filename.
It never writes raw subject tokens, actor tokens, assertions, DPoP proofs, holder-key
thumbprints, or raw `jti` values as path names.

```text
filename = sha256("sts-replay-file-v1" || NUL || replay_key) + ".jti"
contents = expiration timestamp
```

Expected mapping:

- atomic create succeeds: first use, record accepted;
- file already exists and is unexpired: replay detected;
- file exists but is expired: expired file is removed and the current use can record;
- directory unavailable, file write failure, poisoned counter, or capacity exhaustion:
  fail closed as `service_unavailable`.

DPoP already uses `sha256(jkt || NUL || jti)` through `dpop_replay_key`; actor/client
assertion keys remain caller-defined namespaces before the backend applies its filename
digest.

## Redis Direction

Redis remains a reasonable future backend for deployments that do not want a shared
POSIX volume. Use one atomic conditional write per replay key:

```text
SET <namespace:key> 1 EX <ttl_seconds> NX
```

Expected mapping:

- command returns success: first use, record accepted;
- command returns nil/not-set: replay detected;
- Redis unavailable, timeout, invalid TTL, or serialization failure: fail closed as
  `service_unavailable`;
- TTL is derived from the credential/proof expiration already computed by the caller.

## Implemented Tests

- `file_store_records_once_across_instances_without_raw_jti_filename`
- `file_store_reuses_expired_entry_and_enforces_capacity`
- `file_store_fails_closed_when_directory_is_unavailable`
- `contract_actor_replay_is_shared_across_file_backed_replicas`
- `contract_dpop_replay_is_shared_across_file_backed_replicas`

## Open Design Choice

The current `ReplayStore` trait is synchronous. That fits local memory and file-backed
recording. Redis clients are normally async in a Tokio server. A future Redis PR should
either make replay checks async through the HTTP path or isolate any blocking Redis
client behind a small bounded executor. Do not block the async runtime on network I/O.
