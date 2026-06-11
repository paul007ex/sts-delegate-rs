#![forbid(unsafe_code)]

//! Replay-state crate for `sts-delegate-rs`.
//!
//! This crate owns jti replay state, sender-constraining replay keys, and the
//! fail-closed replay policy.

use std::collections::HashMap;
use std::fmt;
use std::sync::Mutex;

use sha2::{Digest, Sha256};

/// Failure categories for replay enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplayErrorKind {
    InvalidRequest,
    ReplayDetected,
    StoreFull,
}

impl fmt::Display for ReplayErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::InvalidRequest => "invalid_request",
            Self::ReplayDetected => "invalid_request",
            Self::StoreFull => "service_unavailable",
        };
        f.write_str(code)
    }
}

/// A stable replay-layer error for token exchange.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayError {
    pub kind: ReplayErrorKind,
    pub message: String,
}

impl ReplayError {
    pub fn new(kind: ReplayErrorKind, message: impl Into<String>) -> Self {
        Self { kind, message: message.into() }
    }
}

impl fmt::Display for ReplayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.kind, self.message)
    }
}

impl std::error::Error for ReplayError {}

/// Replay-store behavior for single-use sender-constraining tokens.
pub trait ReplayStore: Send + Sync {
    fn check_and_record(&self, jti: &str, exp: i64, now: i64) -> Result<(), ReplayError>;

    fn cache_size(&self) -> usize {
        0
    }
}

/// In-memory replay store for single-process validation and tests.
#[derive(Debug)]
pub struct InMemoryReplayStore {
    seen: Mutex<HashMap<String, i64>>,
    calls_since_sweep: Mutex<usize>,
    pub max_seen: usize,
    pub sweep_every: usize,
}

impl Default for InMemoryReplayStore {
    fn default() -> Self {
        Self::new(1024, 256)
    }
}

impl InMemoryReplayStore {
    pub fn new(max_seen: usize, sweep_every: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            calls_since_sweep: Mutex::new(0),
            max_seen,
            sweep_every: sweep_every.max(1),
        }
    }

    fn sweep_expired(&self, seen: &mut HashMap<String, i64>, now: i64) {
        seen.retain(|_, exp| *exp >= now);
    }
}

impl ReplayStore for InMemoryReplayStore {
    fn check_and_record(&self, jti: &str, exp: i64, now: i64) -> Result<(), ReplayError> {
        if jti.trim().is_empty() {
            return Err(ReplayError::new(ReplayErrorKind::InvalidRequest, "jti must not be empty"));
        }

        let mut seen = self.seen.lock().map_err(|_| replay_store_unavailable())?;
        if seen.contains_key(jti) {
            return Err(ReplayError::new(
                ReplayErrorKind::ReplayDetected,
                "actor_token replay detected",
            ));
        }

        let mut calls_since_sweep =
            self.calls_since_sweep.lock().map_err(|_| replay_store_unavailable())?;
        *calls_since_sweep += 1;
        if *calls_since_sweep >= self.sweep_every {
            self.sweep_expired(&mut seen, now);
            *calls_since_sweep = 0;
        }

        if seen.len() >= self.max_seen {
            self.sweep_expired(&mut seen, now);
        }
        if seen.len() >= self.max_seen {
            return Err(ReplayError::new(
                ReplayErrorKind::StoreFull,
                "replay store full, retry shortly",
            ));
        }

        seen.insert(jti.to_string(), exp);
        Ok(())
    }

    fn cache_size(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }
}

fn replay_store_unavailable() -> ReplayError {
    ReplayError::new(ReplayErrorKind::StoreFull, "replay store unavailable, retry shortly")
}

/// The active replay-store boundary for the current process.
pub struct ReplayPolicy {
    store: Box<dyn ReplayStore>,
}

impl ReplayPolicy {
    pub fn new(store: impl ReplayStore + 'static) -> Self {
        Self { store: Box::new(store) }
    }

    pub fn in_memory() -> Self {
        Self::new(InMemoryReplayStore::default())
    }

    pub fn check_and_record(&self, jti: &str, exp: i64, now: i64) -> Result<(), ReplayError> {
        self.store.check_and_record(jti, exp, now)
    }

    pub fn cache_size(&self) -> usize {
        self.store.cache_size()
    }
}

/// Build the bounded replay key for a DPoP proof.
///
/// RFC 9449 makes the proof `jti` single-use per holder key. Hashing
/// `jkt || NUL || jti` keeps the replay-store key fixed-size even though both
/// values are caller-controlled.
pub fn dpop_replay_key(jkt: &str, jti: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(jkt.as_bytes());
    hasher.update([0]);
    hasher.update(jti.as_bytes());
    format!("dpop:{}", hex_lower(&hasher.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_memory_store_records_once() {
        let store = InMemoryReplayStore::new(8, 4);
        assert!(store.check_and_record("jti-1", 10, 1).is_ok());
        let err = store.check_and_record("jti-1", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::ReplayDetected);
    }

    #[test]
    fn in_memory_store_rejects_empty_jti() {
        let store = InMemoryReplayStore::new(8, 4);
        let err = store.check_and_record("", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::InvalidRequest);
    }

    #[test]
    fn in_memory_store_evicts_expired_entries() {
        let store = InMemoryReplayStore::new(1, 256);
        assert!(store.check_and_record("jti-1", 9, 1).is_ok());
        let err = store.check_and_record("jti-2", 10, 3).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::StoreFull);
    }

    #[test]
    fn replay_policy_uses_store_boundary() {
        let policy = ReplayPolicy::in_memory();
        assert!(policy.check_and_record("jti-1", 10, 1).is_ok());
        assert_eq!(policy.cache_size(), 1);
    }

    #[test]
    fn in_memory_store_fails_closed_when_seen_lock_is_poisoned() {
        let store = InMemoryReplayStore::new(8, 4);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.seen.lock().expect("lock");
            panic!("poison replay store");
        }));

        let err = store.check_and_record("jti-2", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::StoreFull);
        assert_eq!(err.message, "replay store unavailable, retry shortly");
        assert_eq!(store.cache_size(), 0);
    }

    #[test]
    fn in_memory_store_fails_closed_when_counter_lock_is_poisoned() {
        let store = InMemoryReplayStore::new(8, 4);
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = store.calls_since_sweep.lock().expect("lock");
            panic!("poison replay counter");
        }));

        let err = store.check_and_record("jti-2", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::StoreFull);
        assert_eq!(err.message, "replay store unavailable, retry shortly");
    }

    #[test]
    fn dpop_replay_key_is_bounded_and_namespaced() {
        let key = dpop_replay_key("holder-thumbprint", &"x".repeat(4096));
        assert!(key.starts_with("dpop:"));
        assert_eq!(key.len(), "dpop:".len() + 64);
        assert_ne!(key, dpop_replay_key("holder-thumbprintx", ""));
    }
}
