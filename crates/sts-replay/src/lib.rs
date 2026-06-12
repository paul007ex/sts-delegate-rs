#![forbid(unsafe_code)]

//! Replay-state crate for `sts-delegate-rs`.
//!
//! This crate owns jti replay state, sender-constraining replay keys, and the
//! fail-closed replay policy.

use std::collections::HashMap;
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
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

/// File-backed replay store for multi-replica deployments sharing a POSIX directory.
///
/// The caller-controlled replay key is hashed before it becomes a filename. Recording
/// uses `create_new` so two processes racing on the same key get exactly one winner.
#[derive(Debug)]
pub struct FileReplayStore {
    dir: PathBuf,
    max_seen: usize,
    sweep_every: usize,
    calls_since_sweep: Mutex<usize>,
}

impl FileReplayStore {
    pub fn new(
        dir: impl Into<PathBuf>,
        max_seen: usize,
        sweep_every: usize,
    ) -> Result<Self, ReplayError> {
        let dir = dir.into();
        fs::create_dir_all(&dir).map_err(|_| replay_store_unavailable())?;
        if !dir.is_dir() {
            return Err(replay_store_unavailable());
        }
        Ok(Self {
            dir,
            max_seen,
            sweep_every: sweep_every.max(1),
            calls_since_sweep: Mutex::new(0),
        })
    }

    fn path_for_jti(&self, jti: &str) -> PathBuf {
        self.dir.join(replay_filename(jti))
    }

    fn sweep_expired(&self, now: i64) -> Result<(), ReplayError> {
        let entries = fs::read_dir(&self.dir).map_err(|_| replay_store_unavailable())?;
        for entry in entries {
            let entry = entry.map_err(|_| replay_store_unavailable())?;
            let path = entry.path();
            if !path.is_file() {
                continue;
            }
            if read_exp(&path).is_some_and(|exp| exp < now) {
                remove_replay_file(&path)?;
            }
        }
        Ok(())
    }

    fn maybe_sweep(&self, now: i64) -> Result<(), ReplayError> {
        let mut calls_since_sweep =
            self.calls_since_sweep.lock().map_err(|_| replay_store_unavailable())?;
        *calls_since_sweep += 1;
        if *calls_since_sweep >= self.sweep_every {
            self.sweep_expired(now)?;
            *calls_since_sweep = 0;
        }
        Ok(())
    }

    fn active_entry_count(&self) -> Result<usize, ReplayError> {
        let entries = fs::read_dir(&self.dir).map_err(|_| replay_store_unavailable())?;
        let mut count = 0;
        for entry in entries {
            let entry = entry.map_err(|_| replay_store_unavailable())?;
            if entry.path().is_file() {
                count += 1;
            }
        }
        Ok(count)
    }
}

impl ReplayStore for FileReplayStore {
    fn check_and_record(&self, jti: &str, exp: i64, now: i64) -> Result<(), ReplayError> {
        if jti.trim().is_empty() {
            return Err(ReplayError::new(ReplayErrorKind::InvalidRequest, "jti must not be empty"));
        }

        self.maybe_sweep(now)?;
        if self.active_entry_count()? >= self.max_seen {
            self.sweep_expired(now)?;
        }
        if self.active_entry_count()? >= self.max_seen {
            return Err(ReplayError::new(
                ReplayErrorKind::StoreFull,
                "replay store full, retry shortly",
            ));
        }

        let path = self.path_for_jti(jti);
        if read_exp(&path).is_some_and(|stored_exp| stored_exp < now) {
            remove_replay_file(&path)?;
        }

        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                writeln!(file, "{exp}").map_err(|_| replay_store_unavailable())?;
                Ok(())
            }
            Err(err) if err.kind() == ErrorKind::AlreadyExists => Err(ReplayError::new(
                ReplayErrorKind::ReplayDetected,
                "actor_token replay detected",
            )),
            Err(_) => Err(replay_store_unavailable()),
        }
    }

    fn cache_size(&self) -> usize {
        self.active_entry_count().unwrap_or(0)
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

fn replay_filename(jti: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"sts-replay-file-v1");
    hasher.update([0]);
    hasher.update(jti.as_bytes());
    format!("{}.jti", hex_lower(&hasher.finalize()))
}

fn read_exp(path: &Path) -> Option<i64> {
    let mut content = String::new();
    let mut file = OpenOptions::new().read(true).open(path).ok()?;
    file.read_to_string(&mut content).ok()?;
    content.trim().parse::<i64>().ok()
}

fn remove_replay_file(path: &Path) -> Result<(), ReplayError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
        Err(_) => Err(replay_store_unavailable()),
    }
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

    #[test]
    fn file_store_records_once_across_instances_without_raw_jti_filename() {
        let dir = unique_test_dir("file-store-records");
        let store1 = FileReplayStore::new(&dir, 8, 4).expect("store1");
        let store2 = FileReplayStore::new(&dir, 8, 4).expect("store2");

        assert!(store1.check_and_record("act:chat-mcp:raw/jti-value", 10, 1).is_ok());
        let err = store2.check_and_record("act:chat-mcp:raw/jti-value", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::ReplayDetected);

        let names = fs::read_dir(&dir)
            .expect("dir")
            .map(|entry| entry.expect("entry").file_name().to_string_lossy().to_string())
            .collect::<Vec<_>>();
        assert_eq!(names.len(), 1);
        assert!(!names[0].contains("raw"));
        assert!(!names[0].contains("chat-mcp"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn file_store_reuses_expired_entry_and_enforces_capacity() {
        let dir = unique_test_dir("file-store-expiry");
        let store = FileReplayStore::new(&dir, 1, 1).expect("store");

        assert!(store.check_and_record("jti-1", 2, 1).is_ok());
        assert!(store.check_and_record("jti-1", 10, 3).is_ok());
        let err = store.check_and_record("jti-2", 10, 3).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::StoreFull);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn file_store_fails_closed_when_directory_is_unavailable() {
        let dir = unique_test_dir("file-store-unavailable");
        let store = FileReplayStore::new(&dir, 8, 4).expect("store");
        fs::remove_dir_all(&dir).expect("remove dir");

        let err = store.check_and_record("jti-1", 10, 1).unwrap_err();
        assert_eq!(err.kind, ReplayErrorKind::StoreFull);
        assert_eq!(err.message, "replay store unavailable, retry shortly");
    }

    fn unique_test_dir(label: &str) -> PathBuf {
        let unique =
            format!("sts-replay-{label}-{}-{:?}", std::process::id(), std::thread::current().id());
        std::env::temp_dir().join(unique)
    }
}
