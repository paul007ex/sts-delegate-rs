#![forbid(unsafe_code)]

//! Replay-state crate for `sts-delegate-rs`.
//!
//! This crate will own jti replay state, sender-constraining replay keys, and
//! the fail-closed replay policy.

/// Marker type for the replay crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replay;
