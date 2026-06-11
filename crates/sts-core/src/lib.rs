#![forbid(unsafe_code)]

//! Core token-exchange policy and claim-shaping crate for `sts-delegate-rs`.
//!
//! This crate will own the stable, protocol-facing semantics that the current
//! Python implementation already proves through contract tests.

/// Marker type for the core crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Core;
