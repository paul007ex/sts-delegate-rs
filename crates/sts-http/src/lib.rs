#![forbid(unsafe_code)]

//! HTTP surface for `sts-delegate-rs`.
//!
//! This crate will own `/token`, `/jwks`, discovery metadata, and error mapping
//! without letting transport own policy.

/// Marker type for the HTTP crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Http;
