#![forbid(unsafe_code)]

//! Trust-anchor and token-verification crate for `sts-delegate-rs`.

/// Marker type for the verification crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verify;
