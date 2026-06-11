#![forbid(unsafe_code)]

//! Configuration and bootstrap crate for `sts-delegate-rs`.

/// Marker type for the config crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Config;
