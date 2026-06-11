#![forbid(unsafe_code)]

//! JOSE/JWK/JWKS, signing, and backend-selection crate for `sts-delegate-rs`.
//!
//! This crate will encapsulate the classical and PQC signing surfaces behind a
//! fail-closed API.

/// Marker type for the JOSE crate boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jose;
