#![forbid(unsafe_code)]

//! Runtime configuration and target-policy loading for `sts-delegate-rs`.
//!
//! This crate owns env parsing and deployment-owned authorization data loading.
//! It is intentionally side-effect free at import time; callers opt into loading
//! by invoking [`RuntimeConfig::from_env`] or [`load_target_policy_from_env`].

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fmt;
use std::fs;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use url::{Host, Url};

const DEFAULT_ISSUER: &str = "http://localhost:8888/";
const DEFAULT_KID: &str = "sts-delegate-key-1";
const DEFAULT_SECRETS_DIR: &str = "./secrets";
const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:8888";
const DEFAULT_CLOCK_SKEW_LEEWAY: i64 = 30;
const DEFAULT_SCOPED_TOKEN_TTL: i64 = 300;
const DEFAULT_JWKS_CACHE_MAX_AGE: i64 = 300;
const DEFAULT_ASSERTION_MAX_TTL: i64 = 300;
const DEFAULT_MAX_SEEN_JTI: usize = 100_000;
const DEFAULT_MAX_TOKEN_LEN: usize = 8_192;

/// Stable configuration failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigErrorKind {
    MissingEnv,
    InvalidValue,
    InvalidJson,
    InvalidPolicy,
    NotFound,
}

impl fmt::Display for ConfigErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = match self {
            Self::MissingEnv => "missing_env",
            Self::InvalidValue => "invalid_value",
            Self::InvalidJson => "invalid_json",
            Self::InvalidPolicy => "invalid_policy",
            Self::NotFound => "not_found",
        };
        f.write_str(code)
    }
}

/// Stable config error with a narrow boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub kind: ConfigErrorKind,
    pub key: Option<String>,
    pub message: String,
}

impl ConfigError {
    pub fn new(kind: ConfigErrorKind, key: Option<String>, message: impl Into<String>) -> Self {
        Self { kind, key, message: message.into() }
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.key {
            Some(key) => write!(f, "{}({key}): {}", self.kind, self.message),
            None => write!(f, "{}: {}", self.kind, self.message),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Exchange profile selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TokenExchangeMode {
    Delegation,
    Impersonation,
    Both,
}

/// Client-auth policy selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ClientAuthPolicy {
    Auto,
    PrivateKeyJwtRequired,
    ActorTokenAllowed,
}

/// Policy rows for a single target audience.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetPolicyEntry {
    pub allowed_scopes: BTreeSet<String>,
    pub default_scopes: BTreeSet<String>,
}

/// Deny-by-default target policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TargetPolicy {
    pub targets: BTreeMap<String, TargetPolicyEntry>,
}

impl TargetPolicy {
    pub fn empty() -> Self {
        Self { targets: BTreeMap::new() }
    }

    pub fn get(&self, audience: &str) -> Option<&TargetPolicyEntry> {
        self.targets.get(audience)
    }
}

/// Per-client impersonation authorization policy.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ImpersonationPolicy {
    pub clients: BTreeMap<String, ImpersonationPolicyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ImpersonationPolicyEntry {
    pub targets: ImpersonationSelector,
    pub subjects: ImpersonationSelector,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ImpersonationSelector {
    Any,
    Values(BTreeSet<String>),
}

impl ImpersonationSelector {
    pub fn allows(&self, value: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Values(values) => values.contains(value),
        }
    }
}

/// Raw configuration source.
#[derive(Debug, Clone, Default)]
pub struct ConfigSource {
    values: BTreeMap<String, String>,
}

impl ConfigSource {
    /// Snapshot the current process environment into a stable source map.
    ///
    /// This keeps config parsing side-effect free at the call site while still
    /// allowing the runtime to load from env when explicitly asked.
    pub fn from_env() -> Self {
        Self { values: env::vars().collect() }
    }

    /// Build a source map from explicit key/value pairs for tests and harnesses.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        let values = pairs.into_iter().map(|(k, v)| (k.into(), v.into())).collect();
        Self { values }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.values.get(key).map(String::as_str)
    }
}

/// Full runtime configuration for the Rust STS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeConfig {
    pub idp_issuer: String,
    pub expected_subject_aud: BTreeSet<String>,
    pub our_issuer: String,
    pub our_kid: String,
    pub sts_secrets_dir: PathBuf,
    pub obo_sts_key_file: PathBuf,
    pub idp_jwks_file: Option<PathBuf>,
    pub idp_jwks_uri: Option<String>,
    pub actor_jwks_file: PathBuf,
    pub client_jwks_file: PathBuf,
    pub obo_sts_extra_jwks_file: Option<PathBuf>,
    pub actor_ids: BTreeSet<String>,
    pub actor_id: String,
    pub client_ids: BTreeSet<String>,
    pub token_exchange_mode: TokenExchangeMode,
    pub client_auth_policy: ClientAuthPolicy,
    pub impersonation_policy: ImpersonationPolicy,
    pub target_policy: TargetPolicy,
    pub sts_signing_alg: String,
    pub sts_signing_provider: String,
    pub sts_signing_public_jwks_file: Option<PathBuf>,
    pub mock_external_signer_key_file: Option<PathBuf>,
    pub clock_skew_leeway: i64,
    pub scoped_token_ttl: i64,
    pub jwks_cache_max_age: i64,
    pub assertion_max_ttl: i64,
    pub max_seen_jti: usize,
    pub max_token_len: usize,
    pub require_subject_binding: bool,
    pub subject_scope_bound_required: bool,
    pub allow_insecure_jwks: bool,
    pub allow_insecure_actor_jwks: bool,
    pub allow_insecure_client_jwks: bool,
    pub allow_insecure_key_file: bool,
    pub allow_insecure_http_bind: bool,
    pub actor_jwks_sha256: Option<String>,
    pub client_jwks_sha256: Option<String>,
    pub http_addr: String,
    pub enable_metrics: bool,
    pub log_format_json: bool,
    pub log_level: String,
    pub audit_hash_chain: bool,
}

impl RuntimeConfig {
    /// Load the runtime config from the live process environment.
    ///
    /// This is the production entry point; it validates the IdP issuer,
    /// subject audience, actor/client trust knobs, target policy, and replay /
    /// token-lifetime controls before the HTTP layer starts.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_source(&ConfigSource::from_env())
    }

    /// Load the runtime config from an explicit source map.
    ///
    /// Tests use this to avoid mutating process env; production uses
    /// [`RuntimeConfig::from_env`].
    pub fn from_source(source: &ConfigSource) -> Result<Self, ConfigError> {
        let idp_issuer = require_issuer(source)?;
        let expected_subject_aud = require_expected_aud(source)?;
        let sts_secrets_dir = PathBuf::from(
            source
                .get("STS_SECRETS_DIR")
                .map(str::to_string)
                .unwrap_or_else(|| default_secrets_dir().display().to_string()),
        );
        let actor_jwks_file = PathBuf::from(
            source
                .get("ACTOR_JWKS_FILE")
                .map(str::to_string)
                .unwrap_or_else(|| sts_secrets_dir.join("actor_jwks.json").display().to_string()),
        );
        let obo_sts_key_file =
            PathBuf::from(source.get("OBO_STS_KEY_FILE").map(str::to_string).unwrap_or_else(
                || sts_secrets_dir.join("obo_sts_private_key.json").display().to_string(),
            ));
        let idp_jwks_file = source
            .get("IDP_JWKS_FILE")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let idp_jwks_uri = source
            .get("IDP_JWKS_URI")
            .or_else(|| source.get("OKTA_JWKS_URL"))
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string);
        let client_jwks_file = PathBuf::from(
            source
                .get("CLIENT_JWKS_FILE")
                .map(str::to_string)
                .unwrap_or_else(|| actor_jwks_file.display().to_string()),
        );
        let obo_sts_extra_jwks_file = source
            .get("OBO_STS_EXTRA_JWKS_FILE")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);

        let actor_ids = parse_actor_ids(source)?;
        let actor_id = source
            .get("GATEWAY_ACTOR_ID")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
            .unwrap_or_else(|| actor_ids.iter().next().cloned().unwrap_or_default());
        if actor_id.is_empty() {
            return Err(ConfigError::new(
                ConfigErrorKind::MissingEnv,
                Some("ACTOR_IDS".to_string()),
                "no actor identities configured",
            ));
        }

        let client_ids = parse_client_ids(source, &actor_ids);

        Ok(Self {
            idp_issuer,
            expected_subject_aud,
            our_issuer: validate_issuer(
                source.get("OBO_STS_ISSUER").unwrap_or(DEFAULT_ISSUER),
                "OBO_STS_ISSUER",
            )?,
            our_kid: source
                .get("STS_SIGNING_KID")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .unwrap_or(DEFAULT_KID)
                .to_string(),
            sts_secrets_dir,
            obo_sts_key_file,
            idp_jwks_file,
            idp_jwks_uri,
            actor_jwks_file,
            client_jwks_file,
            obo_sts_extra_jwks_file,
            actor_ids,
            actor_id,
            client_ids,
            token_exchange_mode: parse_token_exchange_mode(source)?,
            client_auth_policy: parse_client_auth_policy(source)?,
            impersonation_policy: parse_impersonation_policy(source)?,
            target_policy: load_target_policy_from_source(source)?,
            sts_signing_alg: source.get("STS_SIGNING_ALG").unwrap_or("").trim().to_string(),
            sts_signing_provider: source
                .get("STS_SIGNING_PROVIDER")
                .unwrap_or("file")
                .trim()
                .to_ascii_lowercase(),
            sts_signing_public_jwks_file: source
                .get("STS_SIGNING_PUBLIC_JWKS_FILE")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            mock_external_signer_key_file: source
                .get("STS_MOCK_EXTERNAL_SIGNER_KEY_FILE")
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(PathBuf::from),
            clock_skew_leeway: parse_env_int(
                source,
                "CLOCK_SKEW_LEEWAY",
                DEFAULT_CLOCK_SKEW_LEEWAY,
                Some(0),
                None,
            )?,
            scoped_token_ttl: parse_env_int(
                source,
                "SCOPED_TOKEN_TTL",
                DEFAULT_SCOPED_TOKEN_TTL,
                Some(1),
                Some(3600),
            )?,
            jwks_cache_max_age: parse_env_int(
                source,
                "JWKS_CACHE_MAX_AGE",
                DEFAULT_JWKS_CACHE_MAX_AGE,
                Some(0),
                None,
            )?,
            assertion_max_ttl: parse_env_int(
                source,
                "ASSERTION_MAX_TTL",
                DEFAULT_ASSERTION_MAX_TTL,
                Some(1),
                None,
            )?,
            max_seen_jti: parse_env_usize(
                source,
                "MAX_SEEN_JTI",
                DEFAULT_MAX_SEEN_JTI,
                Some(1),
                None,
            )?,
            max_token_len: parse_env_usize(
                source,
                "MAX_TOKEN_LEN",
                DEFAULT_MAX_TOKEN_LEN,
                Some(1),
                None,
            )?,
            require_subject_binding: parse_bool(source, "REQUIRE_SUBJECT_BINDING", true),
            subject_scope_bound_required: parse_bool(source, "SUBJECT_SCOPE_BOUND_REQUIRED", false),
            allow_insecure_jwks: parse_bool(source, "ALLOW_INSECURE_JWKS", false),
            allow_insecure_actor_jwks: parse_bool(source, "ALLOW_INSECURE_ACTOR_JWKS", false),
            allow_insecure_client_jwks: parse_bool_with_fallback(
                source,
                "ALLOW_INSECURE_CLIENT_JWKS",
                "ALLOW_INSECURE_ACTOR_JWKS",
                false,
            ),
            allow_insecure_key_file: parse_bool(source, "ALLOW_INSECURE_KEY_FILE", false),
            allow_insecure_http_bind: parse_bool(source, "ALLOW_INSECURE_HTTP_BIND", false),
            actor_jwks_sha256: source
                .get("ACTOR_JWKS_SHA256")
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToString::to_string),
            client_jwks_sha256: source
                .get("CLIENT_JWKS_SHA256")
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .map(ToString::to_string)
                .or_else(|| {
                    source
                        .get("ACTOR_JWKS_SHA256")
                        .map(str::trim)
                        .filter(|v| !v.is_empty())
                        .map(ToString::to_string)
                }),
            http_addr: source.get("STS_HTTP_ADDR").unwrap_or(DEFAULT_HTTP_ADDR).trim().to_string(),
            enable_metrics: parse_bool(source, "STS_ENABLE_METRICS", false),
            log_format_json: parse_bool(source, "LOG_FORMAT_JSON", false)
                || source.get("LOG_FORMAT").is_some_and(|v| v.trim().eq_ignore_ascii_case("json")),
            log_level: parse_log_level(source),
            audit_hash_chain: parse_bool(source, "STS_AUDIT_HASH_CHAIN", false),
        })
    }
}

fn default_secrets_dir() -> PathBuf {
    PathBuf::from(DEFAULT_SECRETS_DIR)
}

fn require_issuer(source: &ConfigSource) -> Result<String, ConfigError> {
    if let Some(value) = source.get("IDP_ISSUER") {
        return validate_issuer(value, "IDP_ISSUER");
    }
    if let Some(value) = source.get("OKTA_ISSUER") {
        return validate_issuer(value, "OKTA_ISSUER");
    }
    Err(ConfigError::new(
        ConfigErrorKind::MissingEnv,
        Some("IDP_ISSUER".to_string()),
        "set IDP_ISSUER (or OKTA_ISSUER) to the OIDC issuer that signs subject tokens",
    ))
}

fn require_expected_aud(source: &ConfigSource) -> Result<BTreeSet<String>, ConfigError> {
    let raw = source.get("EXPECTED_SUBJECT_AUD").ok_or_else(|| {
        ConfigError::new(
            ConfigErrorKind::MissingEnv,
            Some("EXPECTED_SUBJECT_AUD".to_string()),
            "set EXPECTED_SUBJECT_AUD to the subject-token audience",
        )
    })?;
    let values = split_csv_set(raw);
    if values.is_empty() {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some("EXPECTED_SUBJECT_AUD".to_string()),
            "EXPECTED_SUBJECT_AUD contains no non-empty entries",
        ));
    }
    Ok(values)
}

fn validate_issuer(value: &str, key: &str) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            "issuer must not be empty",
        ));
    }
    if trimmed.chars().any(char::is_whitespace) {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            "issuer must not contain whitespace",
        ));
    }
    let parsed = Url::parse(trimmed).map_err(|err| {
        ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            format!("issuer must be an absolute URL: {err}"),
        )
    })?;
    if parsed.host_str().is_none() {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            "issuer must include a host",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            "issuer must not contain a query or fragment component",
        ));
    }
    let is_loopback = match parsed.host() {
        Some(Host::Domain(host)) => host.eq_ignore_ascii_case("localhost"),
        Some(Host::Ipv4(host)) => host.is_loopback(),
        Some(Host::Ipv6(host)) => host.is_loopback(),
        None => false,
    };
    if parsed.scheme() != "https" && !(parsed.scheme() == "http" && is_loopback) {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            "issuer must use https, except http is allowed for loopback local development",
        ));
    }
    Ok(trimmed.trim_end_matches('/').to_string())
}

fn parse_actor_ids(source: &ConfigSource) -> Result<BTreeSet<String>, ConfigError> {
    let mut ids = split_csv_set(source.get("ACTOR_IDS").unwrap_or(""));
    if let Some(single) =
        source.get("GATEWAY_ACTOR_ID").map(str::trim).filter(|value| !value.is_empty())
    {
        ids.insert(single.to_string());
    }
    if ids.is_empty() {
        return Err(ConfigError::new(
            ConfigErrorKind::MissingEnv,
            Some("ACTOR_IDS".to_string()),
            "set ACTOR_IDS (or GATEWAY_ACTOR_ID) to at least one actor identity",
        ));
    }
    Ok(ids)
}

fn parse_client_ids(source: &ConfigSource, actor_ids: &BTreeSet<String>) -> BTreeSet<String> {
    let mut ids = split_csv_set(source.get("CLIENT_IDS").unwrap_or(""));
    if ids.is_empty() {
        ids.extend(actor_ids.iter().cloned());
    }
    ids
}

fn parse_token_exchange_mode(source: &ConfigSource) -> Result<TokenExchangeMode, ConfigError> {
    let raw = source.get("STS_TOKEN_EXCHANGE_MODE").unwrap_or("delegation");
    match raw.trim().to_ascii_lowercase().as_str() {
        "delegation" => Ok(TokenExchangeMode::Delegation),
        "impersonation" => Ok(TokenExchangeMode::Impersonation),
        "both" => Ok(TokenExchangeMode::Both),
        other => Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some("STS_TOKEN_EXCHANGE_MODE".to_string()),
            format!("must be delegation, impersonation, or both; got {other:?}"),
        )),
    }
}

fn parse_client_auth_policy(source: &ConfigSource) -> Result<ClientAuthPolicy, ConfigError> {
    let raw = source.get("CLIENT_AUTH_POLICY").unwrap_or("auto");
    match raw.trim().to_ascii_lowercase().as_str() {
        "auto" | "actor_token_allowed" => Ok(ClientAuthPolicy::Auto),
        "private_key_jwt_required" => Ok(ClientAuthPolicy::PrivateKeyJwtRequired),
        other => Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some("CLIENT_AUTH_POLICY".to_string()),
            format!(
                "must be auto, actor_token_allowed, or private_key_jwt_required; got {other:?}"
            ),
        )),
    }
}

fn parse_impersonation_policy(source: &ConfigSource) -> Result<ImpersonationPolicy, ConfigError> {
    let Some(raw) =
        source.get("IMPERSONATION_POLICY_JSON").map(str::trim).filter(|value| !value.is_empty())
    else {
        return Ok(ImpersonationPolicy::default());
    };
    let parsed: serde_json::Value = serde_json::from_str(raw).map_err(|err| {
        ConfigError::new(
            ConfigErrorKind::InvalidJson,
            Some("IMPERSONATION_POLICY_JSON".to_string()),
            format!("impersonation policy JSON could not be parsed: {err}"),
        )
    })?;
    normalize_impersonation_policy(&parsed)
}

fn parse_log_level(source: &ConfigSource) -> String {
    source.get("LOG_LEVEL").unwrap_or("info").trim().to_string()
}

fn parse_bool(source: &ConfigSource, key: &str, default: bool) -> bool {
    source.get(key).map(|value| value.trim().eq_ignore_ascii_case("true")).unwrap_or(default)
}

fn parse_bool_with_fallback(
    source: &ConfigSource,
    key: &str,
    fallback_key: &str,
    default: bool,
) -> bool {
    source
        .get(key)
        .or_else(|| source.get(fallback_key))
        .map(|value| value.trim().eq_ignore_ascii_case("true"))
        .unwrap_or(default)
}

fn parse_env_int(
    source: &ConfigSource,
    key: &str,
    default: i64,
    minimum: Option<i64>,
    maximum: Option<i64>,
) -> Result<i64, ConfigError> {
    let raw = source.get(key).unwrap_or("");
    let raw = if raw.is_empty() { default.to_string() } else { raw.to_string() };
    let value = raw.trim().parse::<i64>().map_err(|_| {
        ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            format!("{key} must be an integer"),
        )
    })?;
    if minimum.is_some_and(|min| value < min) || maximum.is_some_and(|max| value > max) {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            format!("{key} out of range"),
        ));
    }
    Ok(value)
}

fn parse_env_usize(
    source: &ConfigSource,
    key: &str,
    default: usize,
    minimum: Option<usize>,
    maximum: Option<usize>,
) -> Result<usize, ConfigError> {
    let raw = source.get(key).unwrap_or("");
    let raw = if raw.is_empty() { default.to_string() } else { raw.to_string() };
    let value = raw.trim().parse::<usize>().map_err(|_| {
        ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            format!("{key} must be a non-negative integer"),
        )
    })?;
    if minimum.is_some_and(|min| value < min) || maximum.is_some_and(|max| value > max) {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidValue,
            Some(key.to_string()),
            format!("{key} out of range"),
        ));
    }
    Ok(value)
}

fn split_csv_set(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .collect()
}

/// Load deployment-owned target policy data from env/file.
///
/// `TARGET_POLICY_JSON` wins over `TARGET_POLICY_FILE`. If neither is present,
/// the policy is empty and every target is rejected by the exchange layer.
pub fn load_target_policy_from_env() -> Result<TargetPolicy, ConfigError> {
    load_target_policy_from_source(&ConfigSource::from_env())
}

fn load_target_policy_from_source(source: &ConfigSource) -> Result<TargetPolicy, ConfigError> {
    let raw = source.get("TARGET_POLICY_JSON").map(ToString::to_string).or_else(|| {
        source.get("TARGET_POLICY_FILE").and_then(|path| fs::read_to_string(path).ok())
    });

    let Some(raw) = raw else {
        return Ok(TargetPolicy::empty());
    };

    let parsed: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
        ConfigError::new(
            ConfigErrorKind::InvalidJson,
            Some("TARGET_POLICY_JSON".to_string()),
            format!("target policy JSON could not be parsed: {err}"),
        )
    })?;

    normalize_target_policy(&parsed)
}

fn normalize_target_policy(data: &serde_json::Value) -> Result<TargetPolicy, ConfigError> {
    let Some(map) = data.as_object() else {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidPolicy,
            Some("TARGET_POLICY_JSON".to_string()),
            "target policy must be a JSON object",
        ));
    };

    let mut targets = BTreeMap::new();
    for (aud, policy) in map {
        if aud.starts_with('_') {
            continue;
        }
        let Some(entry) = policy.as_object() else {
            return Err(ConfigError::new(
                ConfigErrorKind::InvalidPolicy,
                Some(aud.to_string()),
                "target policy entry must be an object",
            ));
        };
        let allowed_scopes = parse_scopes(aud, "allowed_scopes", entry.get("allowed_scopes"))?;
        let default_scopes = parse_scopes(aud, "default_scopes", entry.get("default_scopes"))?;
        targets.insert(aud.to_string(), TargetPolicyEntry { allowed_scopes, default_scopes });
    }

    Ok(TargetPolicy { targets })
}

fn normalize_impersonation_policy(
    data: &serde_json::Value,
) -> Result<ImpersonationPolicy, ConfigError> {
    let Some(map) = data.as_object() else {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidPolicy,
            Some("IMPERSONATION_POLICY_JSON".to_string()),
            "impersonation policy must be a JSON object",
        ));
    };

    let mut clients = BTreeMap::new();
    for (client_id, policy) in map {
        let Some(entry) = policy.as_object() else {
            return Err(ConfigError::new(
                ConfigErrorKind::InvalidPolicy,
                Some(client_id.to_string()),
                "impersonation policy entry must be an object",
            ));
        };
        let targets = parse_impersonation_selector(client_id, "targets", entry.get("targets"))?;
        let subjects = parse_impersonation_selector(client_id, "subjects", entry.get("subjects"))?;
        clients.insert(client_id.to_string(), ImpersonationPolicyEntry { targets, subjects });
    }
    Ok(ImpersonationPolicy { clients })
}

fn parse_impersonation_selector(
    client_id: &str,
    field: &str,
    value: Option<&serde_json::Value>,
) -> Result<ImpersonationSelector, ConfigError> {
    let Some(value) = value else {
        return Ok(ImpersonationSelector::Values(BTreeSet::new()));
    };
    if value.as_str() == Some("*") {
        return Ok(ImpersonationSelector::Any);
    }
    let Some(values) = value.as_array() else {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidPolicy,
            Some(client_id.to_string()),
            format!("impersonation policy {field} must be a JSON array of strings or \"*\""),
        ));
    };
    let mut parsed = BTreeSet::new();
    for item in values {
        let Some(item) = item.as_str() else {
            return Err(ConfigError::new(
                ConfigErrorKind::InvalidPolicy,
                Some(client_id.to_string()),
                format!("impersonation policy {field} must contain only strings"),
            ));
        };
        parsed.insert(item.to_string());
    }
    Ok(ImpersonationSelector::Values(parsed))
}

fn parse_scopes(
    aud: &str,
    key: &str,
    value: Option<&serde_json::Value>,
) -> Result<BTreeSet<String>, ConfigError> {
    let Some(value) = value else {
        return Ok(BTreeSet::new());
    };
    let Some(arr) = value.as_array() else {
        return Err(ConfigError::new(
            ConfigErrorKind::InvalidPolicy,
            Some(aud.to_string()),
            format!("{key} must be a JSON array of strings"),
        ));
    };
    let mut scopes = BTreeSet::new();
    for scope in arr {
        let Some(scope) = scope.as_str() else {
            return Err(ConfigError::new(
                ConfigErrorKind::InvalidPolicy,
                Some(aud.to_string()),
                format!("{key} must contain only strings"),
            ));
        };
        scopes.insert(scope.to_string());
    }
    Ok(scopes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_issuer_is_rejected() {
        let source = ConfigSource::from_pairs([
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
        ]);
        let err = require_issuer(&source).unwrap_err();
        assert_eq!(err.kind, ConfigErrorKind::MissingEnv);
    }

    #[test]
    fn target_policy_defaults_to_empty() {
        let source = ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
        ]);
        let policy = load_target_policy_from_source(&source).expect("policy");
        assert!(policy.targets.is_empty());
    }

    #[test]
    fn target_policy_rejects_scalar_scopes() {
        let source = ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
            (
                "TARGET_POLICY_JSON",
                r#"{"api://chat-mcp":{"allowed_scopes":"oops","default_scopes":[]}}"#,
            ),
        ]);
        let err = load_target_policy_from_source(&source).unwrap_err();
        assert_eq!(err.kind, ConfigErrorKind::InvalidPolicy);
    }

    #[test]
    fn impersonation_policy_parses_targets_and_subjects() {
        let source = ConfigSource::from_pairs([(
            "IMPERSONATION_POLICY_JSON",
            r#"{"chat-mcp":{"targets":["api://tool"],"subjects":["alice@example.com"]}}"#,
        )]);
        let policy = parse_impersonation_policy(&source).expect("policy");
        let entry = policy.clients.get("chat-mcp").expect("entry");
        assert!(entry.targets.allows("api://tool"));
        assert!(!entry.targets.allows("api://other"));
        assert!(entry.subjects.allows("alice@example.com"));
        assert!(!entry.subjects.allows("bob@example.com"));
    }

    #[test]
    fn impersonation_policy_parses_star_subjects() {
        let source = ConfigSource::from_pairs([(
            "IMPERSONATION_POLICY_JSON",
            r#"{"chat-mcp":{"targets":["api://tool"],"subjects":"*"}}"#,
        )]);
        let policy = parse_impersonation_policy(&source).expect("policy");
        let entry = policy.clients.get("chat-mcp").expect("entry");
        assert!(entry.targets.allows("api://tool"));
        assert!(entry.subjects.allows("anyone@example.com"));
    }

    #[test]
    fn impersonation_policy_rejects_invalid_entry_type() {
        let source =
            ConfigSource::from_pairs([("IMPERSONATION_POLICY_JSON", r#"{"chat-mcp":"bad"}"#)]);
        let err = parse_impersonation_policy(&source).unwrap_err();
        assert_eq!(err.kind, ConfigErrorKind::InvalidPolicy);
    }

    #[test]
    fn runtime_config_loads_a_minimal_valid_env() {
        let source = ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example/oauth2/default"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
            (
                "TARGET_POLICY_JSON",
                r#"{"api://chat-mcp":{"allowed_scopes":["chat.read"],"default_scopes":["chat.read"]}}"#,
            ),
        ]);
        let cfg = RuntimeConfig::from_source(&source).expect("config");
        assert_eq!(cfg.idp_issuer, "https://issuer.example/oauth2/default");
        assert!(cfg.expected_subject_aud.contains("api://obo"));
        assert_eq!(cfg.actor_id, "chat-mcp");
        assert_eq!(cfg.target_policy.targets.len(), 1);
        assert_eq!(cfg.client_ids.len(), 1);
        assert_eq!(cfg.our_kid, DEFAULT_KID);
        assert_eq!(cfg.sts_signing_provider, "file");
        assert!(cfg.sts_signing_public_jwks_file.is_none());
        assert!(cfg.mock_external_signer_key_file.is_none());
    }

    #[test]
    fn runtime_config_parses_external_signing_metadata() {
        let source = ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example/oauth2/default"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
            ("STS_SIGNING_PROVIDER", "mock-external"),
            ("STS_SIGNING_KID", "external-kid-1"),
            ("STS_SIGNING_PUBLIC_JWKS_FILE", "/run/sts/signing-public.json"),
            ("STS_MOCK_EXTERNAL_SIGNER_KEY_FILE", "/run/sts/mock-private.json"),
        ]);
        let cfg = RuntimeConfig::from_source(&source).expect("config");
        assert_eq!(cfg.sts_signing_provider, "mock-external");
        assert_eq!(cfg.our_kid, "external-kid-1");
        assert_eq!(
            cfg.sts_signing_public_jwks_file,
            Some(PathBuf::from("/run/sts/signing-public.json"))
        );
        assert_eq!(
            cfg.mock_external_signer_key_file,
            Some(PathBuf::from("/run/sts/mock-private.json"))
        );
    }

    fn minimal_source_with_sts_issuer(issuer: &str) -> ConfigSource {
        ConfigSource::from_pairs([
            ("IDP_ISSUER", "https://issuer.example/oauth2/default"),
            ("EXPECTED_SUBJECT_AUD", "api://obo"),
            ("ACTOR_IDS", "chat-mcp"),
            ("OBO_STS_ISSUER", issuer),
        ])
    }

    #[test]
    fn runtime_config_rejects_unsafe_sts_issuer_components() {
        for issuer in
            ["https://sts.example/?q=1", "https://sts.example#fragment", "http://sts.example"]
        {
            let err = RuntimeConfig::from_source(&minimal_source_with_sts_issuer(issuer))
                .expect_err("unsafe issuer must fail config load");
            assert_eq!(err.kind, ConfigErrorKind::InvalidValue);
            assert_eq!(err.key.as_deref(), Some("OBO_STS_ISSUER"));
        }
    }

    #[test]
    fn runtime_config_canonicalizes_https_and_loopback_http_sts_issuers() {
        for (raw, expected) in [
            ("https://sts.example/", "https://sts.example"),
            ("http://localhost:8888/", "http://localhost:8888"),
            ("http://127.0.0.1:9000/", "http://127.0.0.1:9000"),
            ("http://[::1]:9000/", "http://[::1]:9000"),
        ] {
            let cfg = RuntimeConfig::from_source(&minimal_source_with_sts_issuer(raw))
                .expect("safe issuer must load");
            assert_eq!(cfg.our_issuer, expected);
        }
    }
}
