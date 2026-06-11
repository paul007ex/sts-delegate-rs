#![forbid(unsafe_code)]

use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// Operator/runtime CLI for `sts-delegate-rs`.
#[derive(Debug, Parser)]
#[command(name = "sts-cli")]
#[command(about = "Operate and validate the Rust sts-delegate runtime")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Load runtime config and start the HTTP STS.
    Serve,
    /// Load runtime config, keys, trust anchors, and replay policy, then exit.
    BootstrapCheck,
    /// Run a local startup smoke check without hidden network access by default.
    Smoke(SmokeArgs),
    /// Inspect live-canary configuration without printing configured values.
    Canary {
        #[command(subcommand)]
        command: CanaryCommand,
    },
    /// Inspect public JWKS documents without printing private key material.
    Jwks {
        #[command(subcommand)]
        command: JwksCommand,
    },
    /// Inspect one public JWK without printing private key material.
    Key {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Debug, Args)]
struct SmokeArgs {
    /// Allow IdP JWKS retrieval over the network during bootstrap.
    #[arg(long)]
    allow_network: bool,
}

#[derive(Debug, Subcommand)]
enum CanaryCommand {
    /// Check required CANARY_* names and report only names/status.
    CheckConfig,
}

#[derive(Debug, Subcommand)]
enum JwksCommand {
    /// Inspect a public JWKS or single public JWK file.
    Inspect(InspectFileArgs),
}

#[derive(Debug, Subcommand)]
enum KeyCommand {
    /// Inspect exactly one public JWK from a file.
    Inspect(InspectFileArgs),
}

#[derive(Debug, Args)]
struct InspectFileArgs {
    /// Path to a public JWKS or public JWK JSON file.
    #[arg(long, value_name = "PATH")]
    file: PathBuf,
}

#[derive(Debug)]
struct CliError {
    code: i32,
    message: String,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self { code: 2, message: message.into() }
    }

    fn runtime(message: impl Into<String>) -> Self {
        Self { code: 1, message: message.into() }
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CliError {}

impl From<sts_http::BootstrapError> for CliError {
    fn from(value: sts_http::BootstrapError) -> Self {
        Self::runtime(value.to_string())
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(output) => print!("{output}"),
        Err(err) => {
            eprintln!("{err}");
            std::process::exit(err.code);
        }
    }
}

async fn run(cli: Cli) -> Result<String, CliError> {
    match cli.command {
        Command::Serve => {
            sts_http::serve_from_env().await?;
            Ok(String::new())
        }
        Command::BootstrapCheck => {
            sts_http::bootstrap_check_from_env().await?;
            Ok("bootstrap_status=ok\n".to_string())
        }
        Command::Smoke(args) => run_smoke(args).await,
        Command::Canary { command } => match command {
            CanaryCommand::CheckConfig => Ok(render_canary_config_status_from_env()),
        },
        Command::Jwks { command } => match command {
            JwksCommand::Inspect(args) => inspect_file(&args.file, InspectMode::Jwks),
        },
        Command::Key { command } => match command {
            KeyCommand::Inspect(args) => inspect_file(&args.file, InspectMode::SingleKey),
        },
    }
}

async fn run_smoke(args: SmokeArgs) -> Result<String, CliError> {
    if !args.allow_network && std::env::var_os("IDP_JWKS_FILE").is_none() {
        return Err(CliError::usage(
            "offline smoke requires IDP_JWKS_FILE; pass --allow-network to allow live IdP JWKS retrieval",
        ));
    }
    sts_http::bootstrap_check_from_env().await?;
    let network = if args.allow_network { "allowed" } else { "disabled" };
    Ok(format!("smoke_status=ok\nnetwork={network}\n"))
}

fn render_canary_config_status_from_env() -> String {
    let present = |key: &str| std::env::var_os(key).is_some_and(|value| !value.is_empty());
    render_canary_config_status(present)
}

fn render_canary_config_status<F>(present: F) -> String
where
    F: Fn(&str) -> bool,
{
    let mut missing = Vec::new();
    for name in [
        "CANARY_STS_BASE_URL",
        "CANARY_IDP_ISSUER",
        "CANARY_EXPECTED_SUBJECT_AUD",
        "CANARY_TARGET_AUDIENCE",
        "CANARY_TARGET_SCOPE",
        "CANARY_ACTOR_ID",
    ] {
        if !present(name) {
            missing.push(name.to_string());
        }
    }
    if !present("CANARY_SUBJECT_TOKEN") && !present("CANARY_SUBJECT_TOKEN_FILE") {
        missing.push("CANARY_SUBJECT_TOKEN or CANARY_SUBJECT_TOKEN_FILE".to_string());
    }
    if !present("CANARY_ACTOR_PRIVATE_JWK") && !present("CANARY_ACTOR_PRIVATE_JWK_FILE") {
        missing.push("CANARY_ACTOR_PRIVATE_JWK or CANARY_ACTOR_PRIVATE_JWK_FILE".to_string());
    }

    if missing.is_empty() {
        "canary_status=configured\nnetwork=disabled\n".to_string()
    } else {
        format!("canary_status=not_configured\nmissing={}\n", missing.join(","))
    }
}

#[derive(Clone, Copy)]
enum InspectMode {
    Jwks,
    SingleKey,
}

fn inspect_file(path: &Path, mode: InspectMode) -> Result<String, CliError> {
    let raw = fs::read_to_string(path)
        .map_err(|err| CliError::runtime(format!("failed to read {}: {err}", path.display())))?;
    inspect_json(&raw, mode)
}

fn inspect_json(raw: &str, mode: InspectMode) -> Result<String, CliError> {
    let value: serde_json::Value =
        serde_json::from_str(raw).map_err(|err| CliError::usage(format!("invalid JSON: {err}")))?;
    let keys = normalize_jwks_value(&value)?;
    if matches!(mode, InspectMode::SingleKey) && keys.len() != 1 {
        return Err(CliError::usage("key inspect requires exactly one public JWK"));
    }
    let inspected = inspect_public_keys(&keys)?;
    Ok(render_inspection(&inspected, mode))
}

fn normalize_jwks_value(
    value: &serde_json::Value,
) -> Result<Vec<&serde_json::Map<String, serde_json::Value>>, CliError> {
    let Some(object) = value.as_object() else {
        return Err(CliError::usage("JWK input must be a JSON object"));
    };
    let raw_keys = match object.get("keys") {
        Some(serde_json::Value::Array(keys)) => keys.iter().collect::<Vec<_>>(),
        Some(_) => return Err(CliError::usage("JWKS keys member must be an array")),
        None => vec![value],
    };
    if raw_keys.is_empty() {
        return Err(CliError::usage("JWKS contains no keys"));
    }
    let mut keys = Vec::with_capacity(raw_keys.len());
    for key in raw_keys {
        let Some(object) = key.as_object() else {
            return Err(CliError::usage("JWK entries must be JSON objects"));
        };
        keys.push(object);
    }
    Ok(keys)
}

#[derive(Debug, PartialEq, Eq)]
struct InspectedKey {
    index: usize,
    kid: Option<String>,
    kty: String,
    use_: Option<String>,
    alg: Option<String>,
    rsa_modulus_bits: Option<usize>,
}

fn inspect_public_keys(
    keys: &[&serde_json::Map<String, serde_json::Value>],
) -> Result<Vec<InspectedKey>, CliError> {
    let mut inspected = Vec::with_capacity(keys.len());
    for (index, key) in keys.iter().enumerate() {
        if key.keys().any(|member| PRIVATE_JWK_MEMBERS.contains(&member.as_str())) {
            return Err(CliError::usage(format!(
                "key[{index}] contains non-public key material; refusing to inspect private or symmetric JWK input"
            )));
        }
        let kty = required_string(key, "kty", index)?;
        let kid = optional_string(key, "kid", index)?;
        let use_ = optional_string(key, "use", index)?;
        let alg = optional_string(key, "alg", index)?;
        let rsa_modulus_bits =
            if kty == "RSA" { Some(rsa_modulus_bits_from_key(key, index)?) } else { None };
        inspected.push(InspectedKey { index, kid, kty, use_, alg, rsa_modulus_bits });
    }
    Ok(inspected)
}

fn required_string(
    key: &serde_json::Map<String, serde_json::Value>,
    member: &str,
    index: usize,
) -> Result<String, CliError> {
    optional_string(key, member, index)?
        .ok_or_else(|| CliError::usage(format!("key[{index}] missing required member {member}")))
}

fn optional_string(
    key: &serde_json::Map<String, serde_json::Value>,
    member: &str,
    index: usize,
) -> Result<Option<String>, CliError> {
    key.get(member)
        .map(|value| {
            value.as_str().map(ToString::to_string).ok_or_else(|| {
                CliError::usage(format!("key[{index}] member {member} must be a string"))
            })
        })
        .transpose()
}

fn rsa_modulus_bits_from_key(
    key: &serde_json::Map<String, serde_json::Value>,
    index: usize,
) -> Result<usize, CliError> {
    let n = required_string(key, "n", index)?;
    let e = required_string(key, "e", index)?;
    let modulus = decode_base64url_uint("n", &n, index)?;
    let exponent = decode_base64url_uint("e", &e, index)?;
    if exponent.is_empty() || exponent.iter().all(|octet| *octet == 0) {
        return Err(CliError::usage(format!("key[{index}] RSA exponent is invalid")));
    }
    if modulus.is_empty() || modulus.iter().all(|octet| *octet == 0) {
        return Err(CliError::usage(format!("key[{index}] RSA modulus is invalid")));
    }
    let leading_bits = 8 - modulus[0].leading_zeros() as usize;
    Ok((modulus.len() - 1) * 8 + leading_bits)
}

fn decode_base64url_uint(member: &str, value: &str, index: usize) -> Result<Vec<u8>, CliError> {
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| CliError::usage(format!("key[{index}] member {member} is not base64url")))
}

fn render_inspection(keys: &[InspectedKey], mode: InspectMode) -> String {
    let mut output = String::new();
    match mode {
        InspectMode::Jwks => {
            output.push_str("jwks_status=public\n");
            output.push_str(&format!("key_count={}\n", keys.len()));
        }
        InspectMode::SingleKey => {
            output.push_str("key_status=public\n");
        }
    }
    for key in keys {
        output.push_str(&format!("key[{}].kid={}\n", key.index, display_optional(&key.kid)));
        output.push_str(&format!("key[{}].kty={}\n", key.index, sanitize(&key.kty)));
        output.push_str(&format!("key[{}].use={}\n", key.index, display_optional(&key.use_)));
        output.push_str(&format!("key[{}].alg={}\n", key.index, display_optional(&key.alg)));
        if let Some(bits) = key.rsa_modulus_bits {
            output.push_str(&format!("key[{}].rsa_modulus_bits={bits}\n", key.index));
        }
    }
    output
}

fn display_optional(value: &Option<String>) -> String {
    value.as_deref().map(sanitize).unwrap_or_else(|| "(absent)".to_string())
}

fn sanitize(value: &str) -> String {
    const MAX_FIELD_LEN: usize = 120;
    let mut sanitized = String::new();
    for ch in value.chars().take(MAX_FIELD_LEN) {
        if ch.is_ascii_graphic() {
            sanitized.push(ch);
        } else {
            sanitized.push('?');
        }
    }
    if value.chars().count() > MAX_FIELD_LEN {
        sanitized.push_str("...");
    }
    sanitized
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn parser_accepts_explicit_jwks_inspect_command() {
        let cli = Cli::try_parse_from(["sts-cli", "jwks", "inspect", "--file", "jwks.json"])
            .expect("parse jwks inspect");

        match cli.command {
            Command::Jwks { command: JwksCommand::Inspect(args) } => {
                assert_eq!(args.file, PathBuf::from("jwks.json"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn canary_check_config_reports_missing_names_without_values() {
        let output = render_canary_config_status(|name| name == "CANARY_IDP_ISSUER");

        assert!(output.contains("canary_status=not_configured"));
        assert!(output.contains("CANARY_STS_BASE_URL"));
        assert!(output.contains("CANARY_SUBJECT_TOKEN or CANARY_SUBJECT_TOKEN_FILE"));
        assert!(!output.contains("https://"));
    }

    #[test]
    fn canary_check_config_reports_configured_without_values() {
        let present: BTreeSet<&str> = [
            "CANARY_STS_BASE_URL",
            "CANARY_IDP_ISSUER",
            "CANARY_EXPECTED_SUBJECT_AUD",
            "CANARY_TARGET_AUDIENCE",
            "CANARY_TARGET_SCOPE",
            "CANARY_ACTOR_ID",
            "CANARY_SUBJECT_TOKEN_FILE",
            "CANARY_ACTOR_PRIVATE_JWK_FILE",
        ]
        .into_iter()
        .collect();

        let output = render_canary_config_status(|name| present.contains(name));

        assert_eq!(output, "canary_status=configured\nnetwork=disabled\n");
    }

    #[test]
    fn jwks_inspection_rejects_non_public_key_material_without_printing_value() {
        let raw = format!(
            r#"{{"keys":[{{"kty":"RSA","kid":"public","n":"AQAB","e":"AQAB","{}":""}}]}}"#,
            PRIVATE_JWK_MEMBERS[0]
        );
        let err = inspect_json(&raw, InspectMode::Jwks).expect_err("private material must fail");

        assert_eq!(err.code, 2);
        assert!(err.message.contains("non-public key material"));
        assert!(!err.message.contains(PRIVATE_JWK_MEMBERS[0]));
    }

    #[test]
    fn jwks_inspection_prints_public_metadata_only() {
        let output = inspect_json(
            r#"{"keys":[{"kty":"RSA","kid":"kid-1","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}]}"#,
            InspectMode::Jwks,
        )
        .expect("public jwks");

        assert!(output.contains("jwks_status=public"));
        assert!(output.contains("key_count=1"));
        assert!(output.contains("key[0].kid=kid-1"));
        assert!(output.contains("key[0].rsa_modulus_bits=17"));
        assert!(!output.contains("\"n\""));
        assert!(!output.contains("AQAB"));
    }

    #[tokio::test]
    async fn key_inspect_command_reads_public_file() {
        let path = unique_temp_path("sts-cli-public-key.json");
        fs::write(
            &path,
            r#"{"kty":"RSA","kid":"kid-1","use":"sig","alg":"RS256","n":"AQAB","e":"AQAB"}"#,
        )
        .expect("write public key");

        let output = run(Cli {
            command: Command::Key {
                command: KeyCommand::Inspect(InspectFileArgs { file: path.clone() }),
            },
        })
        .await
        .expect("inspect public key");

        let _ = fs::remove_file(path);
        assert!(output.contains("key_status=public"));
        assert!(output.contains("key[0].kid=kid-1"));
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{nanos}-{name}"))
    }
}
