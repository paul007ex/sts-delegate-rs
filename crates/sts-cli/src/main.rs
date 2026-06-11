#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand};
use sts_jose::{JoseSigner, JwksDocument, PublicJwk, RsaJoseSigner, rsa_public_key_bits_from_jwk};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];

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
    /// Rotate a file-backed RSA private JWK and stage the old public key for overlap.
    Rotate(RotateArgs),
}

#[derive(Debug, Args)]
struct InspectFileArgs {
    /// Path to a public JWKS or public JWK JSON file.
    #[arg(long, value_name = "PATH")]
    file: PathBuf,
}

#[derive(Debug, Args)]
struct RotateArgs {
    /// Current RSA private JWK file. Defaults to OBO_STS_KEY_FILE or ./secrets/obo_sts_private_key.json.
    #[arg(long, value_name = "PATH")]
    key_file: Option<PathBuf>,
    /// Public overlap JWKS file. Defaults to OBO_STS_EXTRA_JWKS_FILE or a sibling retiring JWKS file.
    #[arg(long, value_name = "PATH")]
    extra_jwks_file: Option<PathBuf>,
    /// Validate the rotation plan without writing files or generating replacement key material.
    #[arg(long)]
    dry_run: bool,
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
            KeyCommand::Rotate(args) => rotate_signing_key(args),
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

fn rotate_signing_key(args: RotateArgs) -> Result<String, CliError> {
    let key_file = resolve_key_file(&args);
    let extra_jwks_file = resolve_extra_jwks_file(&args, &key_file);

    if args.dry_run {
        let current = load_current_signing_key(&key_file)?;
        let overlap = load_existing_overlap(&extra_jwks_file)?;
        return Ok(render_rotation_dry_run(&current, &overlap, &key_file, &extra_jwks_file));
    }

    let _lock = RotationLock::acquire(&key_file)?;
    let current = load_current_signing_key(&key_file)?;
    let generated = RsaJoseSigner::generate_private_jwk()
        .map_err(|err| CliError::runtime(format!("failed to generate replacement key: {err}")))?;
    let overlap = load_existing_overlap(&extra_jwks_file)?;
    let mut retained = Vec::new();
    for key in overlap {
        if key.kid != current.kid && key.kid != generated.public_jwk.kid {
            retained.push(key);
        }
    }
    retained.push(current.clone());
    let staged = JwksDocument::new(retained);

    atomic_write_json(&extra_jwks_file, &staged, 0o644)?;
    atomic_write_text(&key_file, &generated.private_jwk_json, 0o600)?;

    Ok(render_rotation_success(
        &current,
        &generated.public_jwk,
        staged.keys.len(),
        &key_file,
        &extra_jwks_file,
    ))
}

fn resolve_key_file(args: &RotateArgs) -> PathBuf {
    args.key_file.clone().unwrap_or_else(|| {
        std::env::var_os("OBO_STS_KEY_FILE").map(PathBuf::from).unwrap_or_else(|| {
            let secrets = std::env::var_os("STS_SECRETS_DIR")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from("./secrets"));
            secrets.join("obo_sts_private_key.json")
        })
    })
}

fn resolve_extra_jwks_file(args: &RotateArgs, key_file: &Path) -> PathBuf {
    args.extra_jwks_file.clone().unwrap_or_else(|| {
        std::env::var_os("OBO_STS_EXTRA_JWKS_FILE").map(PathBuf::from).unwrap_or_else(|| {
            key_file.parent().unwrap_or_else(|| Path::new(".")).join("obo_sts_retiring_jwks.json")
        })
    })
}

fn load_current_signing_key(path: &Path) -> Result<PublicJwk, CliError> {
    let raw = fs::read_to_string(path).map_err(|err| {
        CliError::runtime(format!("failed to read current signing key {}: {err}", path.display()))
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
        CliError::usage(format!(
            "current signing key {} must be an RSA private JWK JSON object: {err}",
            path.display()
        ))
    })?;
    let Some(object) = value.as_object() else {
        return Err(CliError::usage(format!(
            "current signing key {} must be an RSA private JWK JSON object",
            path.display()
        )));
    };
    if object.keys().any(|member| member == "k") || object.get("d").is_none() {
        return Err(CliError::usage(format!(
            "current signing key {} must be an RSA private JWK",
            path.display()
        )));
    }
    match object.get("kid").and_then(serde_json::Value::as_str) {
        Some(kid) if !kid.is_empty() => {}
        _ => {
            return Err(CliError::usage(format!(
                "current signing key {} must include a non-empty kid for overlap staging",
                path.display()
            )));
        }
    }

    let signer = RsaJoseSigner::from_private_jwk(&raw, "unused").map_err(|err| {
        CliError::usage(format!("current signing key {} is invalid: {err}", path.display()))
    })?;
    signer
        .public_jwks()
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| CliError::runtime("current signing key produced no public JWK"))
}

fn load_existing_overlap(path: &Path) -> Result<Vec<PublicJwk>, CliError> {
    let raw = match fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(CliError::runtime(format!(
                "failed to read overlap JWKS {}: {err}",
                path.display()
            )));
        }
    };
    parse_public_jwks_document(&raw, "overlap JWKS")
}

fn parse_public_jwks_document(raw: &str, label: &str) -> Result<Vec<PublicJwk>, CliError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| CliError::usage(format!("{label} is invalid JSON: {err}")))?;
    let keys = normalize_jwks_value(&value)?;
    inspect_public_keys(&keys)?;

    let mut public_keys = Vec::with_capacity(keys.len());
    for (index, key) in keys.into_iter().enumerate() {
        let jwk: PublicJwk = serde_json::from_value(serde_json::Value::Object(key.clone()))
            .map_err(|err| {
                CliError::usage(format!(
                    "{label} key[{index}] is not a valid RSA public JWK: {err}"
                ))
            })?;
        let bits = rsa_public_key_bits_from_jwk(&jwk).map_err(|err| {
            CliError::usage(format!("{label} key[{index}] is not a valid RSA public JWK: {err}"))
        })?;
        if bits < 2048 {
            return Err(CliError::usage(format!(
                "{label} key[{index}] RSA modulus must be at least 2048 bits"
            )));
        }
        public_keys.push(jwk);
    }
    Ok(public_keys)
}

fn render_rotation_dry_run(
    current: &PublicJwk,
    overlap: &[PublicJwk],
    key_file: &Path,
    extra_jwks_file: &Path,
) -> String {
    let retained = overlap.iter().filter(|key| key.kid != current.kid).count();
    format!(
        "rotate_status=dry_run\ncurrent_kid={}\nwould_stage_kid={}\nwould_overlap_keys={}\nprivate_key_file={}\noverlap_jwks_file={}\nrestart_required=true\n",
        sanitize(&current.kid),
        sanitize(&current.kid),
        retained + 1,
        sanitize_path(key_file),
        sanitize_path(extra_jwks_file),
    )
}

fn render_rotation_success(
    old: &PublicJwk,
    new: &PublicJwk,
    overlap_keys: usize,
    key_file: &Path,
    extra_jwks_file: &Path,
) -> String {
    format!(
        "rotate_status=rotated\nold_kid={}\nnew_kid={}\nprivate_key_file={}\nprivate_key_mode=0600\noverlap_jwks_file={}\noverlap_keys={overlap_keys}\nrestart_required=true\n",
        sanitize(&old.kid),
        sanitize(&new.kid),
        sanitize_path(key_file),
        sanitize_path(extra_jwks_file),
    )
}

fn atomic_write_json(path: &Path, value: &JwksDocument, mode: u32) -> Result<(), CliError> {
    let mut bytes = serde_json::to_vec_pretty(value)
        .map_err(|err| CliError::runtime(format!("failed to encode {}: {err}", path.display())))?;
    bytes.push(b'\n');
    atomic_write_bytes(path, &bytes, mode)
}

fn atomic_write_text(path: &Path, value: &str, mode: u32) -> Result<(), CliError> {
    atomic_write_bytes(path, value.as_bytes(), mode)
}

fn atomic_write_bytes(path: &Path, bytes: &[u8], mode: u32) -> Result<(), CliError> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| {
            CliError::runtime(format!("failed to create directory {}: {err}", parent.display()))
        })?;
    }
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let tmp_path = unique_temp_path_for(path);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(&tmp_path).map_err(|err| {
        CliError::runtime(format!("failed to create temp file {}: {err}", tmp_path.display()))
    })?;
    if let Err(err) = file.write_all(bytes).and_then(|_| file.sync_all()) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CliError::runtime(format!(
            "failed to write temp file {}: {err}",
            tmp_path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(err) = fs::set_permissions(&tmp_path, fs::Permissions::from_mode(mode)) {
            let _ = fs::remove_file(&tmp_path);
            return Err(CliError::runtime(format!(
                "failed to set permissions on {}: {err}",
                tmp_path.display()
            )));
        }
    }
    if let Err(err) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(CliError::runtime(format!(
            "failed to replace {} atomically: {err}",
            path.display()
        )));
    }
    let _ = File::open(parent).and_then(|dir| dir.sync_all());
    Ok(())
}

fn unique_temp_path_for(path: &Path) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let filename = path.file_name().and_then(|name| name.to_str()).unwrap_or("sts-key");
    path.parent().unwrap_or_else(|| Path::new(".")).join(format!(
        ".{filename}.{}.{}.tmp",
        std::process::id(),
        nanos
    ))
}

struct RotationLock {
    path: PathBuf,
}

impl RotationLock {
    fn acquire(key_file: &Path) -> Result<Self, CliError> {
        let mut lock_name = key_file.as_os_str().to_os_string();
        lock_name.push(".rotate.lock");
        let lock_path = PathBuf::from(lock_name);
        if let Some(parent) = lock_path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            fs::create_dir_all(parent).map_err(|err| {
                CliError::runtime(format!(
                    "failed to create lock directory {}: {err}",
                    parent.display()
                ))
            })?;
        }
        OpenOptions::new().write(true).create_new(true).open(&lock_path).map_err(|err| {
            CliError::runtime(format!(
                "failed to acquire rotation lock {}: {err}",
                lock_path.display()
            ))
        })?;
        Ok(Self { path: lock_path })
    }
}

impl Drop for RotationLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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

fn sanitize_path(path: &Path) -> String {
    sanitize(&path.display().to_string())
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
    fn parser_accepts_explicit_key_rotate_command() {
        let cli = Cli::try_parse_from([
            "sts-cli",
            "key",
            "rotate",
            "--key-file",
            "sts-key.json",
            "--extra-jwks-file",
            "retiring.json",
            "--dry-run",
        ])
        .expect("parse key rotate");

        match cli.command {
            Command::Key { command: KeyCommand::Rotate(args) } => {
                assert_eq!(args.key_file, Some(PathBuf::from("sts-key.json")));
                assert_eq!(args.extra_jwks_file, Some(PathBuf::from("retiring.json")));
                assert!(args.dry_run);
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

    #[tokio::test]
    async fn key_rotate_dry_run_validates_without_writing_files() {
        let dir = unique_temp_dir("sts-cli-rotate-dry-run");
        let key_file = dir.join("obo_sts_private_key.json");
        let overlap_file = dir.join("obo_sts_retiring_jwks.json");
        let (old_private, _) = private_jwk_with_kid("old-kid");
        fs::write(&key_file, &old_private).expect("write current key");

        let output = run(Cli {
            command: Command::Key {
                command: KeyCommand::Rotate(RotateArgs {
                    key_file: Some(key_file.clone()),
                    extra_jwks_file: Some(overlap_file.clone()),
                    dry_run: true,
                }),
            },
        })
        .await
        .expect("dry run");

        assert!(output.contains("rotate_status=dry_run"));
        assert!(output.contains("current_kid=old-kid"));
        assert!(output.contains("would_overlap_keys=1"));
        assert_eq!(fs::read_to_string(&key_file).expect("read current key"), old_private);
        assert!(!overlap_file.exists());
        assert!(!output.contains(r#""d""#));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn key_rotate_stages_old_public_key_before_replacing_private_key() {
        let dir = unique_temp_dir("sts-cli-rotate-success");
        let key_file = dir.join("obo_sts_private_key.json");
        let overlap_file = dir.join("obo_sts_retiring_jwks.json");
        let (old_private, old_public) = private_jwk_with_kid("old-kid");
        let (_, older_public) = private_jwk_with_kid("older-kid");
        fs::write(&key_file, old_private).expect("write current key");
        write_jwks(&overlap_file, vec![older_public.clone()]);

        let output = run(Cli {
            command: Command::Key {
                command: KeyCommand::Rotate(RotateArgs {
                    key_file: Some(key_file.clone()),
                    extra_jwks_file: Some(overlap_file.clone()),
                    dry_run: false,
                }),
            },
        })
        .await
        .expect("rotate");

        assert!(output.contains("rotate_status=rotated"));
        assert!(output.contains("old_kid=old-kid"));
        assert!(output.contains("overlap_keys=2"));
        assert!(!output.contains(r#""d""#));
        assert!(!output.contains("BEGIN PRIVATE KEY"));

        let new_private = fs::read_to_string(&key_file).expect("read new private key");
        let new_value: serde_json::Value =
            serde_json::from_str(&new_private).expect("new private key JSON");
        assert_ne!(new_value.get("kid").and_then(serde_json::Value::as_str), Some("old-kid"));
        assert!(new_value.get("d").is_some());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&key_file).expect("key metadata").permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&overlap_file).expect("overlap metadata").permissions().mode() & 0o777,
                0o644
            );
        }

        let overlap = read_jwks(&overlap_file);
        let kids: BTreeSet<String> = overlap.keys.iter().map(|key| key.kid.clone()).collect();
        assert_eq!(kids, BTreeSet::from(["older-kid".to_string(), "old-kid".to_string()]));
        let staged_old = overlap.keys.iter().find(|key| key.kid == "old-kid").expect("old key");
        assert_eq!(staged_old, &old_public);
        let raw_overlap = fs::read_to_string(&overlap_file).expect("read overlap");
        assert!(!raw_overlap.contains(r#""d""#));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn key_rotate_rejects_public_current_key_without_writing_overlap() {
        let dir = unique_temp_dir("sts-cli-rotate-public-current");
        let key_file = dir.join("obo_sts_private_key.json");
        let overlap_file = dir.join("obo_sts_retiring_jwks.json");
        let (_, old_public) = private_jwk_with_kid("public-only");
        fs::write(&key_file, serde_json::to_string(&old_public).expect("public jwk"))
            .expect("write public current key");

        let err = run(Cli {
            command: Command::Key {
                command: KeyCommand::Rotate(RotateArgs {
                    key_file: Some(key_file.clone()),
                    extra_jwks_file: Some(overlap_file.clone()),
                    dry_run: false,
                }),
            },
        })
        .await
        .expect_err("public key must fail");

        assert_eq!(err.code, 2);
        assert!(err.message.contains("must be an RSA private JWK"));
        assert!(!overlap_file.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn key_rotate_rejects_bad_overlap_without_replacing_private_key() {
        let dir = unique_temp_dir("sts-cli-rotate-bad-overlap");
        let key_file = dir.join("obo_sts_private_key.json");
        let overlap_file = dir.join("obo_sts_retiring_jwks.json");
        let (old_private, _) = private_jwk_with_kid("old-kid");
        fs::write(&key_file, &old_private).expect("write current key");
        fs::write(&overlap_file, "{not-json").expect("write bad overlap");

        let err = run(Cli {
            command: Command::Key {
                command: KeyCommand::Rotate(RotateArgs {
                    key_file: Some(key_file.clone()),
                    extra_jwks_file: Some(overlap_file.clone()),
                    dry_run: false,
                }),
            },
        })
        .await
        .expect_err("bad overlap must fail");

        assert_eq!(err.code, 2);
        assert!(err.message.contains("overlap JWKS is invalid JSON"));
        assert_eq!(fs::read_to_string(&key_file).expect("read current key"), old_private);
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn key_rotate_rejects_private_overlap_without_leaking_or_replacing_private_key() {
        let dir = unique_temp_dir("sts-cli-rotate-private-overlap");
        let key_file = dir.join("obo_sts_private_key.json");
        let overlap_file = dir.join("obo_sts_retiring_jwks.json");
        let (old_private, _) = private_jwk_with_kid("old-kid");
        let (_, overlap_public) = private_jwk_with_kid("retiring-kid");
        fs::write(&key_file, &old_private).expect("write current key");
        let mut overlap_private = serde_json::to_value(&overlap_public).expect("public value");
        overlap_private["d"] = serde_json::Value::String("do-not-print-this-secret".to_string());
        fs::write(&overlap_file, serde_json::json!({ "keys": [overlap_private] }).to_string())
            .expect("write private overlap");

        let err = run(Cli {
            command: Command::Key {
                command: KeyCommand::Rotate(RotateArgs {
                    key_file: Some(key_file.clone()),
                    extra_jwks_file: Some(overlap_file.clone()),
                    dry_run: false,
                }),
            },
        })
        .await
        .expect_err("private overlap must fail");

        assert_eq!(err.code, 2);
        assert!(err.message.contains("non-public key material"));
        assert!(!err.message.contains("do-not-print-this-secret"));
        assert_eq!(fs::read_to_string(&key_file).expect("read current key"), old_private);
        let _ = fs::remove_dir_all(dir);
    }

    fn private_jwk_with_kid(kid: &str) -> (String, PublicJwk) {
        let generated = RsaJoseSigner::generate_private_jwk().expect("generate key");
        let mut value: serde_json::Value =
            serde_json::from_str(&generated.private_jwk_json).expect("private jwk json");
        value["kid"] = serde_json::Value::String(kid.to_string());
        let private_jwk = format!("{}\n", serde_json::to_string_pretty(&value).expect("encode"));
        let signer =
            RsaJoseSigner::from_private_jwk(&private_jwk, "fallback").expect("parse private jwk");
        let public = signer.public_jwks().keys.into_iter().next().expect("public jwk");
        (private_jwk, public)
    }

    fn write_jwks(path: &Path, keys: Vec<PublicJwk>) {
        let jwks = JwksDocument::new(keys);
        fs::write(path, serde_json::to_string(&jwks).expect("jwks json")).expect("write jwks");
    }

    fn read_jwks(path: &Path) -> JwksDocument {
        serde_json::from_str(&fs::read_to_string(path).expect("read jwks")).expect("jwks")
    }

    fn unique_temp_dir(name: &str) -> PathBuf {
        let path = unique_temp_path(name);
        fs::create_dir_all(&path).expect("create temp dir");
        path
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        std::env::temp_dir().join(format!("{nanos}-{name}"))
    }
}
