#![forbid(unsafe_code)]

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use sha2::{Digest, Sha256};
use sts_dpop::{DpopHolderKey, DpopProofBuild, dpop_htu_for_request_uri, generate_dpop_jti};
use sts_jose::{
    JoseSigner, JwksDocument, PublicJwk, RsaJoseSigner, rsa_public_key_bits_from_jwk,
    verify_claims_against_jwks_with_header,
};
#[cfg(feature = "pqc-openssl-unstable")]
use sts_jose::{MlDsaAlgorithm, MlDsaJoseSigner};

const PRIVATE_JWK_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k", "priv"];
const TOKEN_EXCHANGE_GRANT_TYPE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const JWT_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:jwt";
const CLIENT_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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
    /// Manage DPoP holder keys for sender-constrained token exchange.
    Dpop {
        #[command(subcommand)]
        command: DpopCommand,
    },
    /// Inspect PQC backend readiness without printing key or token material.
    Pqc {
        #[command(subcommand)]
        command: PqcCommand,
    },
    /// Verify a minted compact JWT against a public JWKS and print safe claims.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Call the STS token endpoint with a redacted RFC 8693 token exchange request.
    Exchange(Box<ExchangeArgs>),
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

#[derive(Debug, Subcommand)]
enum DpopCommand {
    /// Manage DPoP holder keys.
    Key {
        #[command(subcommand)]
        command: DpopKeyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum DpopKeyCommand {
    /// Generate a private P-256 DPoP holder JWK without printing private material.
    Generate(DpopKeyGenerateArgs),
}

#[derive(Debug, Subcommand)]
enum PqcCommand {
    /// Check compiled feature status and ML-DSA sign/verify availability.
    Preflight,
    /// Manage ML-DSA signing keys for the experimental PQC backend.
    Key {
        #[command(subcommand)]
        command: PqcKeyCommand,
    },
}

#[derive(Debug, Subcommand)]
enum PqcKeyCommand {
    /// Generate an ML-DSA private AKP JWK and optional public JWKS.
    Generate(PqcKeyGenerateArgs),
    /// Inspect one ML-DSA AKP key or JWKS without printing private material.
    Inspect(InspectFileArgs),
    /// Rotate a file-backed ML-DSA private AKP JWK and stage overlap JWKS.
    Rotate(PqcKeyRotateArgs),
}

#[derive(Debug, Subcommand)]
enum TokenCommand {
    /// Verify a compact JWT against a public JWKS.
    Verify(TokenVerifyArgs),
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

#[derive(Debug, Args)]
struct DpopKeyGenerateArgs {
    /// Output path for the private DPoP holder JWK. The file must not already exist.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
}

#[derive(Debug, Args)]
struct PqcKeyGenerateArgs {
    /// ML-DSA JOSE algorithm: ML-DSA-44, ML-DSA-65, or ML-DSA-87.
    #[arg(long, default_value = "ML-DSA-65")]
    alg: String,
    /// Optional key id. Defaults to the RFC 9964 AKP thumbprint.
    #[arg(long)]
    kid: Option<String>,
    /// Output path for the private AKP JWK. The file must not already exist unless --force is used.
    #[arg(long, value_name = "PATH")]
    out: PathBuf,
    /// Optional output path for the public JWKS.
    #[arg(long, value_name = "PATH")]
    public_jwks_out: Option<PathBuf>,
    /// Replace existing output files.
    #[arg(long)]
    force: bool,
}

#[derive(Debug, Args)]
struct PqcKeyRotateArgs {
    /// Current ML-DSA private AKP JWK file.
    #[arg(long, value_name = "PATH")]
    key_file: PathBuf,
    /// Public overlap JWKS file.
    #[arg(long, value_name = "PATH")]
    extra_jwks_file: PathBuf,
    /// Optional replacement key id. Defaults to the RFC 9964 AKP thumbprint.
    #[arg(long)]
    kid: Option<String>,
    /// Validate the rotation plan without writing files or generating replacement key material.
    #[arg(long)]
    dry_run: bool,
}

#[derive(Debug, Args)]
struct TokenVerifyArgs {
    /// File containing the compact JWT to verify. The token is never printed.
    #[arg(long, value_name = "PATH")]
    token_file: PathBuf,
    /// Public JWKS file used to verify the compact JWT.
    #[arg(long, value_name = "PATH", conflicts_with = "jwks_url")]
    jwks_file: Option<PathBuf>,
    /// Public JWKS URL used to verify the compact JWT.
    #[arg(long, value_name = "URL", conflicts_with = "jwks_file")]
    jwks_url: Option<String>,
    /// Output style. All styles redact the compact token.
    #[arg(long, value_enum, default_value = "redacted")]
    output: ExchangeOutputFormat,
}

#[derive(Debug, Args)]
struct ExchangeArgs {
    /// STS issuer/base URL; the token endpoint is derived by appending /token.
    #[arg(long, value_name = "URL", conflicts_with = "token_endpoint")]
    sts_url: Option<String>,
    /// Exact token endpoint URL to call instead of deriving from --sts-url.
    #[arg(long, value_name = "URL", conflicts_with = "sts_url")]
    token_endpoint: Option<String>,
    /// File containing the subject token. The token is never printed by default.
    #[arg(long, value_name = "PATH")]
    subject_token_file: PathBuf,
    /// Subject token type URN.
    #[arg(long, default_value = ACCESS_TOKEN_TYPE)]
    subject_token_type: String,
    /// File containing the actor token for delegation mode.
    #[arg(long, value_name = "PATH")]
    actor_token_file: Option<PathBuf>,
    /// Actor token type URN. Sent only when --actor-token-file is present.
    #[arg(long, default_value = JWT_TOKEN_TYPE)]
    actor_token_type: String,
    /// File containing a private_key_jwt client assertion.
    #[arg(long, value_name = "PATH")]
    client_assertion_file: Option<PathBuf>,
    /// Client assertion type URN. Sent only when --client-assertion-file is present.
    #[arg(long, default_value = CLIENT_ASSERTION_TYPE)]
    client_assertion_type: String,
    /// Optional OAuth client_id to send alongside a client assertion.
    #[arg(long)]
    client_id: Option<String>,
    /// Target audience. May be repeated.
    #[arg(long, value_name = "AUDIENCE")]
    audience: Vec<String>,
    /// Target resource URI. May be repeated.
    #[arg(long, value_name = "URI")]
    resource: Vec<String>,
    /// Requested downscoped scope string.
    #[arg(long)]
    scope: Option<String>,
    /// Requested token type URN.
    #[arg(long)]
    requested_token_type: Option<String>,
    /// File containing a precomputed DPoP proof JWT to send in the DPoP header.
    #[arg(long, value_name = "PATH", conflicts_with = "dpop_key_file")]
    dpop_proof_file: Option<PathBuf>,
    /// Private DPoP holder JWK used to generate a fresh token-endpoint proof.
    #[arg(long, value_name = "PATH", conflicts_with = "dpop_proof_file")]
    dpop_key_file: Option<PathBuf>,
    /// Public JWKS file used to verify the minted JWT before printing claims.
    #[arg(long, value_name = "PATH", conflicts_with = "jwks_url")]
    jwks_file: Option<PathBuf>,
    /// Public JWKS URL used to verify the minted JWT before printing claims.
    #[arg(long, value_name = "URL", conflicts_with = "jwks_file")]
    jwks_url: Option<String>,
    /// Output style. All styles redact submitted tokens by default.
    #[arg(long, value_enum, default_value = "redacted")]
    output: ExchangeOutputFormat,
    /// Print the minted access token. This is intentionally off by default.
    #[arg(long)]
    print_token: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ExchangeOutputFormat {
    Redacted,
    Claims,
    Json,
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
        Command::Dpop { command } => match command {
            DpopCommand::Key { command } => match command {
                DpopKeyCommand::Generate(args) => generate_dpop_key(args),
            },
        },
        Command::Pqc { command } => match command {
            PqcCommand::Preflight => run_pqc_preflight(),
            PqcCommand::Key { command } => match command {
                PqcKeyCommand::Generate(args) => generate_pqc_key(args),
                PqcKeyCommand::Inspect(args) => inspect_pqc_key(&args.file),
                PqcKeyCommand::Rotate(args) => rotate_pqc_key(args),
            },
        },
        Command::Token { command } => match command {
            TokenCommand::Verify(args) => verify_token(args).await,
        },
        Command::Exchange(args) => run_exchange(*args).await,
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

fn generate_dpop_key(args: DpopKeyGenerateArgs) -> Result<String, CliError> {
    let generated = DpopHolderKey::generate_private_jwk()
        .map_err(|err| CliError::runtime(format!("failed to generate DPoP holder key: {err}")))?;
    write_new_secret_text(&args.out, &generated.private_jwk_json, 0o600)?;
    Ok(format!(
        "dpop_key_status=generated\nprivate_key_file={}\nprivate_key_mode=0600\nalg=ES256\ncrv=P-256\njkt_sha256_prefix={}\n",
        sanitize_path(&args.out),
        sha256_hex_prefix(&generated.public_jkt),
    ))
}

fn run_pqc_preflight() -> Result<String, CliError> {
    let selected_alg = std::env::var("STS_SIGNING_ALG")
        .ok()
        .map(|value| sanitize(value.trim()))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "RS256(default)".to_string());
    let mut lines = vec![
        "pqc_preflight_status=ok".to_string(),
        format!("selected_sts_signing_alg={selected_alg}"),
    ];

    match sts_jose::openssl_version_text() {
        Some(version) => {
            lines.push("pqc_openssl_feature_enabled=true".to_string());
            lines.push(format!("openssl_version={}", sanitize(&version)));
        }
        None => {
            lines.push("pqc_openssl_feature_enabled=false".to_string());
            lines.push("openssl_version=not_compiled".to_string());
            lines.push("mldsa_sign_verify=not_compiled".to_string());
            lines.push(String::new());
            return Ok(lines.join("\n"));
        }
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    {
        for (algorithm, seed) in [
            (sts_jose::MlDsaAlgorithm::MlDsa44, [44_u8; 32]),
            (sts_jose::MlDsaAlgorithm::MlDsa65, [65_u8; 32]),
            (sts_jose::MlDsaAlgorithm::MlDsa87, [87_u8; 32]),
        ] {
            let result = (|| -> Result<(), String> {
                let signer = sts_jose::MlDsaJoseSigner::from_seed_for_tests(
                    algorithm,
                    seed,
                    "pqc-preflight",
                )
                .map_err(|err| sanitize_oauth_text(&err.to_string()))?;
                let token = signer
                    .sign_json_claims(&serde_json::json!({
                        "iss": "urn:sts-delegate-rs:pqc-preflight",
                        "sub": "preflight",
                        "aud": "urn:sts-delegate-rs:pqc-preflight",
                        "iat": 1,
                        "exp": 2
                    }))
                    .map_err(|err| sanitize_oauth_text(&err.to_string()))?;
                verify_claims_against_jwks_with_header::<serde_json::Value>(
                    &token,
                    &signer.public_jwks(),
                )
                .map_err(|err| sanitize_oauth_text(&err.to_string()))?;
                Ok(())
            })();
            match result {
                Ok(()) => lines.push(format!("{}_sign_verify=ok", algorithm.jose_alg())),
                Err(err) => {
                    lines.push(format!("{}_sign_verify=fail", algorithm.jose_alg()));
                    return Err(CliError::runtime(format!(
                        "PQC preflight failed for {}: {err}",
                        algorithm.jose_alg()
                    )));
                }
            }
        }
    }

    lines.push(String::new());
    Ok(lines.join("\n"))
}

#[cfg(feature = "pqc-openssl-unstable")]
fn parse_mldsa_algorithm(value: &str) -> Result<MlDsaAlgorithm, CliError> {
    MlDsaAlgorithm::from_jose_alg(value)
        .or_else(|| MlDsaAlgorithm::from_selector(value))
        .ok_or_else(|| CliError::usage("PQC algorithm must be ML-DSA-44, ML-DSA-65, or ML-DSA-87"))
}

fn generate_pqc_key(args: PqcKeyGenerateArgs) -> Result<String, CliError> {
    #[cfg(not(feature = "pqc-openssl-unstable"))]
    {
        let _ = args;
        Err(CliError::runtime("pqc key generate requires the pqc-openssl-unstable feature"))
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    {
        let algorithm = parse_mldsa_algorithm(&args.alg)?;
        let generated = MlDsaJoseSigner::generate_private_jwk(algorithm, args.kid.as_deref())
            .map_err(|err| CliError::runtime(format!("failed to generate ML-DSA key: {err}")))?;
        write_secret_text(&args.out, &generated.private_jwk_json, 0o600, args.force)?;
        if let Some(path) = &args.public_jwks_out {
            atomic_write_json_if_allowed(
                path,
                &JwksDocument::new(vec![generated.public_jwk.clone()]),
                0o644,
                args.force,
            )?;
        }
        Ok(format!(
            "pqc_key_status=generated\nprivate_key_file={}\nprivate_key_mode=0600\nalg={}\nkty=AKP\nkid={}\npublic_key_sha256_prefix={}\npublic_jwks_file={}\n",
            sanitize_path(&args.out),
            generated.public_jwk.alg,
            sanitize(&generated.public_jwk.kid),
            akp_public_sha256_prefix(&generated.public_jwk)?,
            args.public_jwks_out
                .as_deref()
                .map(sanitize_path)
                .unwrap_or_else(|| "(not-written)".to_string()),
        ))
    }
}

fn inspect_pqc_key(path: &Path) -> Result<String, CliError> {
    let raw = fs::read_to_string(path).map_err(|err| {
        CliError::runtime(format!("failed to read PQC key file {}: {err}", sanitize_path(path)))
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw)
        .map_err(|err| CliError::usage(format!("PQC key file is invalid JSON: {err}")))?;
    if value.get("priv").is_some() {
        return inspect_pqc_private_key(&raw);
    }
    let keys = normalize_jwks_value(&value)?;
    let inspected = inspect_public_keys(&keys)?;
    Ok(render_inspection(&inspected, InspectMode::Jwks))
}

fn inspect_pqc_private_key(raw: &str) -> Result<String, CliError> {
    #[cfg(not(feature = "pqc-openssl-unstable"))]
    {
        let _ = raw;
        Err(CliError::runtime(
            "pqc key inspect for private AKP JWK requires the pqc-openssl-unstable feature",
        ))
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    {
        let value: serde_json::Value = serde_json::from_str(raw)
            .map_err(|err| CliError::usage(format!("PQC private key JSON is invalid: {err}")))?;
        let alg = value
            .get("alg")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| CliError::usage("PQC private key missing alg"))?;
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &sts_jose::BackendSelection::parse(alg),
            raw,
            "",
        )
        .map_err(|err| CliError::usage(format!("PQC private key is invalid: {err}")))?;
        let public = signer.public_jwks().keys[0].clone();
        Ok(format!(
            "pqc_key_status=private-valid\nalg={}\nkty=AKP\nkid={}\npublic_key_bytes={}\npublic_key_sha256_prefix={}\nprivate_material=redacted\n",
            public.alg,
            sanitize(&public.kid),
            akp_public_bytes(&public)?,
            akp_public_sha256_prefix(&public)?,
        ))
    }
}

fn rotate_pqc_key(args: PqcKeyRotateArgs) -> Result<String, CliError> {
    #[cfg(not(feature = "pqc-openssl-unstable"))]
    {
        let _ = args;
        Err(CliError::runtime("pqc key rotate requires the pqc-openssl-unstable feature"))
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    {
        let current = load_current_pqc_signing_key(&args.key_file)?;
        let overlap = load_existing_overlap(&args.extra_jwks_file)?;
        if args.dry_run {
            return Ok(format!(
                "pqc_rotate_status=dry_run\ncurrent_kid={}\ncurrent_alg={}\nwould_stage_kid={}\nwould_overlap_keys={}\nprivate_key_file={}\noverlap_jwks_file={}\nrestart_required=true\n",
                sanitize(&current.kid),
                current.alg,
                sanitize(&current.kid),
                overlap.iter().filter(|key| key.kid != current.kid).count() + 1,
                sanitize_path(&args.key_file),
                sanitize_path(&args.extra_jwks_file),
            ));
        }

        let _lock = RotationLock::acquire(&args.key_file)?;
        let algorithm = parse_mldsa_algorithm(&current.alg)?;
        let generated = MlDsaJoseSigner::generate_private_jwk(algorithm, args.kid.as_deref())
            .map_err(|err| {
                CliError::runtime(format!("failed to generate replacement ML-DSA key: {err}"))
            })?;
        let mut retained = vec![current.clone()];
        for key in overlap {
            if key.kid != current.kid && key.kid != generated.public_jwk.kid {
                retained.push(key);
            }
        }
        atomic_write_json(&args.extra_jwks_file, &JwksDocument::new(retained), 0o644)?;
        atomic_write_text(&args.key_file, &generated.private_jwk_json, 0o600)?;
        Ok(format!(
            "pqc_rotate_status=rotated\nold_kid={}\nnew_kid={}\nalg={}\nprivate_key_file={}\nprivate_key_mode=0600\noverlap_jwks_file={}\nrestart_required=true\n",
            sanitize(&current.kid),
            sanitize(&generated.public_jwk.kid),
            generated.public_jwk.alg,
            sanitize_path(&args.key_file),
            sanitize_path(&args.extra_jwks_file),
        ))
    }
}

async fn verify_token(args: TokenVerifyArgs) -> Result<String, CliError> {
    let token = read_secret_file(&args.token_file, "token")?;
    let client = reqwest::Client::new();
    let (jwks, source) =
        load_jwks_for_verification(args.jwks_file.as_deref(), args.jwks_url.as_deref(), &client)
            .await?;
    let verified = verify_claims_against_jwks_with_header::<serde_json::Value>(&token, &jwks)
        .map_err(|err| {
            CliError::runtime(format!(
                "token verification failed: {}",
                sanitize_oauth_text(&err.to_string())
            ))
        })?;
    let mut safe = serde_json::Map::new();
    safe.insert("token_verify_status".to_string(), serde_json::json!("ok"));
    safe.insert(
        "access_token_sha256_prefix".to_string(),
        serde_json::json!(sha256_hex_prefix(&token)),
    );
    safe.insert("jwt_signature_verified".to_string(), serde_json::json!(true));
    safe.insert("jwt_verification_source".to_string(), serde_json::json!(source));
    safe.insert("jwt_header_alg".to_string(), serde_json::json!(sanitize(&verified.alg)));
    safe.insert("jwt_header_kid".to_string(), serde_json::json!(sanitize(&verified.kid)));
    safe.insert("claims".to_string(), safe_claims_summary(&verified.claims));

    match args.output {
        ExchangeOutputFormat::Redacted => Ok(render_token_verify_map_lines(&safe)),
        ExchangeOutputFormat::Claims => {
            let mut output = serde_json::to_string_pretty(
                safe.get("claims").unwrap_or(&serde_json::Value::Object(safe.clone())),
            )
            .unwrap_or_else(|_| "{}".to_string());
            output.push('\n');
            Ok(output)
        }
        ExchangeOutputFormat::Json => {
            let mut output = serde_json::to_string_pretty(&serde_json::Value::Object(safe))
                .unwrap_or_else(|_| "{}".to_string());
            output.push('\n');
            Ok(output)
        }
    }
}

struct ExchangeHttpRequest {
    token_endpoint: String,
    body: String,
    dpop_proof: Option<String>,
    dpop_jkt: Option<String>,
}

async fn run_exchange(args: ExchangeArgs) -> Result<String, CliError> {
    let request = build_exchange_http_request(&args)?;
    let client = reqwest::Client::new();
    let mut builder = client
        .post(&request.token_endpoint)
        .header(reqwest::header::ACCEPT, "application/json")
        .header(reqwest::header::CONTENT_TYPE, "application/x-www-form-urlencoded; charset=utf-8")
        .body(request.body);
    if let Some(proof) = &request.dpop_proof {
        builder = builder.header("DPoP", proof);
    }

    let response = builder.send().await.map_err(|err| {
        CliError::runtime(format!(
            "exchange request failed: {}",
            sanitize_oauth_text(&err.to_string())
        ))
    })?;
    let status = response.status();
    let response_text = response.text().await.map_err(|err| {
        CliError::runtime(format!(
            "failed to read exchange response body: {}",
            sanitize_oauth_text(&err.to_string())
        ))
    })?;
    let response_body: serde_json::Value = serde_json::from_str(&response_text).map_err(|err| {
        CliError::runtime(format!(
            "exchange response was not JSON\nhttp_status={}\nparse_error={}",
            status.as_u16(),
            sanitize_oauth_text(&err.to_string())
        ))
    })?;

    if !status.is_success() {
        return Err(CliError::runtime(render_exchange_error(
            &args,
            status.as_u16(),
            &response_body,
        )));
    }

    render_exchange_success(
        &args,
        status.as_u16(),
        response_body,
        request.dpop_jkt.as_deref(),
        &client,
    )
    .await
}

fn build_exchange_http_request(args: &ExchangeArgs) -> Result<ExchangeHttpRequest, CliError> {
    let token_endpoint = resolve_token_endpoint(args)?;
    let subject_token = read_secret_file(&args.subject_token_file, "subject token")?;
    let actor_token = args
        .actor_token_file
        .as_deref()
        .map(|path| read_secret_file(path, "actor token"))
        .transpose()?;
    let client_assertion = args
        .client_assertion_file
        .as_deref()
        .map(|path| read_secret_file(path, "client assertion"))
        .transpose()?;
    let dpop_proof = args
        .dpop_proof_file
        .as_deref()
        .map(|path| read_secret_file(path, "DPoP proof"))
        .transpose()?;
    let (dpop_proof, dpop_jkt) = if let Some(path) = &args.dpop_key_file {
        let raw = read_secret_file(path, "DPoP holder key")?;
        let key = DpopHolderKey::from_private_jwk(&raw)
            .map_err(|err| CliError::usage(format!("invalid DPoP holder key: {err}")))?;
        let htu = dpop_htu_for_request_uri(&token_endpoint)
            .map_err(|err| CliError::usage(format!("invalid DPoP token endpoint: {err}")))?;
        let proof = key
            .sign_proof(DpopProofBuild {
                htm: "POST".to_string(),
                htu,
                iat: unix_timestamp_now()?,
                jti: generate_dpop_jti(),
            })
            .map_err(|err| CliError::runtime(format!("failed to sign DPoP proof: {err}")))?;
        (Some(proof), Some(key.public_jkt().to_string()))
    } else {
        (dpop_proof, None)
    };

    let mut form = Vec::new();
    push_form_param(&mut form, "grant_type", TOKEN_EXCHANGE_GRANT_TYPE)?;
    push_form_param(&mut form, "subject_token", &subject_token)?;
    push_form_param(&mut form, "subject_token_type", &args.subject_token_type)?;
    if let Some(actor_token) = actor_token {
        push_form_param(&mut form, "actor_token", &actor_token)?;
        push_form_param(&mut form, "actor_token_type", &args.actor_token_type)?;
    }
    if let Some(client_assertion) = client_assertion {
        push_form_param(&mut form, "client_assertion", &client_assertion)?;
        push_form_param(&mut form, "client_assertion_type", &args.client_assertion_type)?;
    }
    if let Some(client_id) = &args.client_id {
        push_form_param(&mut form, "client_id", client_id)?;
    }
    for audience in &args.audience {
        push_form_param(&mut form, "audience", audience)?;
    }
    for resource in &args.resource {
        push_form_param(&mut form, "resource", resource)?;
    }
    if let Some(scope) = &args.scope {
        push_form_param(&mut form, "scope", scope)?;
    }
    if let Some(requested_token_type) = &args.requested_token_type {
        push_form_param(&mut form, "requested_token_type", requested_token_type)?;
    }

    let body = serde_urlencoded::to_string(&form)
        .map_err(|err| CliError::runtime(format!("failed to encode exchange form: {err}")))?;
    Ok(ExchangeHttpRequest { token_endpoint, body, dpop_proof, dpop_jkt })
}

fn resolve_token_endpoint(args: &ExchangeArgs) -> Result<String, CliError> {
    let endpoint = if let Some(token_endpoint) = &args.token_endpoint {
        token_endpoint.trim().to_string()
    } else if let Some(sts_url) = &args.sts_url {
        format!("{}/token", sts_url.trim().trim_end_matches('/'))
    } else {
        return Err(CliError::usage("exchange requires --sts-url or --token-endpoint"));
    };
    if endpoint.is_empty() {
        return Err(CliError::usage("exchange token endpoint must not be empty"));
    }
    if !endpoint.starts_with("https://") && !endpoint.starts_with("http://") {
        return Err(CliError::usage("exchange token endpoint must be an http or https URL"));
    }
    Ok(endpoint)
}

fn read_secret_file(path: &Path, label: &str) -> Result<String, CliError> {
    let raw = fs::read_to_string(path).map_err(|err| {
        CliError::runtime(format!("failed to read {label} file {}: {err}", sanitize_path(path)))
    })?;
    let value = raw.trim();
    if value.is_empty() {
        return Err(CliError::usage(format!("{label} file {} is empty", sanitize_path(path))));
    }
    Ok(value.to_string())
}

fn write_new_secret_text(path: &Path, value: &str, mode: u32) -> Result<(), CliError> {
    if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
        fs::create_dir_all(parent).map_err(|err| {
            CliError::runtime(format!("failed to create directory {}: {err}", parent.display()))
        })?;
    }
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(mode);
    }
    let mut file = options.open(path).map_err(|err| {
        CliError::runtime(format!("failed to create secret file {}: {err}", sanitize_path(path)))
    })?;
    file.write_all(value.as_bytes()).and_then(|_| file.sync_all()).map_err(|err| {
        CliError::runtime(format!("failed to write secret file {}: {err}", sanitize_path(path)))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).map_err(|err| {
            CliError::runtime(format!(
                "failed to set permissions on secret file {}: {err}",
                sanitize_path(path)
            ))
        })?;
    }
    Ok(())
}

#[cfg(feature = "pqc-openssl-unstable")]
fn write_secret_text(path: &Path, value: &str, mode: u32, force: bool) -> Result<(), CliError> {
    if force {
        atomic_write_text(path, value, mode)
    } else {
        write_new_secret_text(path, value, mode)
    }
}

#[cfg(feature = "pqc-openssl-unstable")]
fn atomic_write_json_if_allowed(
    path: &Path,
    value: &JwksDocument,
    mode: u32,
    force: bool,
) -> Result<(), CliError> {
    if !force && path.exists() {
        return Err(CliError::runtime(format!(
            "refusing to replace existing file {}; pass --force to overwrite",
            sanitize_path(path)
        )));
    }
    atomic_write_json(path, value, mode)
}

fn unix_timestamp_now() -> Result<i64, CliError> {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|err| CliError::runtime(format!("system clock is before Unix epoch: {err}")))?
        .as_secs();
    i64::try_from(seconds)
        .map_err(|_| CliError::runtime("system time exceeds supported JWT timestamp range"))
}

fn push_form_param(
    form: &mut Vec<(String, String)>,
    name: &str,
    value: &str,
) -> Result<(), CliError> {
    if value.trim().is_empty() {
        return Err(CliError::usage(format!("exchange parameter {name} must not be empty")));
    }
    form.push((name.to_string(), value.to_string()));
    Ok(())
}

fn render_exchange_error(
    args: &ExchangeArgs,
    http_status: u16,
    body: &serde_json::Value,
) -> String {
    let oauth_error = body
        .get("error")
        .and_then(serde_json::Value::as_str)
        .map(sanitize_oauth_text)
        .unwrap_or_else(|| "oauth_error".to_string());
    let description =
        body.get("error_description").and_then(serde_json::Value::as_str).map(sanitize_oauth_text);

    let mut safe = serde_json::Map::new();
    safe.insert("exchange_status".to_string(), serde_json::json!("error"));
    safe.insert("http_status".to_string(), serde_json::json!(http_status));
    safe.insert("error".to_string(), serde_json::json!(oauth_error));
    if let Some(description) = description {
        safe.insert("error_description".to_string(), serde_json::json!(description));
    }

    match args.output {
        ExchangeOutputFormat::Redacted => render_exchange_map_lines(&safe, None),
        ExchangeOutputFormat::Claims | ExchangeOutputFormat::Json => {
            let mut output = serde_json::to_string_pretty(&serde_json::Value::Object(safe))
                .unwrap_or_else(|_| "{\"exchange_status\":\"error\"}".to_string());
            output.push('\n');
            output
        }
    }
}

async fn render_exchange_success(
    args: &ExchangeArgs,
    http_status: u16,
    body: serde_json::Value,
    expected_dpop_jkt: Option<&str>,
    client: &reqwest::Client,
) -> Result<String, CliError> {
    let access_token =
        body.get("access_token").and_then(serde_json::Value::as_str).ok_or_else(|| {
            CliError::runtime("exchange response missing access_token; refusing to print raw body")
        })?;
    let token_type = body
        .get("token_type")
        .and_then(serde_json::Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "(absent)".to_string());
    let issued_token_type = body
        .get("issued_token_type")
        .and_then(serde_json::Value::as_str)
        .map(sanitize)
        .unwrap_or_else(|| "(absent)".to_string());

    let decoded = decode_compact_jwt(access_token)?;
    let jwks = load_exchange_jwks(args, client).await?;
    let (claims, verified_alg, verified_kid, verification_source) =
        if let Some((jwks, source)) = jwks {
            let verified =
                verify_claims_against_jwks_with_header::<serde_json::Value>(access_token, &jwks)
                    .map_err(|err| {
                        CliError::runtime(format!(
                            "minted token verification failed: {}",
                            sanitize_oauth_text(&err.to_string())
                        ))
                    })?;
            (Some(verified.claims), Some(verified.alg), Some(verified.kid), source)
        } else {
            let claims = decoded.as_ref().map(|(_, payload)| payload.clone());
            (claims, None, None, "none".to_string())
        };

    let mut safe = serde_json::Map::new();
    safe.insert("exchange_status".to_string(), serde_json::json!("ok"));
    safe.insert("http_status".to_string(), serde_json::json!(http_status));
    safe.insert("token_type".to_string(), serde_json::json!(token_type));
    safe.insert("issued_token_type".to_string(), serde_json::json!(issued_token_type));
    safe.insert(
        "access_token_sha256_prefix".to_string(),
        serde_json::json!(sha256_hex_prefix(access_token)),
    );
    if let Some(scope) = body.get("scope").and_then(serde_json::Value::as_str) {
        safe.insert("scope".to_string(), serde_json::json!(sanitize(scope)));
    }
    if let Some(expires_in) = body.get("expires_in").and_then(serde_json::Value::as_i64) {
        safe.insert("expires_in".to_string(), serde_json::json!(expires_in));
    }

    let signature_verified = verification_source != "none";
    safe.insert("jwt_signature_verified".to_string(), serde_json::json!(signature_verified));
    safe.insert("jwt_verification_source".to_string(), serde_json::json!(verification_source));

    if let Some((header, _)) = &decoded {
        if verified_alg.is_none()
            && let Some(alg) = header.get("alg").and_then(serde_json::Value::as_str)
        {
            safe.insert("jwt_header_alg".to_string(), serde_json::json!(sanitize(alg)));
        }
        if verified_kid.is_none()
            && let Some(kid) = header.get("kid").and_then(serde_json::Value::as_str)
        {
            safe.insert("jwt_header_kid".to_string(), serde_json::json!(sanitize(kid)));
        }
        if let Some(typ) = header.get("typ").and_then(serde_json::Value::as_str) {
            safe.insert("jwt_header_typ".to_string(), serde_json::json!(sanitize(typ)));
        }
    }
    if let Some(alg) = verified_alg {
        safe.insert("jwt_header_alg".to_string(), serde_json::json!(sanitize(&alg)));
    }
    if let Some(kid) = verified_kid {
        safe.insert("jwt_header_kid".to_string(), serde_json::json!(sanitize(&kid)));
    }
    if let Some(expected_jkt) = expected_dpop_jkt {
        let claims = claims.as_ref().ok_or_else(|| {
            CliError::runtime("DPoP exchange response access_token is not a compact JWT")
        })?;
        let actual_jkt = claims
            .get("cnf")
            .and_then(|cnf| cnf.get("jkt"))
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                CliError::runtime("DPoP exchange response missing access_token cnf.jkt")
            })?;
        if actual_jkt != expected_jkt {
            return Err(CliError::runtime(
                "DPoP exchange response cnf.jkt does not match holder key",
            ));
        }
        safe.insert("dpop_cnf_jkt_matches_holder".to_string(), serde_json::json!(true));
        safe.insert(
            "dpop_holder_jkt_sha256_prefix".to_string(),
            serde_json::json!(sha256_hex_prefix(expected_jkt)),
        );
    }
    if let Some(claims) = claims {
        safe.insert("claims".to_string(), safe_claims_summary(&claims));
    }

    match args.output {
        ExchangeOutputFormat::Redacted => {
            let raw_token = args.print_token.then_some(access_token);
            Ok(render_exchange_map_lines(&safe, raw_token))
        }
        ExchangeOutputFormat::Claims => {
            if args.print_token {
                safe.insert("access_token".to_string(), serde_json::json!(access_token));
            }
            let fallback = serde_json::Value::Object(safe.clone());
            let mut output = serde_json::to_string_pretty(safe.get("claims").unwrap_or(&fallback))
                .unwrap_or_else(|_| "{}".to_string());
            output.push('\n');
            Ok(output)
        }
        ExchangeOutputFormat::Json => {
            if args.print_token {
                safe.insert("access_token".to_string(), serde_json::json!(access_token));
            }
            let mut output = serde_json::to_string_pretty(&serde_json::Value::Object(safe))
                .unwrap_or_else(|_| "{}".to_string());
            output.push('\n');
            Ok(output)
        }
    }
}

async fn load_exchange_jwks(
    args: &ExchangeArgs,
    client: &reqwest::Client,
) -> Result<Option<(JwksDocument, String)>, CliError> {
    if let Some(path) = &args.jwks_file {
        let raw = fs::read_to_string(path).map_err(|err| {
            CliError::runtime(format!("failed to read JWKS file {}: {err}", sanitize_path(path)))
        })?;
        return parse_exchange_jwks_document(&raw, "JWKS file")
            .map(|jwks| Some((jwks, "file".to_string())));
    }
    if let Some(url) = &args.jwks_url {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(CliError::usage("JWKS URL must be an http or https URL"));
        }
        let response = client.get(url).send().await.map_err(|err| {
            CliError::runtime(format!(
                "failed to fetch JWKS URL: {}",
                sanitize_oauth_text(&err.to_string())
            ))
        })?;
        let status = response.status();
        let raw = response.text().await.map_err(|err| {
            CliError::runtime(format!(
                "failed to read JWKS response body: {}",
                sanitize_oauth_text(&err.to_string())
            ))
        })?;
        if !status.is_success() {
            return Err(CliError::runtime(format!(
                "JWKS URL fetch failed\nhttp_status={}",
                status.as_u16()
            )));
        }
        return parse_exchange_jwks_document(&raw, "JWKS URL")
            .map(|jwks| Some((jwks, "url".to_string())));
    }
    Ok(None)
}

async fn load_jwks_for_verification(
    jwks_file: Option<&Path>,
    jwks_url: Option<&str>,
    client: &reqwest::Client,
) -> Result<(JwksDocument, String), CliError> {
    if let Some(path) = jwks_file {
        let raw = fs::read_to_string(path).map_err(|err| {
            CliError::runtime(format!("failed to read JWKS file {}: {err}", sanitize_path(path)))
        })?;
        return parse_exchange_jwks_document(&raw, "JWKS file")
            .map(|jwks| (jwks, "file".to_string()));
    }
    if let Some(url) = jwks_url {
        if !url.starts_with("https://") && !url.starts_with("http://") {
            return Err(CliError::usage("JWKS URL must be an http or https URL"));
        }
        let response = client.get(url).send().await.map_err(|err| {
            CliError::runtime(format!(
                "failed to fetch JWKS URL: {}",
                sanitize_oauth_text(&err.to_string())
            ))
        })?;
        let status = response.status();
        let raw = response.text().await.map_err(|err| {
            CliError::runtime(format!(
                "failed to read JWKS response body: {}",
                sanitize_oauth_text(&err.to_string())
            ))
        })?;
        if !status.is_success() {
            return Err(CliError::runtime(format!(
                "JWKS URL fetch failed\nhttp_status={}",
                status.as_u16()
            )));
        }
        return parse_exchange_jwks_document(&raw, "JWKS URL")
            .map(|jwks| (jwks, "url".to_string()));
    }
    Err(CliError::usage("token verify requires --jwks-file or --jwks-url"))
}

fn parse_exchange_jwks_document(raw: &str, label: &str) -> Result<JwksDocument, CliError> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| CliError::usage(format!("{label} is invalid JSON: {err}")))?;
    let keys = normalize_jwks_value(&value)?;
    inspect_public_keys(&keys)?;

    let mut public_keys = Vec::with_capacity(keys.len());
    for (index, key) in keys.into_iter().enumerate() {
        let jwk: PublicJwk = serde_json::from_value(serde_json::Value::Object(key.clone()))
            .map_err(|err| {
                CliError::usage(format!("{label} key[{index}] is not a public JWK: {err}"))
            })?;
        if jwk.kid.is_empty() {
            return Err(CliError::usage(format!(
                "{label} key[{index}] missing required member kid"
            )));
        }
        public_keys.push(jwk);
    }
    Ok(JwksDocument::new(public_keys))
}

fn decode_compact_jwt(
    token: &str,
) -> Result<Option<(serde_json::Value, serde_json::Value)>, CliError> {
    let parts = token.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Ok(None);
    }
    let header = decode_compact_jwt_json_part(parts[0], "JWT header")?;
    let payload = decode_compact_jwt_json_part(parts[1], "JWT payload")?;
    Ok(Some((header, payload)))
}

fn decode_compact_jwt_json_part(part: &str, label: &str) -> Result<serde_json::Value, CliError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| CliError::runtime(format!("minted {label} is not valid base64url")))?;
    serde_json::from_slice(&bytes)
        .map_err(|err| CliError::runtime(format!("minted {label} is not JSON: {err}")))
}

fn safe_claims_summary(claims: &serde_json::Value) -> serde_json::Value {
    let mut safe = serde_json::Map::new();
    insert_safe_string_claim(&mut safe, claims, "iss");
    insert_safe_audience_claim(&mut safe, claims);
    insert_safe_string_claim(&mut safe, claims, "scope");
    insert_safe_string_claim(&mut safe, claims, "client_id");
    if let Some(sub) = claims.get("sub").and_then(serde_json::Value::as_str) {
        safe.insert("sub_sha256_prefix".to_string(), serde_json::json!(sha256_hex_prefix(sub)));
    }
    if let Some(jti) = claims.get("jti").and_then(serde_json::Value::as_str) {
        safe.insert("jti_sha256_prefix".to_string(), serde_json::json!(sha256_hex_prefix(jti)));
    }
    if let Some(act_sub) =
        claims.get("act").and_then(|act| act.get("sub")).and_then(serde_json::Value::as_str)
    {
        safe.insert("act_sub".to_string(), serde_json::json!(sanitize(act_sub)));
    }
    if let Some(jkt) =
        claims.get("cnf").and_then(|cnf| cnf.get("jkt")).and_then(serde_json::Value::as_str)
    {
        safe.insert("cnf_jkt_sha256_prefix".to_string(), serde_json::json!(sha256_hex_prefix(jkt)));
    }
    for name in ["iat", "exp"] {
        if let Some(value) = claims.get(name).and_then(serde_json::Value::as_i64) {
            safe.insert(name.to_string(), serde_json::json!(value));
        }
    }
    serde_json::Value::Object(safe)
}

fn insert_safe_string_claim(
    safe: &mut serde_json::Map<String, serde_json::Value>,
    claims: &serde_json::Value,
    name: &str,
) {
    if let Some(value) = claims.get(name).and_then(serde_json::Value::as_str) {
        safe.insert(name.to_string(), serde_json::json!(sanitize(value)));
    }
}

fn insert_safe_audience_claim(
    safe: &mut serde_json::Map<String, serde_json::Value>,
    claims: &serde_json::Value,
) {
    match claims.get("aud") {
        Some(serde_json::Value::String(value)) => {
            safe.insert("aud".to_string(), serde_json::json!(sanitize(value)));
        }
        Some(serde_json::Value::Array(values)) => {
            let audiences = values
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(sanitize)
                .collect::<Vec<_>>();
            safe.insert("aud".to_string(), serde_json::json!(audiences));
        }
        _ => {}
    }
}

fn render_exchange_map_lines(
    safe: &serde_json::Map<String, serde_json::Value>,
    raw_access_token: Option<&str>,
) -> String {
    let mut output = String::new();
    for name in [
        "exchange_status",
        "http_status",
        "error",
        "error_description",
        "token_type",
        "issued_token_type",
        "scope",
        "expires_in",
        "access_token_sha256_prefix",
        "jwt_signature_verified",
        "jwt_verification_source",
        "jwt_header_alg",
        "jwt_header_kid",
        "jwt_header_typ",
        "dpop_cnf_jkt_matches_holder",
        "dpop_holder_jkt_sha256_prefix",
    ] {
        if let Some(value) = safe.get(name) {
            output.push_str(&format!("{name}={}\n", display_json_scalar(value)));
        }
    }
    if let Some(serde_json::Value::Object(claims)) = safe.get("claims") {
        for name in [
            "iss",
            "aud",
            "scope",
            "client_id",
            "sub_sha256_prefix",
            "jti_sha256_prefix",
            "act_sub",
            "cnf_jkt_sha256_prefix",
            "iat",
            "exp",
        ] {
            if let Some(value) = claims.get(name) {
                output.push_str(&format!("claims.{name}={}\n", display_json_scalar(value)));
            }
        }
    }
    if let Some(token) = raw_access_token {
        output.push_str(&format!("access_token={token}\n"));
    }
    output
}

fn render_token_verify_map_lines(safe: &serde_json::Map<String, serde_json::Value>) -> String {
    let mut output = String::new();
    for name in [
        "token_verify_status",
        "access_token_sha256_prefix",
        "jwt_signature_verified",
        "jwt_verification_source",
        "jwt_header_alg",
        "jwt_header_kid",
    ] {
        if let Some(value) = safe.get(name) {
            output.push_str(&format!("{name}={}\n", display_json_scalar(value)));
        }
    }
    if let Some(serde_json::Value::Object(claims)) = safe.get("claims") {
        for name in [
            "iss",
            "aud",
            "scope",
            "client_id",
            "sub_sha256_prefix",
            "jti_sha256_prefix",
            "act_sub",
            "cnf_jkt_sha256_prefix",
            "iat",
            "exp",
        ] {
            if let Some(value) = claims.get(name) {
                output.push_str(&format!("claims.{name}={}\n", display_json_scalar(value)));
            }
        }
    }
    output
}

fn display_json_scalar(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(value) => sanitize(value),
        serde_json::Value::Number(value) => value.to_string(),
        serde_json::Value::Bool(value) => value.to_string(),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => serde_json::to_string(value)
            .map(|value| sanitize(&value))
            .unwrap_or_else(|_| "(unrenderable)".to_string()),
        serde_json::Value::Null => "(absent)".to_string(),
    }
}

fn sha256_hex_prefix(value: &str) -> String {
    let digest = Sha256::digest(value.as_bytes());
    digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

fn sha256_bytes_hex_prefix(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    digest.iter().take(8).map(|byte| format!("{byte:02x}")).collect()
}

fn sanitize_oauth_text(value: &str) -> String {
    sanitize(value)
        .split_whitespace()
        .map(|part| if looks_like_compact_jwt(part) { "[redacted]" } else { part })
        .collect::<Vec<_>>()
        .join(" ")
}

fn looks_like_compact_jwt(value: &str) -> bool {
    let trimmed = value.trim_matches(|ch: char| {
        !(ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.')
    });
    trimmed.len() > 40 && trimmed.matches('.').count() == 2
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

#[cfg(feature = "pqc-openssl-unstable")]
fn load_current_pqc_signing_key(path: &Path) -> Result<PublicJwk, CliError> {
    let raw = fs::read_to_string(path).map_err(|err| {
        CliError::runtime(format!(
            "failed to read current PQC signing key {}: {err}",
            sanitize_path(path)
        ))
    })?;
    let value: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
        CliError::usage(format!(
            "current PQC signing key {} must be an AKP private JWK JSON object: {err}",
            sanitize_path(path)
        ))
    })?;
    let Some(object) = value.as_object() else {
        return Err(CliError::usage(format!(
            "current PQC signing key {} must be an AKP private JWK JSON object",
            sanitize_path(path)
        )));
    };
    if object.get("priv").is_none()
        || object.get("kty").and_then(serde_json::Value::as_str) != Some("AKP")
    {
        return Err(CliError::usage(format!(
            "current PQC signing key {} must be an AKP private JWK",
            sanitize_path(path)
        )));
    }
    let alg = object
        .get("alg")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| CliError::usage("current PQC signing key missing alg"))?;
    let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
        &sts_jose::BackendSelection::parse(alg),
        &raw,
        "",
    )
    .map_err(|err| {
        CliError::usage(format!(
            "current PQC signing key {} is invalid: {err}",
            sanitize_path(path)
        ))
    })?;
    signer
        .public_jwks()
        .keys
        .into_iter()
        .next()
        .ok_or_else(|| CliError::runtime("current PQC signing key produced no public JWK"))
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
                CliError::usage(format!("{label} key[{index}] is not a valid public JWK: {err}"))
            })?;
        if jwk.kty == "RSA" {
            let bits = rsa_public_key_bits_from_jwk(&jwk).map_err(|err| {
                CliError::usage(format!(
                    "{label} key[{index}] is not a valid RSA public JWK: {err}"
                ))
            })?;
            if bits < 2048 {
                return Err(CliError::usage(format!(
                    "{label} key[{index}] RSA modulus must be at least 2048 bits"
                )));
            }
        } else if jwk.kty == "AKP" {
            let _ = akp_public_bytes(&jwk)?;
        } else {
            return Err(CliError::usage(format!(
                "{label} key[{index}] unsupported JWK kty {}",
                jwk.kty
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
    akp_public_bytes: Option<usize>,
    akp_public_sha256_prefix: Option<String>,
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
        let (akp_public_bytes, akp_public_sha256_prefix) = if kty == "AKP" {
            let public = akp_public_from_key(key, index)?;
            (Some(public.len()), Some(sha256_bytes_hex_prefix(&public)))
        } else {
            (None, None)
        };
        inspected.push(InspectedKey {
            index,
            kid,
            kty,
            use_,
            alg,
            rsa_modulus_bits,
            akp_public_bytes,
            akp_public_sha256_prefix,
        });
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

fn akp_public_from_key(
    key: &serde_json::Map<String, serde_json::Value>,
    index: usize,
) -> Result<Vec<u8>, CliError> {
    if key.get("n").is_some() || key.get("e").is_some() {
        return Err(CliError::usage(format!(
            "key[{index}] AKP key must not contain RSA n/e members"
        )));
    }
    let alg = required_string(key, "alg", index)?;
    let algorithm = sts_jose::MlDsaAlgorithm::from_jose_alg(&alg)
        .ok_or_else(|| CliError::usage(format!("key[{index}] unsupported AKP alg {alg}")))?;
    let public = required_string(key, "pub", index)?;
    let bytes = URL_SAFE_NO_PAD
        .decode(public)
        .map_err(|_| CliError::usage(format!("key[{index}] member pub is not base64url")))?;
    if bytes.len() != algorithm.public_key_len() {
        return Err(CliError::usage(format!(
            "key[{index}] AKP pub length must be {} bytes for {}",
            algorithm.public_key_len(),
            algorithm.jose_alg()
        )));
    }
    Ok(bytes)
}

fn akp_public_bytes(jwk: &PublicJwk) -> Result<usize, CliError> {
    let value = serde_json::to_value(jwk)
        .map_err(|err| CliError::runtime(format!("failed to inspect public JWK: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::runtime("public JWK did not serialize to an object"))?;
    akp_public_from_key(object, 0).map(|bytes| bytes.len())
}

#[cfg(feature = "pqc-openssl-unstable")]
fn akp_public_sha256_prefix(jwk: &PublicJwk) -> Result<String, CliError> {
    let value = serde_json::to_value(jwk)
        .map_err(|err| CliError::runtime(format!("failed to inspect public JWK: {err}")))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError::runtime("public JWK did not serialize to an object"))?;
    akp_public_from_key(object, 0).map(|bytes| sha256_bytes_hex_prefix(&bytes))
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
        if let Some(bytes) = key.akp_public_bytes {
            output.push_str(&format!("key[{}].akp_public_bytes={bytes}\n", key.index));
        }
        if let Some(prefix) = &key.akp_public_sha256_prefix {
            output.push_str(&format!(
                "key[{}].akp_public_sha256_prefix={}\n",
                key.index,
                sanitize(prefix)
            ));
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
        if ch.is_ascii_graphic() || ch == ' ' {
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

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
    fn parser_accepts_dpop_key_generate_command() {
        let cli = Cli::try_parse_from(["sts-cli", "dpop", "key", "generate", "--out", "dpop.json"])
            .expect("parse dpop key generate");

        match cli.command {
            Command::Dpop {
                command: DpopCommand::Key { command: DpopKeyCommand::Generate(args) },
            } => {
                assert_eq!(args.out, PathBuf::from("dpop.json"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parser_accepts_pqc_preflight_command() {
        let cli =
            Cli::try_parse_from(["sts-cli", "pqc", "preflight"]).expect("parse pqc preflight");
        match cli.command {
            Command::Pqc { command: PqcCommand::Preflight } => {}
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parser_accepts_pqc_key_generate_command() {
        let cli = Cli::try_parse_from([
            "sts-cli",
            "pqc",
            "key",
            "generate",
            "--alg",
            "ML-DSA-65",
            "--kid",
            "ml-key",
            "--out",
            "mldsa-private.json",
            "--public-jwks-out",
            "mldsa-public.jwks.json",
        ])
        .expect("parse pqc key generate");
        match cli.command {
            Command::Pqc {
                command: PqcCommand::Key { command: PqcKeyCommand::Generate(args) },
            } => {
                assert_eq!(args.alg, "ML-DSA-65");
                assert_eq!(args.kid.as_deref(), Some("ml-key"));
                assert_eq!(args.out, PathBuf::from("mldsa-private.json"));
                assert_eq!(args.public_jwks_out, Some(PathBuf::from("mldsa-public.jwks.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parser_accepts_pqc_key_rotate_command() {
        let cli = Cli::try_parse_from([
            "sts-cli",
            "pqc",
            "key",
            "rotate",
            "--key-file",
            "mldsa-private.json",
            "--extra-jwks-file",
            "mldsa-retiring.jwks.json",
            "--kid",
            "new-ml-key",
            "--dry-run",
        ])
        .expect("parse pqc key rotate");
        match cli.command {
            Command::Pqc { command: PqcCommand::Key { command: PqcKeyCommand::Rotate(args) } } => {
                assert_eq!(args.key_file, PathBuf::from("mldsa-private.json"));
                assert_eq!(args.extra_jwks_file, PathBuf::from("mldsa-retiring.jwks.json"));
                assert_eq!(args.kid.as_deref(), Some("new-ml-key"));
                assert!(args.dry_run);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn parser_accepts_token_verify_command() {
        let cli = Cli::try_parse_from([
            "sts-cli",
            "token",
            "verify",
            "--token-file",
            "token.jwt",
            "--jwks-file",
            "jwks.json",
        ])
        .expect("parse token verify");
        match cli.command {
            Command::Token { command: TokenCommand::Verify(args) } => {
                assert_eq!(args.token_file, PathBuf::from("token.jwt"));
                assert_eq!(args.jwks_file, Some(PathBuf::from("jwks.json")));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[cfg(not(feature = "pqc-openssl-unstable"))]
    #[tokio::test]
    async fn pqc_preflight_reports_not_compiled_without_feature() {
        let output = run(Cli { command: Command::Pqc { command: PqcCommand::Preflight } })
            .await
            .expect("preflight");
        assert!(output.contains("pqc_preflight_status=ok"));
        assert!(output.contains("pqc_openssl_feature_enabled=false"));
        assert!(output.contains("openssl_version=not_compiled"));
        assert!(output.contains("mldsa_sign_verify=not_compiled"));
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn pqc_preflight_reports_openssl_mldsa_readiness() {
        let output = run(Cli { command: Command::Pqc { command: PqcCommand::Preflight } })
            .await
            .expect("preflight");
        assert!(output.contains("pqc_preflight_status=ok"));
        assert!(output.contains("pqc_openssl_feature_enabled=true"));
        assert!(output.contains("openssl_version=OpenSSL"));
        assert!(output.contains("ML-DSA-44_sign_verify=ok"));
        assert!(output.contains("ML-DSA-65_sign_verify=ok"));
        assert!(output.contains("ML-DSA-87_sign_verify=ok"));
        assert!(!output.contains("eyJ"));
        assert!(!output.contains("priv"));
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[test]
    fn pqc_key_generate_and_inspect_do_not_print_private_material() {
        let dir = unique_temp_dir("sts-cli-pqc-key");
        let private_file = dir.join("mldsa-private.json");
        let public_file = dir.join("mldsa-public.jwks.json");
        let output = generate_pqc_key(PqcKeyGenerateArgs {
            alg: "ML-DSA-65".to_string(),
            kid: Some("ml-key".to_string()),
            out: private_file.clone(),
            public_jwks_out: Some(public_file.clone()),
            force: false,
        })
        .expect("generate pqc key");

        assert!(output.contains("pqc_key_status=generated"));
        assert!(output.contains("alg=ML-DSA-65"));
        assert!(output.contains("kid=ml-key"));
        assert!(!output.contains("\"priv\""));
        assert!(fs::read_to_string(&private_file).expect("private").contains("\"priv\""));
        let public = fs::read_to_string(&public_file).expect("public");
        assert!(public.contains("\"pub\""));
        assert!(!public.contains("\"priv\""));

        let private_inspect = inspect_pqc_key(&private_file).expect("inspect private");
        assert!(private_inspect.contains("pqc_key_status=private-valid"));
        assert!(private_inspect.contains("private_material=redacted"));
        assert!(!private_inspect.contains("\"priv\""));

        let public_inspect = inspect_pqc_key(&public_file).expect("inspect public");
        assert!(public_inspect.contains("jwks_status=public"));
        assert!(public_inspect.contains("key[0].kty=AKP"));
        assert!(public_inspect.contains("key[0].alg=ML-DSA-65"));
        assert!(public_inspect.contains("key[0].akp_public_bytes=1952"));

        let err = generate_pqc_key(PqcKeyGenerateArgs {
            alg: "ML-DSA-65".to_string(),
            kid: Some("ml-key".to_string()),
            out: private_file,
            public_jwks_out: None,
            force: false,
        })
        .unwrap_err();
        assert!(err.message.contains("failed to create secret file"));
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn pqc_key_rotate_dry_run_validates_without_writing_files() {
        let dir = unique_temp_dir("sts-cli-pqc-rotate-dry-run");
        let key_file = dir.join("sts_mldsa_private.json");
        let overlap_file = dir.join("sts_mldsa_retiring.jwks.json");
        let (old_private, _) = mldsa_private_jwk_with_kid("old-ml-kid");
        fs::write(&key_file, &old_private).expect("write current key");

        let output = run(Cli {
            command: Command::Pqc {
                command: PqcCommand::Key {
                    command: PqcKeyCommand::Rotate(PqcKeyRotateArgs {
                        key_file: key_file.clone(),
                        extra_jwks_file: overlap_file.clone(),
                        kid: Some("new-ml-kid".to_string()),
                        dry_run: true,
                    }),
                },
            },
        })
        .await
        .expect("dry run");

        assert!(output.contains("pqc_rotate_status=dry_run"));
        assert!(output.contains("current_kid=old-ml-kid"));
        assert!(output.contains("current_alg=ML-DSA-65"));
        assert!(output.contains("would_overlap_keys=1"));
        assert_eq!(fs::read_to_string(&key_file).expect("read current key"), old_private);
        assert!(!overlap_file.exists());
        assert!(!output.contains("\"priv\""));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn pqc_key_rotate_stages_old_public_key_before_replacing_private_key() {
        let dir = unique_temp_dir("sts-cli-pqc-rotate-success");
        let key_file = dir.join("sts_mldsa_private.json");
        let overlap_file = dir.join("sts_mldsa_retiring.jwks.json");
        let (old_private, old_public) = mldsa_private_jwk_with_kid("old-ml-kid");
        let (_, older_public) = mldsa_private_jwk_with_kid("older-ml-kid");
        fs::write(&key_file, old_private).expect("write current key");
        write_jwks(&overlap_file, vec![older_public.clone()]);

        let output = run(Cli {
            command: Command::Pqc {
                command: PqcCommand::Key {
                    command: PqcKeyCommand::Rotate(PqcKeyRotateArgs {
                        key_file: key_file.clone(),
                        extra_jwks_file: overlap_file.clone(),
                        kid: Some("new-ml-kid".to_string()),
                        dry_run: false,
                    }),
                },
            },
        })
        .await
        .expect("rotate");

        assert!(output.contains("pqc_rotate_status=rotated"));
        assert!(output.contains("old_kid=old-ml-kid"));
        assert!(output.contains("new_kid=new-ml-kid"));
        assert!(output.contains("private_key_mode=0600"));
        assert!(!output.contains("\"priv\""));

        let new_private = fs::read_to_string(&key_file).expect("read new private key");
        let new_value: serde_json::Value =
            serde_json::from_str(&new_private).expect("new private key JSON");
        assert_eq!(new_value.get("kid").and_then(serde_json::Value::as_str), Some("new-ml-kid"));
        assert_eq!(new_value.get("kty").and_then(serde_json::Value::as_str), Some("AKP"));
        assert_eq!(new_value.get("alg").and_then(serde_json::Value::as_str), Some("ML-DSA-65"));
        assert!(new_value.get("priv").is_some());
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
        assert_eq!(kids, BTreeSet::from(["older-ml-kid".to_string(), "old-ml-kid".to_string()]));
        let staged_old = overlap.keys.iter().find(|key| key.kid == "old-ml-kid").expect("old key");
        assert_eq!(staged_old, &old_public);
        let raw_overlap = fs::read_to_string(&overlap_file).expect("read overlap");
        assert!(!raw_overlap.contains("\"priv\""));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn pqc_key_rotate_rejects_public_current_key_without_writing_overlap() {
        let dir = unique_temp_dir("sts-cli-pqc-rotate-public-current");
        let key_file = dir.join("sts_mldsa_public.json");
        let overlap_file = dir.join("sts_mldsa_retiring.jwks.json");
        let (_, old_public) = mldsa_private_jwk_with_kid("public-only-ml");
        fs::write(&key_file, serde_json::to_string(&old_public).expect("public jwk"))
            .expect("write public current key");

        let err = run(Cli {
            command: Command::Pqc {
                command: PqcCommand::Key {
                    command: PqcKeyCommand::Rotate(PqcKeyRotateArgs {
                        key_file: key_file.clone(),
                        extra_jwks_file: overlap_file.clone(),
                        kid: None,
                        dry_run: false,
                    }),
                },
            },
        })
        .await
        .expect_err("public key must fail");

        assert_eq!(err.code, 2);
        assert!(err.message.contains("must be an AKP private JWK"));
        assert!(!overlap_file.exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn token_verify_accepts_mldsa_akp_jwks_and_redacts_token() {
        let dir = unique_temp_dir("sts-cli-token-verify-mldsa");
        let token_file = dir.join("token.jwt");
        let jwks_file = dir.join("jwks.json");
        let generated =
            MlDsaJoseSigner::generate_private_jwk(MlDsaAlgorithm::MlDsa65, Some("sts-mldsa-kid"))
                .expect("generated mldsa");
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &sts_jose::BackendSelection::parse("ML-DSA-65"),
            &generated.private_jwk_json,
            "",
        )
        .expect("signer");
        let token = signer
            .sign_json_claims(&serde_json::json!({
                "iss": "http://127.0.0.1:8888/tenant1",
                "sub": "user@example.com",
                "aud": "api://chat-mcp",
                "scope": "chat.read",
                "act": {"sub": "chat-mcp"},
                "iat": 1_000,
                "exp": 2_000,
                "jti": "minted-jti-secret"
            }))
            .expect("sign token");
        fs::write(&token_file, &token).expect("write token");
        write_jwks(&jwks_file, signer.public_jwks().keys);

        let output = verify_token(TokenVerifyArgs {
            token_file,
            jwks_file: Some(jwks_file),
            jwks_url: None,
            output: ExchangeOutputFormat::Redacted,
        })
        .await
        .expect("verify token");
        assert!(output.contains("token_verify_status=ok"));
        assert!(output.contains("jwt_signature_verified=true"));
        assert!(output.contains("jwt_header_alg=ML-DSA-65"));
        assert!(output.contains("claims.act_sub=chat-mcp"));
        assert!(!output.contains(&token));
        assert!(!output.contains("minted-jti-secret"));
    }

    #[test]
    fn parser_accepts_exchange_command() {
        let cli = Cli::try_parse_from([
            "sts-cli",
            "exchange",
            "--sts-url",
            "http://127.0.0.1:8888/tenant1",
            "--subject-token-file",
            "subject.txt",
            "--actor-token-file",
            "actor.jwt",
            "--audience",
            "api://chat-mcp",
            "--resource",
            "https://chat.example/resource",
            "--scope",
            "chat.read",
            "--dpop-key-file",
            "dpop-private.json",
            "--jwks-file",
            "jwks.json",
        ])
        .expect("parse exchange");

        match cli.command {
            Command::Exchange(args) => {
                assert_eq!(args.sts_url.as_deref(), Some("http://127.0.0.1:8888/tenant1"));
                assert_eq!(args.subject_token_file, PathBuf::from("subject.txt"));
                assert_eq!(args.actor_token_file, Some(PathBuf::from("actor.jwt")));
                assert_eq!(args.subject_token_type, ACCESS_TOKEN_TYPE);
                assert_eq!(args.actor_token_type, JWT_TOKEN_TYPE);
                assert_eq!(args.audience, vec!["api://chat-mcp"]);
                assert_eq!(args.resource, vec!["https://chat.example/resource"]);
                assert_eq!(args.scope.as_deref(), Some("chat.read"));
                assert_eq!(args.dpop_key_file, Some(PathBuf::from("dpop-private.json")));
                assert_eq!(args.jwks_file, Some(PathBuf::from("jwks.json")));
                assert_eq!(args.output, ExchangeOutputFormat::Redacted);
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn exchange_endpoint_derives_token_path_from_path_bearing_issuer() {
        let args = exchange_args(
            Some("http://127.0.0.1:8888/tenant1/".to_string()),
            None,
            PathBuf::from("subject.txt"),
            None,
        );

        assert_eq!(
            resolve_token_endpoint(&args).expect("endpoint"),
            "http://127.0.0.1:8888/tenant1/token"
        );
    }

    #[tokio::test]
    async fn exchange_posts_form_and_prints_verified_redacted_claims() {
        let dir = unique_temp_dir("sts-cli-exchange-success");
        let subject_file = dir.join("subject.txt");
        let actor_file = dir.join("actor.jwt");
        let dpop_file = dir.join("dpop.jwt");
        let jwks_file = dir.join("jwks.json");
        fs::write(&subject_file, "subject-token-secret\n").expect("write subject");
        fs::write(&actor_file, "actor-token-secret\n").expect("write actor");
        fs::write(&dpop_file, "dpop.proof.secret\n").expect("write dpop");

        let signer = RsaJoseSigner::generate_for_tests("sts-kid").expect("signer");
        write_jwks(&jwks_file, signer.public_jwks().keys);
        let minted_token = signer
            .sign_json_claims(&serde_json::json!({
                "iss": "http://127.0.0.1:8888/tenant1",
                "sub": "user@example.com",
                "aud": "api://chat-mcp",
                "scope": "chat.read",
                "act": {"sub": "chat-mcp"},
                "client_id": "chat-client",
                "iat": 1_000,
                "exp": 2_000,
                "jti": "minted-jti-secret"
            }))
            .expect("sign minted token");
        let (sts_url, captured, handle) = spawn_exchange_server(
            200,
            serde_json::json!({
                "access_token": minted_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "chat.read"
            })
            .to_string(),
        );

        let mut args = exchange_args(Some(sts_url), None, subject_file.clone(), Some(actor_file));
        args.audience = vec!["api://chat-mcp".to_string()];
        args.scope = Some("chat.read".to_string());
        args.dpop_proof_file = Some(dpop_file);
        args.jwks_file = Some(jwks_file);

        let output =
            run(Cli { command: Command::Exchange(Box::new(args)) }).await.expect("exchange");
        let request = captured.recv_timeout(Duration::from_secs(3)).expect("captured request");
        handle.join().expect("server joined");

        assert!(request.request_line.starts_with("POST /token HTTP/1.1"));
        assert!(
            request
                .headers
                .to_ascii_lowercase()
                .contains("content-type: application/x-www-form-urlencoded")
        );
        assert!(request.headers.to_ascii_lowercase().contains("dpop: dpop.proof.secret"));

        let form = serde_urlencoded::from_bytes::<Vec<(String, String)>>(request.body.as_bytes())
            .expect("decode form");
        assert_eq!(form_value(&form, "grant_type"), Some(TOKEN_EXCHANGE_GRANT_TYPE));
        assert_eq!(form_value(&form, "subject_token"), Some("subject-token-secret"));
        assert_eq!(form_value(&form, "subject_token_type"), Some(ACCESS_TOKEN_TYPE));
        assert_eq!(form_value(&form, "actor_token"), Some("actor-token-secret"));
        assert_eq!(form_value(&form, "actor_token_type"), Some(JWT_TOKEN_TYPE));
        assert_eq!(form_value(&form, "audience"), Some("api://chat-mcp"));
        assert_eq!(form_value(&form, "scope"), Some("chat.read"));

        assert!(output.contains("exchange_status=ok"));
        assert!(output.contains("http_status=200"));
        assert!(output.contains("token_type=Bearer"));
        assert!(output.contains("jwt_signature_verified=true"));
        assert!(output.contains("jwt_verification_source=file"));
        assert!(output.contains("jwt_header_alg=RS256"));
        assert!(output.contains("jwt_header_kid=sts-kid"));
        assert!(output.contains("claims.iss=http://127.0.0.1:8888/tenant1"));
        assert!(output.contains("claims.aud=api://chat-mcp"));
        assert!(output.contains("claims.act_sub=chat-mcp"));
        assert!(output.contains("claims.sub_sha256_prefix="));
        assert!(output.contains("claims.jti_sha256_prefix="));
        assert!(output.contains("access_token_sha256_prefix="));
        assert!(!output.contains("subject-token-secret"));
        assert!(!output.contains("actor-token-secret"));
        assert!(!output.contains("dpop.proof.secret"));
        assert!(!output.contains("minted-jti-secret"));
        assert!(!output.contains("user@example.com"));
        assert!(!output.contains("eyJ"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn exchange_verifies_mldsa_akp_jwks_and_redacts_token() {
        let dir = unique_temp_dir("sts-cli-exchange-mldsa-success");
        let subject_file = dir.join("subject.txt");
        let actor_file = dir.join("actor.jwt");
        let jwks_file = dir.join("jwks.json");
        fs::write(&subject_file, "subject-token-secret\n").expect("write subject");
        fs::write(&actor_file, "actor-token-secret\n").expect("write actor");

        let signer = sts_jose::MlDsaJoseSigner::from_seed_for_tests(
            sts_jose::MlDsaAlgorithm::MlDsa65,
            [65_u8; 32],
            "sts-mldsa-kid",
        )
        .expect("mldsa signer");
        write_jwks(&jwks_file, signer.public_jwks().keys);
        let minted_token = signer
            .sign_json_claims(&serde_json::json!({
                "iss": "http://127.0.0.1:8888/tenant1",
                "sub": "user@example.com",
                "aud": "api://pqc-vpn",
                "scope": "vpn.connect",
                "act": {"sub": "pqc-vpn-client"},
                "client_id": "pqc-vpn-client",
                "iat": 1_000,
                "exp": 2_000,
                "jti": "minted-pqc-jti-secret"
            }))
            .expect("sign minted token");
        let (sts_url, _captured, handle) = spawn_exchange_server(
            200,
            serde_json::json!({
                "access_token": minted_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "vpn.connect"
            })
            .to_string(),
        );

        let mut args = exchange_args(Some(sts_url), None, subject_file.clone(), Some(actor_file));
        args.audience = vec!["api://pqc-vpn".to_string()];
        args.scope = Some("vpn.connect".to_string());
        args.jwks_file = Some(jwks_file);

        let output =
            run(Cli { command: Command::Exchange(Box::new(args)) }).await.expect("exchange");
        handle.join().expect("server joined");

        assert!(output.contains("exchange_status=ok"));
        assert!(output.contains("jwt_signature_verified=true"));
        assert!(output.contains("jwt_verification_source=file"));
        assert!(output.contains("jwt_header_alg=ML-DSA-65"));
        assert!(output.contains("jwt_header_kid=sts-mldsa-kid"));
        assert!(output.contains("claims.aud=api://pqc-vpn"));
        assert!(output.contains("claims.act_sub=pqc-vpn-client"));
        assert!(output.contains("access_token_sha256_prefix="));
        assert!(!output.contains("subject-token-secret"));
        assert!(!output.contains("actor-token-secret"));
        assert!(!output.contains("minted-pqc-jti-secret"));
        assert!(!output.contains("user@example.com"));
        assert!(!output.contains("eyJ"));
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(feature = "pqc-openssl-unstable")]
    #[tokio::test]
    async fn exchange_rejects_wrong_mldsa_akp_jwks_without_printing_token() {
        let dir = unique_temp_dir("sts-cli-exchange-mldsa-wrong-jwks");
        let subject_file = dir.join("subject.txt");
        let actor_file = dir.join("actor.jwt");
        let jwks_file = dir.join("jwks.json");
        fs::write(&subject_file, "subject-token-secret\n").expect("write subject");
        fs::write(&actor_file, "actor-token-secret\n").expect("write actor");

        let signer = sts_jose::MlDsaJoseSigner::from_seed_for_tests(
            sts_jose::MlDsaAlgorithm::MlDsa65,
            [66_u8; 32],
            "sts-mldsa-kid",
        )
        .expect("mldsa signer");
        let wrong_signer = sts_jose::MlDsaJoseSigner::from_seed_for_tests(
            sts_jose::MlDsaAlgorithm::MlDsa65,
            [67_u8; 32],
            "sts-mldsa-kid",
        )
        .expect("wrong mldsa signer");
        write_jwks(&jwks_file, wrong_signer.public_jwks().keys);
        let minted_token = signer
            .sign_json_claims(&serde_json::json!({
                "iss": "http://127.0.0.1:8888/tenant1",
                "sub": "user@example.com",
                "aud": "api://pqc-vpn",
                "scope": "vpn.connect",
                "act": {"sub": "pqc-vpn-client"},
                "client_id": "pqc-vpn-client",
                "iat": 1_000,
                "exp": 2_000,
                "jti": "minted-pqc-jti-secret"
            }))
            .expect("sign minted token");
        let (sts_url, _captured, handle) = spawn_exchange_server(
            200,
            serde_json::json!({
                "access_token": minted_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": 300,
                "scope": "vpn.connect"
            })
            .to_string(),
        );

        let mut args = exchange_args(Some(sts_url), None, subject_file.clone(), Some(actor_file));
        args.audience = vec!["api://pqc-vpn".to_string()];
        args.scope = Some("vpn.connect".to_string());
        args.jwks_file = Some(jwks_file);

        let err = run(Cli { command: Command::Exchange(Box::new(args)) })
            .await
            .expect_err("wrong AKP JWKS must fail verification");
        handle.join().expect("server joined");
        assert!(err.message.contains("minted token verification failed"));
        assert!(!err.message.contains("eyJ"));
        assert!(!err.message.contains("minted-pqc-jti-secret"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn exchange_generates_dpop_proof_and_checks_holder_binding() {
        let dir = unique_temp_dir("sts-cli-exchange-dpop-generated");
        let subject_file = dir.join("subject.txt");
        let actor_file = dir.join("actor.jwt");
        let dpop_key_file = dir.join("dpop_private_jwk.json");
        let jwks_file = dir.join("jwks.json");
        fs::write(&subject_file, "subject-token-secret\n").expect("write subject");
        fs::write(&actor_file, "actor-token-secret\n").expect("write actor");
        let generated = DpopHolderKey::generate_private_jwk().expect("dpop key");
        fs::write(&dpop_key_file, &generated.private_jwk_json).expect("write dpop key");

        let signer = RsaJoseSigner::generate_for_tests("sts-kid").expect("signer");
        write_jwks(&jwks_file, signer.public_jwks().keys);
        let minted_token = signer
            .sign_json_claims(&serde_json::json!({
                "iss": "http://127.0.0.1:8888/tenant1",
                "sub": "user@example.com",
                "aud": "api://chat-mcp",
                "scope": "chat.read",
                "act": {"sub": "chat-mcp"},
                "cnf": {"jkt": generated.public_jkt},
                "iat": 1_000,
                "exp": 2_000,
                "jti": "minted-dpop-jti-secret"
            }))
            .expect("sign minted token");
        let (sts_url, captured, handle) = spawn_exchange_server(
            200,
            serde_json::json!({
                "access_token": minted_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "DPoP",
                "expires_in": 300,
                "scope": "chat.read"
            })
            .to_string(),
        );

        let mut args = exchange_args(Some(sts_url.clone()), None, subject_file, Some(actor_file));
        args.audience = vec!["api://chat-mcp".to_string()];
        args.scope = Some("chat.read".to_string());
        args.dpop_key_file = Some(dpop_key_file);
        args.jwks_file = Some(jwks_file);

        let output =
            run(Cli { command: Command::Exchange(Box::new(args)) }).await.expect("exchange");
        let request = captured.recv_timeout(Duration::from_secs(3)).expect("captured request");
        handle.join().expect("server joined");

        let proof = header_value(&request.headers, "DPoP").expect("dpop header");
        let htu = format!("{sts_url}/token");
        let binding = sts_dpop::validate_dpop_proof(sts_dpop::DpopProofRequest {
            proof,
            htm: "POST",
            htu: &htu,
            now: unix_timestamp_now().expect("now"),
            clock_skew_leeway: 300,
        })
        .expect("valid generated proof");
        assert_eq!(binding.jkt, generated.public_jkt);

        assert!(output.contains("exchange_status=ok"));
        assert!(output.contains("token_type=DPoP"));
        assert!(output.contains("dpop_cnf_jkt_matches_holder=true"));
        assert!(output.contains("dpop_holder_jkt_sha256_prefix="));
        assert!(output.contains("claims.cnf_jkt_sha256_prefix="));
        assert!(!output.contains("subject-token-secret"));
        assert!(!output.contains("actor-token-secret"));
        assert!(!output.contains(&generated.public_jkt));
        assert!(!output.contains("minted-dpop-jti-secret"));
        assert!(!output.contains("user@example.com"));
        assert!(!output.contains("eyJ"));
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn exchange_oauth_error_is_redacted_and_returns_runtime_error() {
        let dir = unique_temp_dir("sts-cli-exchange-error");
        let subject_file = dir.join("subject.txt");
        let actor_file = dir.join("actor.jwt");
        fs::write(&subject_file, "subject-token-secret\n").expect("write subject");
        fs::write(&actor_file, "actor-token-secret\n").expect("write actor");

        let (sts_url, captured, handle) = spawn_exchange_server(
            400,
            serde_json::json!({
                "error": "invalid_target",
                "error_description": "audience is not allowed"
            })
            .to_string(),
        );
        let mut args = exchange_args(Some(sts_url), None, subject_file, Some(actor_file));
        args.audience = vec!["api://denied".to_string()];

        let err = run(Cli { command: Command::Exchange(Box::new(args)) })
            .await
            .expect_err("invalid target must fail");
        let request = captured.recv_timeout(Duration::from_secs(3)).expect("captured request");
        handle.join().expect("server joined");

        assert_eq!(err.code, 1);
        assert!(err.message.contains("exchange_status=error"));
        assert!(err.message.contains("http_status=400"));
        assert!(err.message.contains("error=invalid_target"));
        assert!(err.message.contains("error_description=audience is not allowed"));
        assert!(!err.message.contains("subject-token-secret"));
        assert!(!err.message.contains("actor-token-secret"));
        assert!(request.body.contains("audience=api%3A%2F%2Fdenied"));
        let _ = fs::remove_dir_all(dir);
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
    async fn dpop_key_generate_writes_private_file_without_printing_material() {
        let dir = unique_temp_dir("sts-cli-dpop-key-generate");
        let key_file = dir.join("dpop_private_jwk.json");

        let output = run(Cli {
            command: Command::Dpop {
                command: DpopCommand::Key {
                    command: DpopKeyCommand::Generate(DpopKeyGenerateArgs {
                        out: key_file.clone(),
                    }),
                },
            },
        })
        .await
        .expect("generate dpop key");

        let raw = fs::read_to_string(&key_file).expect("read generated key");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("private jwk");
        assert_eq!(value["kty"], "EC");
        assert_eq!(value["crv"], "P-256");
        assert_eq!(value["alg"], "ES256");
        assert!(value.get("d").is_some());
        DpopHolderKey::from_private_jwk(&raw).expect("load generated key");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&key_file).expect("key metadata").permissions().mode() & 0o777,
                0o600
            );
        }

        assert!(output.contains("dpop_key_status=generated"));
        assert!(output.contains("private_key_mode=0600"));
        assert!(output.contains("jkt_sha256_prefix="));
        assert!(!output.contains(r#""d""#));
        assert!(!output.contains(value["d"].as_str().expect("d")));

        let err = run(Cli {
            command: Command::Dpop {
                command: DpopCommand::Key {
                    command: DpopKeyCommand::Generate(DpopKeyGenerateArgs { out: key_file }),
                },
            },
        })
        .await
        .expect_err("existing key must not be overwritten");
        assert_eq!(err.code, 1);
        assert!(err.message.contains("failed to create secret file"));
        let _ = fs::remove_dir_all(dir);
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

    #[cfg(feature = "pqc-openssl-unstable")]
    fn mldsa_private_jwk_with_kid(kid: &str) -> (String, PublicJwk) {
        let generated = MlDsaJoseSigner::generate_private_jwk(MlDsaAlgorithm::MlDsa65, Some(kid))
            .expect("generate mldsa key");
        let signer = MlDsaJoseSigner::from_private_jwk_for_backend(
            &sts_jose::BackendSelection::parse("ML-DSA-65"),
            &generated.private_jwk_json,
            "",
        )
        .expect("parse mldsa private jwk");
        let public = signer.public_jwks().keys.into_iter().next().expect("public jwk");
        (generated.private_jwk_json, public)
    }

    fn write_jwks(path: &Path, keys: Vec<PublicJwk>) {
        let jwks = JwksDocument::new(keys);
        fs::write(path, serde_json::to_string(&jwks).expect("jwks json")).expect("write jwks");
    }

    fn read_jwks(path: &Path) -> JwksDocument {
        serde_json::from_str(&fs::read_to_string(path).expect("read jwks")).expect("jwks")
    }

    #[derive(Debug)]
    struct CapturedRequest {
        request_line: String,
        headers: String,
        body: String,
    }

    fn spawn_exchange_server(
        status: u16,
        body: String,
    ) -> (String, mpsc::Receiver<CapturedRequest>, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind server");
        let addr = listener.local_addr().expect("local addr");
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let captured = read_http_request(&mut stream);
            sender.send(captured).expect("send captured request");
            let reason = if status < 400 { "OK" } else { "Bad Request" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(response.as_bytes()).expect("write response");
        });
        (format!("http://{addr}"), receiver, handle)
    }

    fn read_http_request(stream: &mut TcpStream) -> CapturedRequest {
        stream.set_read_timeout(Some(Duration::from_secs(3))).expect("read timeout");
        let mut buffer = Vec::new();
        let mut temp = [0_u8; 1024];
        loop {
            let read = stream.read(&mut temp).expect("read request");
            if read == 0 {
                break;
            }
            buffer.extend_from_slice(&temp[..read]);
            if let Some(header_end) = find_header_end(&buffer) {
                let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
                let content_length = content_length(&headers);
                let body_start = header_end + 4;
                if buffer.len() >= body_start + content_length {
                    break;
                }
            }
        }
        let header_end = find_header_end(&buffer).expect("header end");
        let headers = String::from_utf8_lossy(&buffer[..header_end]).to_string();
        let body_start = header_end + 4;
        let body_len = content_length(&headers);
        let body = String::from_utf8_lossy(&buffer[body_start..body_start + body_len]).to_string();
        let request_line = headers.lines().next().unwrap_or_default().to_string();
        CapturedRequest { request_line, headers, body }
    }

    fn find_header_end(buffer: &[u8]) -> Option<usize> {
        buffer.windows(4).position(|window| window == b"\r\n\r\n")
    }

    fn content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            })
            .unwrap_or(0)
    }

    fn form_value<'a>(form: &'a [(String, String)], name: &str) -> Option<&'a str> {
        form.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
        headers.lines().find_map(|line| {
            let (header_name, value) = line.split_once(':')?;
            header_name.eq_ignore_ascii_case(name).then(|| value.trim())
        })
    }

    fn exchange_args(
        sts_url: Option<String>,
        token_endpoint: Option<String>,
        subject_token_file: PathBuf,
        actor_token_file: Option<PathBuf>,
    ) -> ExchangeArgs {
        ExchangeArgs {
            sts_url,
            token_endpoint,
            subject_token_file,
            subject_token_type: ACCESS_TOKEN_TYPE.to_string(),
            actor_token_file,
            actor_token_type: JWT_TOKEN_TYPE.to_string(),
            client_assertion_file: None,
            client_assertion_type: CLIENT_ASSERTION_TYPE.to_string(),
            client_id: None,
            audience: Vec::new(),
            resource: Vec::new(),
            scope: None,
            requested_token_type: None,
            dpop_proof_file: None,
            dpop_key_file: None,
            jwks_file: None,
            jwks_url: None,
            output: ExchangeOutputFormat::Redacted,
            print_token: false,
        }
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
