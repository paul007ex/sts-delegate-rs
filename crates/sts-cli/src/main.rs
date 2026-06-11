#![forbid(unsafe_code)]

/// Operator/runtime CLI entrypoint for `sts-delegate-rs`.
#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "help".to_string());
    let result = match command.as_str() {
        "serve" => sts_http::serve_from_env().await,
        "bootstrap-check" => sts_http::bootstrap_check_from_env().await,
        "help" | "--help" | "-h" => {
            print_help();
            Ok(())
        }
        other => {
            eprintln!("unknown command {other:?}");
            print_help();
            std::process::exit(2);
        }
    };
    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "sts-delegate-rs\n\nCommands:\n  serve             load runtime config and start the HTTP STS\n  bootstrap-check   load runtime config, keys, trust anchors, and replay policy, then exit\n  help              show this help\n\nEnvironment:\n  STS_HTTP_ADDR defaults to 127.0.0.1:8888\n  Required: IDP_ISSUER or OKTA_ISSUER, EXPECTED_SUBJECT_AUD, ACTOR_IDS or GATEWAY_ACTOR_ID\n  Key/trust files: OBO_STS_KEY_FILE, ACTOR_JWKS_FILE, CLIENT_JWKS_FILE, optional IDP_JWKS_FILE or IDP_JWKS_URI"
    );
}
