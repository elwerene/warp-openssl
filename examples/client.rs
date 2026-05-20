use clap::Parser;
use reqwest::tls::Version;
use reqwest::{Certificate, ClientBuilder, Identity};
use tracing::info;
use tracing_subscriber::EnvFilter;
use warp_openssl::Result;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Enable client authentication
    #[arg(short, long)]
    client_auth: bool,

    /// Default port to use
    #[arg(short, long, default_value_t = 18443)]
    port: u16,
}

/// For the example to work properly please generate the appropriate certificates and keys in the `certs` directory.
/// Requires openssl to be installed.
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let ca_cert = include_bytes!("../certs/ca.crt").to_vec();
    let crt = include_bytes!("../certs/client.crt").to_vec();
    let key = include_bytes!("../certs/client.key").to_vec();

    let args = Args::parse();

    let identity = Identity::from_pem(&[key, crt].concat())?;

    let trust_root = Certificate::from_pem(&ca_cert).unwrap();
    let builder = ClientBuilder::new()
        .tls_backend_rustls()
        .min_tls_version(Version::TLS_1_2)
        .add_root_certificate(trust_root);

    let builder = if args.client_auth {
        builder.identity(identity)
    } else {
        builder
    };

    let client = builder.build()?;
    let res = client
        .get(format!("https://localhost:{}", args.port))
        .send()
        .await;

    info!("Response: {:?}", res);

    Ok(())
}
