use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use tracing_subscriber::EnvFilter;
use uniclipboard_relay::load_access;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, env = "UC_RELAY_BIND", default_value = "127.0.0.1:3340")]
    bind: SocketAddr,

    #[arg(long, env = "UC_RELAY_TOKEN_FILE")]
    token_file: Option<PathBuf>,

    #[arg(long, env = "UC_RELAY_METRICS_BIND")]
    metrics_bind: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let access = load_access(args.token_file.as_deref())?;
    let mut relay = RelayConfig::new(args.bind);
    relay.access = Arc::new(access);

    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    server_config.metrics_addr = args.metrics_bind;
    let server = Server::spawn(server_config).await?;
    let address = server
        .http_addr()
        .ok_or("relay server did not report a listening address")?;
    tracing::info!(%address, "relay is ready");

    tokio::signal::ctrl_c().await?;
    tracing::info!("shutdown requested");
    server.shutdown().await?;
    Ok(())
}
