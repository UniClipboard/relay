// SPDX-License-Identifier: AGPL-3.0-only
use std::net::SocketAddr;

use clap::Parser;
use iroh_relay::server::{Server, ServerConfig};
use tracing_subscriber::EnvFilter;
use uniclipboard_relay::relay_config;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    #[arg(long, env = "UC_RELAY_BIND", default_value = "127.0.0.1:3340")]
    bind: SocketAddr,

    #[arg(
        long,
        env = "UC_RELAY_GATEWAY_URL",
        default_value = "http://gateway:3341"
    )]
    gateway_url: String,

    #[arg(long, env = "UC_RELAY_METRICS_BIND")]
    metrics_bind: Option<SocketAddr>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let args = Args::parse();
    let relay = relay_config(args.bind, &args.gateway_url)?;

    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    server_config.metrics_addr = args.metrics_bind;
    let server = Server::spawn(server_config).await?;
    let address = server
        .http_addr()
        .ok_or("relay server did not report a listening address")?;
    tracing::info!(%address, "relay is ready");

    shutdown_signal().await?;
    tracing::info!("shutdown requested");
    server.shutdown().await?;
    Ok(())
}

#[cfg(unix)]
async fn shutdown_signal() -> Result<(), std::io::Error> {
    use tokio::signal::unix::{SignalKind, signal};

    let mut terminate = signal(SignalKind::terminate())?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result,
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() -> Result<(), std::io::Error> {
    tokio::signal::ctrl_c().await
}
