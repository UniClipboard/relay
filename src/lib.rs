// SPDX-License-Identifier: AGPL-3.0-only
pub mod auth;

use iroh_relay::server::RelayConfig;
use std::{net::SocketAddr, sync::Arc};

pub use auth::GatewayAccess;

/// Builds an upstream relay whose access decisions belong to the Go gateway.
///
/// # Errors
/// Returns an error when the private gateway URL is invalid.
pub fn relay_config(
    bind: SocketAddr,
    gateway_url: &str,
) -> Result<RelayConfig, Box<dyn std::error::Error + Send + Sync>> {
    let mut relay = RelayConfig::new(bind);
    relay.access = Arc::new(GatewayAccess::new(gateway_url)?);
    Ok(relay)
}
