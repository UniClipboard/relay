pub mod auth;

use std::{net::SocketAddr, sync::Arc};

use iroh_relay::server::{AllowAll, RelayConfig};

pub use auth::{AccessLoadError, TokenAccess, TokenError, load_access};

/// Builds relay access configuration while keeping unauthenticated mode local-only.
///
/// # Errors
///
/// Returns an error when unauthenticated mode is used with a non-loopback listener or when the
/// configured token cannot be loaded.
pub fn relay_config(
    bind: SocketAddr,
    token_file: Option<&std::path::Path>,
    allow_unauthenticated_local: bool,
) -> Result<RelayConfig, AccessLoadError> {
    let mut relay = RelayConfig::new(bind);
    if allow_unauthenticated_local {
        if !bind.ip().is_loopback() {
            return Err(AccessLoadError::UnauthenticatedRequiresLoopback);
        }
        relay.access = Arc::new(AllowAll);
    } else {
        relay.access = Arc::new(load_access(token_file)?);
    }
    Ok(relay)
}
