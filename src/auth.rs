// SPDX-License-Identifier: AGPL-3.0-only
//! Bridge the upstream, handshake-authenticated access hook to the private Go gateway.
use std::time::Duration;

use iroh_relay::server::{Access, AccessControl, ClientRequest};
use reqwest::Url;
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Debug, Clone)]
pub struct GatewayAccess {
    client: reqwest::Client,
    url: Url,
}

#[derive(Serialize)]
struct Admission<'a> {
    tunnel_id: &'a str,
    endpoint_id: String,
    token: &'a str,
}

impl GatewayAccess {
    /// Creates a private access bridge without storing client credentials.
    ///
    /// # Errors
    /// Returns an error if the URL is not an HTTP origin or the client cannot be built.
    pub fn new(origin: &str) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut url = Url::parse(origin)?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path() != "/"
        {
            return Err("gateway URL must be an HTTP or HTTPS origin".into());
        }
        url.set_path("/internal/admit");
        let tls = iroh_relay::tls::CaRootsConfig::default()
            .client_config(iroh_relay::tls::default_provider())?;
        let client = reqwest::Client::builder()
            .tls_backend_preconfigured(tls)
            .timeout(Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self { client, url })
    }
}

impl AccessControl for GatewayAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        let Some(tunnel_id) = request
            .headers()
            .get("X-UC-Relay-Tunnel")
            .and_then(|v| v.to_str().ok())
        else {
            return Access::Deny { reason: None };
        };
        if tunnel_id.len() != 64 || !tunnel_id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Access::Deny { reason: None };
        }
        let token = Zeroizing::new(request.auth_token().unwrap_or_default());
        if token.len() > 16_384 {
            return Access::Deny { reason: None };
        }
        let admission = Admission {
            tunnel_id,
            endpoint_id: request.endpoint_id().to_string(),
            token: &token,
        };
        let response = self
            .client
            .post(self.url.clone())
            .json(&admission)
            .send()
            .await;
        if response.is_ok_and(|r| r.status() == reqwest::StatusCode::NO_CONTENT) {
            Access::Allow
        } else {
            // Do not log request errors: they may carry credentials or request URLs.
            Access::Deny { reason: None }
        }
    }
}
