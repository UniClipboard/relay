use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::handshake,
    server::{RelayConfig, Server, ServerConfig},
    tls::{CaRootsConfig, default_provider},
};
use uniclipboard_relay::{AccessLoadError, TokenAccess, relay_config};

const TOKEN: &str = "0123456789abcdef0123456789abcdef";
const WRONG_TOKEN: &str = "fedcba9876543210fedcba9876543210";

#[tokio::test]
async fn relay_rejects_missing_or_wrong_tokens_and_accepts_the_configured_token() {
    let access = TokenAccess::new(TOKEN.to_owned()).expect("valid token");
    let mut relay = RelayConfig::new((std::net::Ipv4Addr::LOCALHOST, 0));
    relay.access = std::sync::Arc::new(access);
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    let server = Server::spawn(server_config).await.expect("start relay");
    let relay_url = server.http_url().expect("relay URL");

    assert_denied(connect(&relay_url, None).await);
    assert_denied(connect(&relay_url, Some(WRONG_TOKEN)).await);
    let client = connect(&relay_url, Some(TOKEN))
        .await
        .expect("correct token should connect");

    drop(client);
    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test]
async fn local_unauthenticated_mode_accepts_a_client_without_a_token() {
    let relay = relay_config((std::net::Ipv4Addr::LOCALHOST, 0).into(), None, true)
        .expect("loopback relay may opt into unauthenticated mode");
    let mut server_config = ServerConfig::default();
    server_config.relay = Some(relay);
    let server = Server::spawn(server_config).await.expect("start relay");
    let relay_url = server.http_url().expect("relay URL");

    let client = connect(&relay_url, None)
        .await
        .expect("local unauthenticated relay should accept a client without a token");

    drop(client);
    server.shutdown().await.expect("clean shutdown");
}

#[test]
fn unauthenticated_mode_rejects_non_loopback_listeners() {
    assert!(matches!(
        relay_config("0.0.0.0:3340".parse().expect("socket address"), None, true),
        Err(AccessLoadError::UnauthenticatedRequiresLoopback)
    ));
}

async fn connect(relay_url: &RelayUrl, token: Option<&str>) -> Result<Client, ConnectError> {
    let tls = CaRootsConfig::default()
        .client_config(default_provider())
        .expect("valid client TLS configuration");
    let secret = SecretKey::from_bytes(&[7; 32]);
    let mut builder =
        ClientBuilder::new(relay_url.clone(), secret, DnsResolver::new()).tls_client_config(tls);
    if let Some(token) = token {
        builder = builder.auth_token(token);
    }
    builder.connect().await
}

fn assert_denied(result: Result<Client, ConnectError>) {
    let result = result.map(|_| ());
    assert!(
        matches!(
            result,
            Err(ConnectError::Handshake {
                source: handshake::Error::ServerDeniedAuth { ref reason, .. },
                ..
            }) if reason == "not authorized"
        ),
        "expected authorization denial, got {result:?}"
    );
}
