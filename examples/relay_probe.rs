// SPDX-License-Identifier: AGPL-3.0-only
//! Real upstream client used by the gateway end-to-end acceptance suite.
use std::{
    io::{BufRead, Write},
    time::Duration,
};

use futures_util::{SinkExt, StreamExt};
use iroh_base::{RelayUrl, SecretKey};
use iroh_dns::dns::DnsResolver;
use iroh_relay::{
    client::{Client, ClientBuilder, ConnectError},
    protos::{
        handshake,
        relay::{ClientToRelayMsg, Datagrams, RelayToClientMsg},
    },
    tls::{CaRootsConfig, default_provider},
};

async fn connect(url: &RelayUrl, token: &str, seed: u8) -> Result<Client, ConnectError> {
    let tls = CaRootsConfig::default()
        .client_config(default_provider())
        .expect("TLS configuration");
    let mut builder = ClientBuilder::new(
        url.clone(),
        SecretKey::from_bytes(&[seed; 32]),
        DnsResolver::new(),
    )
    .tls_client_config(tls);
    if !token.is_empty() {
        builder = builder.auth_token(token);
    }
    builder.connect().await
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args[1] == "id" {
        let seed: u8 = args[2].parse()?;
        println!("{}", SecretKey::from_bytes(&[seed; 32]).public());
        return Ok(());
    }
    let mut parsed = reqwest::Url::parse(&args[1])?;
    let mut token = zeroize::Zeroizing::new(std::fs::read_to_string(&args[2])?);
    let length = token.trim_end_matches(['\r', '\n']).len();
    token.truncate(length);
    let query_token = std::env::var_os("UC_PROBE_QUERY_TOKEN").is_some();
    if query_token {
        parsed.query_pairs_mut().append_pair("token", &token);
    }
    let url: RelayUrl = parsed.as_str().parse()?;
    let auth_token = if query_token { "" } else { &token };
    if args[3] == "forward" {
        let peer_token = zeroize::Zeroizing::new(match std::env::var("UC_PROBE_PEER_TOKEN_FILE") {
            Ok(path) => std::fs::read_to_string(path)?,
            Err(_) => token.to_string(),
        });
        let mut sender = connect(&url, auth_token, 7).await?;
        let mut receiver = connect(&url, peer_token.trim_end_matches(['\r', '\n']), 8).await?;
        let packets: usize = std::env::var("UC_PROBE_PACKETS")
            .unwrap_or_else(|_| "1".into())
            .parse()?;
        let size: usize = std::env::var("UC_PROBE_PACKET_SIZE")
            .unwrap_or_else(|_| "9".into())
            .parse()?;
        let payload = vec![42_u8; size];
        for _ in 0..packets {
            sender
                .send(ClientToRelayMsg::Datagrams {
                    dst_endpoint_id: SecretKey::from_bytes(&[8; 32]).public(),
                    datagrams: Datagrams {
                        ecn: None,
                        segment_size: None,
                        contents: payload.clone().into(),
                    },
                })
                .await?;
            let message = tokio::time::timeout(Duration::from_secs(15), receiver.next())
                .await?
                .ok_or("closed")??;
            match message {
                RelayToClientMsg::Datagrams {
                    remote_endpoint_id,
                    datagrams,
                } if remote_endpoint_id == SecretKey::from_bytes(&[7; 32]).public()
                    && datagrams.contents.as_ref() == payload.as_slice() =>
                {
                    // Payload and sender identity are checked above.
                }
                _ => return Err("unexpected forwarded message".into()),
            }
        }
        println!("forwarded");
        return Ok(());
    }
    let seed: u8 = args[3].parse()?;
    match connect(&url, auth_token, seed).await {
        Ok(mut client) => {
            println!("connected");
            std::io::stdout().flush()?;
            // Drive the actual connection after policy updates as well as at admission.
            let (commands, mut incoming) = tokio::sync::mpsc::unbounded_channel();
            tokio::task::spawn_blocking(move || {
                for line in std::io::stdin().lock().lines() {
                    let Ok(line) = line else { break };
                    if commands.send(line).is_err() {
                        break;
                    }
                }
            });
            loop {
                tokio::select! {
                    command = incoming.recv() => match command.as_deref() {
                        Some("ping") => client.send(ClientToRelayMsg::Ping(*b"uc-probe")).await?,
                        _ => break,
                    },
                    item = client.next() => match item {
                        Some(Ok(RelayToClientMsg::Pong(payload))) if payload == *b"uc-probe" => {
                            println!("pong");
                            std::io::stdout().flush()?;
                        },
                        Some(Ok(RelayToClientMsg::Ping(payload))) => client.send(ClientToRelayMsg::Pong(payload)).await?,
                        None | Some(Err(_)) => break,
                        _ => {},
                    },
                }
            }
        }
        Err(ConnectError::Handshake {
            source: handshake::Error::ServerDeniedAuth { .. },
            ..
        }) => println!("denied"),
        Err(_) => println!("transport-error"),
    }
    Ok(())
}
