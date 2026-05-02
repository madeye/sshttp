use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use russh::client::{self, AuthResult, Handle};
use russh::keys::key::PrivateKeyWithHashAlg;
use russh::keys::{HashAlg, PublicKey};
use russh::ChannelStream;

use crate::cli::{Keepalive, SshTarget};

#[derive(Debug, Clone)]
pub enum AuthMethod {
    Key {
        path: PathBuf,
        passphrase: Option<String>,
    },
    Agent,
    Password(String),
}

#[derive(Debug, Clone, Copy)]
pub enum HostKeyPolicy {
    StrictKnownHosts,
    AcceptNew,
}

pub struct AuthPlan {
    pub user: String,
    pub methods: Vec<AuthMethod>,
}

struct ClientHandler {
    host: String,
    port: u16,
    known_hosts: PathBuf,
    policy: HostKeyPolicy,
}

impl client::Handler for ClientHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKey,
    ) -> Result<bool, Self::Error> {
        match russh::keys::known_hosts::check_known_hosts_path(
            &self.host,
            self.port,
            server_public_key,
            &self.known_hosts,
        ) {
            Ok(true) => Ok(true),
            Ok(false) => match self.policy {
                HostKeyPolicy::AcceptNew => {
                    if let Err(e) = russh::keys::known_hosts::learn_known_hosts_path(
                        &self.host,
                        self.port,
                        server_public_key,
                        &self.known_hosts,
                    ) {
                        tracing::warn!(error = %e, "failed to record new host key");
                    } else {
                        tracing::info!(
                            host = %self.host,
                            port = self.port,
                            "recorded new host key in known_hosts"
                        );
                    }
                    Ok(true)
                }
                HostKeyPolicy::StrictKnownHosts => {
                    tracing::error!(
                        host = %self.host,
                        port = self.port,
                        "host key not present in {} \u{2014} pass --accept-new-host-keys to trust on first use",
                        self.known_hosts.display()
                    );
                    Ok(false)
                }
            },
            Err(e) => {
                tracing::error!(host = %self.host, port = self.port, error = %e, "host key check failed");
                Ok(false)
            }
        }
    }
}

pub struct SshClient {
    handle: Handle<ClientHandler>,
}

impl SshClient {
    pub async fn connect(
        target: &SshTarget,
        auth: &AuthPlan,
        known_hosts: PathBuf,
        policy: HostKeyPolicy,
        keepalive: Option<Keepalive>,
    ) -> Result<Self> {
        let mut cfg = client::Config::default();
        if let Some(ka) = keepalive {
            cfg.keepalive_interval = Some(Duration::from_secs(ka.interval_secs));
            cfg.keepalive_max = ka.max_missed as usize;
        }
        let config = Arc::new(cfg);
        let handler = ClientHandler {
            host: target.host.clone(),
            port: target.port,
            known_hosts,
            policy,
        };
        let mut handle = client::connect(config, (target.host.as_str(), target.port), handler)
            .await
            .with_context(|| format!("SSH connect to {}:{} failed", target.host, target.port))?;

        authenticate(&mut handle, auth).await?;
        Ok(Self { handle })
    }

    pub async fn open_tunnel(&self, host: &str, port: u16) -> Result<ChannelStream<client::Msg>> {
        let channel = self
            .handle
            .channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0)
            .await
            .with_context(|| format!("SSH direct-tcpip to {host}:{port} failed"))?;
        Ok(channel.into_stream())
    }

    pub async fn shutdown(&self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "client shutdown", "")
            .await;
    }

    pub fn is_closed(&self) -> bool {
        self.handle.is_closed()
    }
}

async fn authenticate(handle: &mut Handle<ClientHandler>, auth: &AuthPlan) -> Result<()> {
    if auth.methods.is_empty() {
        bail!("no authentication methods configured (pass -i, --agent, or --password)");
    }
    let mut last_err: Option<anyhow::Error> = None;
    for method in &auth.methods {
        match try_one(handle, &auth.user, method).await {
            Ok(true) => return Ok(()),
            Ok(false) => {
                tracing::info!(method = %describe(method), "auth method rejected, trying next");
            }
            Err(e) => {
                tracing::warn!(method = %describe(method), error = %e, "auth method errored, trying next");
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("all SSH authentication methods were rejected")))
}

async fn try_one(
    handle: &mut Handle<ClientHandler>,
    user: &str,
    method: &AuthMethod,
) -> Result<bool> {
    match method {
        AuthMethod::Key { path, passphrase } => {
            let key = russh::keys::load_secret_key(path, passphrase.as_deref())
                .with_context(|| format!("failed to load key {}", path.display()))?;
            let hash_alg = handle
                .best_supported_rsa_hash()
                .await
                .ok()
                .flatten()
                .flatten()
                .or(Some(HashAlg::Sha256));
            let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
            Ok(matches!(
                handle.authenticate_publickey(user, key).await?,
                AuthResult::Success
            ))
        }
        AuthMethod::Password(pw) => Ok(matches!(
            handle.authenticate_password(user, pw.as_str()).await?,
            AuthResult::Success
        )),
        AuthMethod::Agent => agent_auth(handle, user).await,
    }
}

async fn agent_auth(handle: &mut Handle<ClientHandler>, user: &str) -> Result<bool> {
    let mut agent = russh::keys::agent::client::AgentClient::connect_env()
        .await
        .context("could not reach ssh-agent (is SSH_AUTH_SOCK set?)")?;
    let identities = agent
        .request_identities()
        .await
        .context("ssh-agent: request_identities failed")?;
    if identities.is_empty() {
        bail!("ssh-agent has no identities loaded");
    }
    let hash_alg = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    for ident in identities {
        let pk = ident.public_key().into_owned();
        match handle
            .authenticate_publickey_with(user, pk, hash_alg, &mut agent)
            .await
        {
            Ok(AuthResult::Success) => return Ok(true),
            Ok(_) => continue,
            Err(e) => {
                tracing::debug!(error = %e, "agent identity rejected");
                continue;
            }
        }
    }
    Ok(false)
}

fn describe(method: &AuthMethod) -> &'static str {
    match method {
        AuthMethod::Key { .. } => "publickey",
        AuthMethod::Agent => "agent",
        AuthMethod::Password(_) => "password",
    }
}
