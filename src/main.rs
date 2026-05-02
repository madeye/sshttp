mod cli;
mod http;
mod ssh;

use std::io::{self, IsTerminal, Read};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::cli::Args;
use crate::ssh::{AuthMethod, AuthPlan, HostKeyPolicy, SshClient};

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    init_tracing(&args);

    let target = args.parse_target()?;
    let known_hosts = args.known_hosts_path()?;
    let policy = if args.accept_new_host_keys {
        HostKeyPolicy::AcceptNew
    } else {
        HostKeyPolicy::StrictKnownHosts
    };
    let auth = build_auth_plan(&args, &target.user)?;
    let keepalive = args.keepalive();

    tracing::info!(
        host = %target.host,
        port = target.port,
        user = %target.user,
        keepalive = ?keepalive,
        "connecting to SSH server"
    );
    let ssh = SshClient::connect(&target, &auth, known_hosts, policy, keepalive)
        .await
        .context("SSH session setup failed")?;
    tracing::info!("SSH session established");
    let ssh = Arc::new(ssh);

    let serve = tokio::spawn({
        let ssh = Arc::clone(&ssh);
        let listen = args.listen;
        async move { http::serve(listen, ssh, keepalive).await }
    });

    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutdown requested");
        }
        res = serve => {
            match res {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "HTTP listener exited");
                    ssh.shutdown().await;
                    return Err(e);
                }
                Err(e) => {
                    tracing::error!(error = %e, "HTTP task panicked");
                    ssh.shutdown().await;
                    bail!("HTTP listener task panicked: {e}");
                }
            }
        }
    }

    ssh.shutdown().await;
    Ok(())
}

fn init_tracing(args: &Args) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("sshttp={}", args.log_level())));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .init();
}

fn build_auth_plan(args: &Args, user: &str) -> Result<AuthPlan> {
    let mut methods = Vec::new();

    for path in &args.identity {
        let passphrase = if args.passphrase_stdin {
            Some(read_secret_stdin("passphrase")?)
        } else {
            None
        };
        methods.push(AuthMethod::Key {
            path: path.clone(),
            passphrase,
        });
    }

    if args.agent {
        methods.push(AuthMethod::Agent);
    }

    if args.password {
        let pw = if args.password_stdin {
            read_secret_stdin("password")?
        } else if io::stdin().is_terminal() {
            rpassword::prompt_password(format!("Password for {user}: "))
                .context("password prompt failed")?
        } else {
            bail!("password auth requested but stdin is not a TTY (use --password-stdin)");
        };
        methods.push(AuthMethod::Password(pw));
    }

    if methods.is_empty() {
        bail!("no auth method selected (pass -i KEYFILE, --agent, or --password)");
    }

    Ok(AuthPlan {
        user: user.to_string(),
        methods,
    })
}

fn read_secret_stdin(label: &str) -> Result<String> {
    let mut s = String::new();
    io::stdin()
        .read_to_string(&mut s)
        .with_context(|| format!("read {label} from stdin"))?;
    while s.ends_with('\n') || s.ends_with('\r') {
        s.pop();
    }
    Ok(s)
}
