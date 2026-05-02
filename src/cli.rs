use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{anyhow, Context, Result};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "sshttp",
    version,
    about = "Expose an HTTP CONNECT proxy that tunnels through an SSH session (ssh -D as HTTP)."
)]
pub struct Args {
    /// SSH target in `user@host[:port]` form (port defaults to 22).
    pub target: String,

    /// HTTP CONNECT bind address.
    #[arg(short = 'L', long, default_value = "127.0.0.1:8080")]
    pub listen: SocketAddr,

    /// Private key file. Repeat to try multiple keys.
    #[arg(short = 'i', long, env = "SSHTTP_IDENTITY")]
    pub identity: Vec<PathBuf>,

    /// Read key passphrase from stdin instead of prompting on the TTY.
    #[arg(long)]
    pub passphrase_stdin: bool,

    /// Try ssh-agent (`$SSH_AUTH_SOCK`).
    #[arg(long)]
    pub agent: bool,

    /// Try password auth (prompted unless `--password-stdin`).
    #[arg(long)]
    pub password: bool,

    /// Read password from stdin.
    #[arg(long)]
    pub password_stdin: bool,

    /// known_hosts file path.
    #[arg(long)]
    pub known_hosts: Option<PathBuf>,

    /// Append unknown server keys to known_hosts (TOFU).
    #[arg(long)]
    pub accept_new_host_keys: bool,

    /// Seconds between SSH keepalives, and TCP keepalive probe interval on the
    /// HTTP listener side. Set to 0 with --no-keepalive to disable.
    #[arg(long, default_value_t = 15, value_name = "SECS")]
    pub keepalive_interval: u64,

    /// Drop the SSH session after this many missed keepalives.
    #[arg(long, default_value_t = 3, value_name = "COUNT")]
    pub keepalive_max: u32,

    /// Disable both SSH and TCP keepalives (not recommended over NAT/CGNAT).
    #[arg(long)]
    pub no_keepalive: bool,

    /// Increase log level. -v=info, -vv=debug, -vvv=trace.
    #[arg(short = 'v', long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Keepalive {
    pub interval_secs: u64,
    pub max_missed: u32,
}

#[derive(Debug, Clone)]
pub struct SshTarget {
    pub user: String,
    pub host: String,
    pub port: u16,
}

impl Args {
    pub fn parse_target(&self) -> Result<SshTarget> {
        let (user, rest) = self
            .target
            .split_once('@')
            .ok_or_else(|| anyhow!("SSH target must be `user@host[:port]`"))?;
        let (host, port) = match rest.rsplit_once(':') {
            Some((h, p)) if !h.contains(':') || h.starts_with('[') => {
                let host = h.trim_start_matches('[').trim_end_matches(']').to_string();
                let port: u16 = p.parse().context("invalid SSH port")?;
                (host, port)
            }
            _ => (rest.to_string(), 22),
        };
        if user.is_empty() || host.is_empty() {
            return Err(anyhow!("SSH target must be `user@host[:port]`"));
        }
        Ok(SshTarget {
            user: user.to_string(),
            host,
            port,
        })
    }

    pub fn known_hosts_path(&self) -> Result<PathBuf> {
        if let Some(p) = &self.known_hosts {
            return Ok(p.clone());
        }
        let home = dirs::home_dir().ok_or_else(|| anyhow!("could not locate home directory"))?;
        Ok(home.join(".ssh").join("known_hosts"))
    }

    pub fn keepalive(&self) -> Option<Keepalive> {
        if self.no_keepalive || self.keepalive_interval == 0 {
            None
        } else {
            Some(Keepalive {
                interval_secs: self.keepalive_interval,
                max_missed: self.keepalive_max,
            })
        }
    }

    pub fn log_level(&self) -> &'static str {
        match self.verbose {
            0 => "warn",
            1 => "info",
            2 => "debug",
            _ => "trace",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args_with_target(target: &str) -> Args {
        Args::parse_from(["sshttp", target])
    }

    #[test]
    fn parses_user_host_default_port() {
        let t = args_with_target("alice@bastion.example.com")
            .parse_target()
            .unwrap();
        assert_eq!(t.user, "alice");
        assert_eq!(t.host, "bastion.example.com");
        assert_eq!(t.port, 22);
    }

    #[test]
    fn parses_user_host_explicit_port() {
        let t = args_with_target("bob@1.2.3.4:2222").parse_target().unwrap();
        assert_eq!(t.user, "bob");
        assert_eq!(t.host, "1.2.3.4");
        assert_eq!(t.port, 2222);
    }

    #[test]
    fn parses_ipv6_with_port() {
        let t = args_with_target("carol@[::1]:2200").parse_target().unwrap();
        assert_eq!(t.host, "::1");
        assert_eq!(t.port, 2200);
    }

    #[test]
    fn rejects_target_without_user() {
        assert!(args_with_target("bastion.example.com")
            .parse_target()
            .is_err());
    }

    #[test]
    fn keepalive_default_is_15s_3() {
        let ka = args_with_target("alice@host").keepalive().unwrap();
        assert_eq!(ka.interval_secs, 15);
        assert_eq!(ka.max_missed, 3);
    }

    #[test]
    fn keepalive_disabled_by_no_keepalive_flag() {
        let args = Args::parse_from(["sshttp", "--no-keepalive", "alice@host"]);
        assert!(args.keepalive().is_none());
    }

    #[test]
    fn keepalive_disabled_by_zero_interval() {
        let args = Args::parse_from(["sshttp", "--keepalive-interval", "0", "alice@host"]);
        assert!(args.keepalive().is_none());
    }

    #[test]
    fn keepalive_custom_values() {
        let args = Args::parse_from([
            "sshttp",
            "--keepalive-interval",
            "30",
            "--keepalive-max",
            "5",
            "alice@host",
        ]);
        let ka = args.keepalive().unwrap();
        assert_eq!(ka.interval_secs, 30);
        assert_eq!(ka.max_missed, 5);
    }
}
