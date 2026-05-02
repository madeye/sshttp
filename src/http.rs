use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use socket2::{SockRef, TcpKeepalive};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::cli::Keepalive;
use crate::ssh::SshClient;

const MAX_HEADER_BYTES: usize = 8 * 1024;

pub async fn serve(
    listen: SocketAddr,
    ssh: Arc<SshClient>,
    keepalive: Option<Keepalive>,
) -> Result<()> {
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("bind {listen} failed"))?;
    tracing::info!(%listen, keepalive = ?keepalive, "HTTP CONNECT proxy listening");

    loop {
        let (sock, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                continue;
            }
        };
        if let Some(ka) = keepalive {
            if let Err(e) = apply_tcp_keepalive(&sock, ka) {
                tracing::debug!(%peer, error = %e, "could not set TCP keepalive on accepted socket");
            }
        }
        let ssh = Arc::clone(&ssh);
        tokio::spawn(async move {
            if let Err(e) = handle_conn(sock, ssh).await {
                tracing::warn!(%peer, error = %e, "connection failed");
            }
        });
    }
}

fn apply_tcp_keepalive(sock: &TcpStream, ka: Keepalive) -> std::io::Result<()> {
    let interval = Duration::from_secs(ka.interval_secs);
    // Idle time before the first probe. 4x interval keeps probing off the wire
    // on healthy idle connections.
    let idle = interval.saturating_mul(4);
    let probes = TcpKeepalive::new()
        .with_time(idle)
        .with_interval(interval)
        .with_retries(ka.max_missed);
    SockRef::from(sock).set_tcp_keepalive(&probes)
}

async fn handle_conn(mut sock: TcpStream, ssh: Arc<SshClient>) -> Result<()> {
    let (target, leftover) = match read_request(&mut sock).await {
        Ok(v) => v,
        Err(ParseError::TooLarge) => {
            let _ = sock
                .write_all(
                    b"HTTP/1.1 431 Request Header Fields Too Large\r\nConnection: close\r\n\r\n",
                )
                .await;
            return Ok(());
        }
        Err(ParseError::NotConnect) => {
            let _ = sock
                .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nAllow: CONNECT\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
        Err(ParseError::Malformed(msg)) => {
            let body = format!(
                "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: {}\r\n\r\n{}",
                msg.len(),
                msg
            );
            let _ = sock.write_all(body.as_bytes()).await;
            return Ok(());
        }
        Err(ParseError::Io(e)) => return Err(e.into()),
    };

    if ssh.is_closed() {
        let _ = sock
            .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\nSSH session closed")
            .await;
        return Ok(());
    }

    let mut tunnel = match ssh.open_tunnel(&target.host, target.port).await {
        Ok(t) => t,
        Err(e) => {
            tracing::info!(host = %target.host, port = target.port, error = %e, "tunnel open failed");
            let body = format!("HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n{e}");
            let _ = sock.write_all(body.as_bytes()).await;
            return Ok(());
        }
    };

    sock.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    if !leftover.is_empty() {
        tunnel.write_all(&leftover).await?;
    }

    let (from_client, from_server) = tokio::io::copy_bidirectional(&mut sock, &mut tunnel).await?;
    tracing::debug!(
        host = %target.host,
        port = target.port,
        bytes_up = from_client,
        bytes_down = from_server,
        "tunnel closed"
    );
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectTarget {
    host: String,
    port: u16,
}

#[derive(Debug)]
enum ParseError {
    TooLarge,
    NotConnect,
    Malformed(&'static str),
    Io(std::io::Error),
}

impl From<std::io::Error> for ParseError {
    fn from(e: std::io::Error) -> Self {
        ParseError::Io(e)
    }
}

async fn read_request(sock: &mut TcpStream) -> Result<(ConnectTarget, Vec<u8>), ParseError> {
    let mut buf = Vec::with_capacity(512);
    let mut tmp = [0u8; 1024];
    loop {
        if buf.len() > MAX_HEADER_BYTES {
            return Err(ParseError::TooLarge);
        }
        if let Some(end) = find_header_end(&buf) {
            let head = &buf[..end];
            let target = parse_connect(head)?;
            let leftover = buf[end..].to_vec();
            return Ok((target, leftover));
        }
        let n = sock.read(&mut tmp).await?;
        if n == 0 {
            return Err(ParseError::Malformed("connection closed before request"));
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

fn parse_connect(head: &[u8]) -> Result<ConnectTarget, ParseError> {
    let line_end = head
        .windows(2)
        .position(|w| w == b"\r\n")
        .ok_or(ParseError::Malformed("missing request line"))?;
    let line = std::str::from_utf8(&head[..line_end])
        .map_err(|_| ParseError::Malformed("non-UTF-8 request line"))?;
    let mut parts = line.split(' ');
    let method = parts
        .next()
        .ok_or(ParseError::Malformed("empty request line"))?;
    let target = parts
        .next()
        .ok_or(ParseError::Malformed("missing request target"))?;
    let _version = parts
        .next()
        .ok_or(ParseError::Malformed("missing HTTP version"))?;
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(ParseError::NotConnect);
    }
    parse_authority(target).ok_or(ParseError::Malformed("invalid CONNECT target"))
}

fn parse_authority(s: &str) -> Option<ConnectTarget> {
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let after = &rest[end + 1..];
        let port_str = after.strip_prefix(':')?;
        let port: u16 = port_str.parse().ok()?;
        return Some(ConnectTarget {
            host: host.to_string(),
            port,
        });
    }
    let (host, port) = s.rsplit_once(':')?;
    if host.is_empty() {
        return None;
    }
    let port: u16 = port.parse().ok()?;
    Some(ConnectTarget {
        host: host.to_string(),
        port,
    })
}

#[allow(dead_code)]
fn parse_connect_for_test(head: &[u8]) -> Result<ConnectTarget, &'static str> {
    match parse_connect(head) {
        Ok(t) => Ok(t),
        Err(ParseError::Malformed(m)) => Err(m),
        Err(ParseError::NotConnect) => Err("not CONNECT"),
        Err(ParseError::TooLarge) => Err("too large"),
        Err(ParseError::Io(_)) => Err("io"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(head: &[u8]) -> Result<ConnectTarget, &'static str> {
        parse_connect_for_test(head)
    }

    #[test]
    fn parses_simple_connect() {
        let t =
            parse(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n").unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn parses_connect_ipv6() {
        let t = parse(b"CONNECT [2001:db8::1]:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(t.host, "2001:db8::1");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn rejects_non_connect() {
        assert_eq!(parse(b"GET / HTTP/1.1\r\n\r\n").unwrap_err(), "not CONNECT");
    }

    #[test]
    fn rejects_missing_port() {
        assert!(parse(b"CONNECT example.com HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn rejects_bad_port() {
        assert!(parse(b"CONNECT example.com:abc HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn finds_header_end() {
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n\r\n"), Some(18));
        assert_eq!(find_header_end(b"GET / HTTP/1.1\r\n"), None);
    }

    #[test]
    fn rejects_empty_host() {
        assert!(parse(b"CONNECT :443 HTTP/1.1\r\n\r\n").is_err());
    }

    #[test]
    fn parses_connect_with_extra_headers() {
        let head = b"CONNECT example.com:443 HTTP/1.1\r\n\
                     Host: example.com:443\r\n\
                     Proxy-Connection: keep-alive\r\n\
                     User-Agent: curl/8\r\n\r\n";
        let t = parse(head).unwrap();
        assert_eq!(t.host, "example.com");
        assert_eq!(t.port, 443);
    }

    #[test]
    fn rejects_lf_only_line_endings() {
        // No CRLF — find_header_end returns None, parse_connect would never see this
        // in practice, but the request-line parser must still reject if asked.
        assert!(parse(b"CONNECT example.com:443 HTTP/1.1\n\n").is_err());
    }

    #[test]
    fn rejects_short_request_line() {
        assert!(parse(b"CONNECT\r\n\r\n").is_err());
        assert!(parse(b"CONNECT example.com:443\r\n\r\n").is_err());
    }

    #[test]
    fn accepts_lowercase_method() {
        let t = parse(b"connect example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(t.host, "example.com");
    }

    #[test]
    fn rejects_port_out_of_range() {
        assert!(parse(b"CONNECT example.com:99999 HTTP/1.1\r\n\r\n").is_err());
    }
}
