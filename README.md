# sshttp

An HTTP `CONNECT` proxy that tunnels every request through a single SSH session
— think `ssh -D`, but it speaks HTTP instead of SOCKS5 so any tool that honors
`https_proxy` can use it directly.

## Build

```
cargo build --release
```

## Run

```
sshttp [OPTIONS] <user@host[:port]>

  -L, --listen <ADDR>         HTTP CONNECT bind address [default: 127.0.0.1:8080]
  -i, --identity <PATH>       Private key file (repeat for multiple keys)
      --passphrase-stdin      Read key passphrase from stdin
      --agent                 Use ssh-agent
      --password              Use password auth
      --password-stdin        Read password from stdin
      --known-hosts <PATH>    [default: ~/.ssh/known_hosts]
      --accept-new-host-keys  Trust unknown server keys on first use (TOFU)
  -v, --verbose...            -v info, -vv debug, -vvv trace
```

Auth methods are tried in order: keys → agent → password.

## Smoke test

```
# Terminal 1
sshttp -i ~/.ssh/id_ed25519 -L 127.0.0.1:8080 me@bastion.example.com -v

# Terminal 2
curl -x http://127.0.0.1:8080 https://api.ipify.org   # prints bastion's egress IP
HTTPS_PROXY=http://127.0.0.1:8080 git ls-remote https://github.com/rust-lang/rust
```

## Notes

- Only HTTPS-style `CONNECT` is supported. Plain HTTP forward proxying is not.
- The server's host key must be in `known_hosts`; otherwise pass
  `--accept-new-host-keys` for trust-on-first-use.
- Bind to loopback. There is no proxy authentication.
