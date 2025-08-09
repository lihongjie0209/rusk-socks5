# rusk-socks5

A simple, async SOCKS5 proxy server written in Rust.

Features:
- SOCKS5 CONNECT with optional username/password auth
- Anonymous access toggle
- DNS caching with Moka (configurable TTL/capacity, debug hit/miss logs)
- Connection concurrency limit
- Source IP whitelist (CIDR + IPv4 wildcard). If unset, allow all by default

## Build

Requires Rust 1.75+.

- Debug: `cargo build`
- Release: `cargo build --release`

## Run

Examples:

- Anonymous:
```
cargo run -- --address 127.0.0.1 --port 1080 --allow-anonymous
```

- With auth + DNS cache tuning + whitelist + limit:
```
cargo run -- \
  --address 0.0.0.0 --port 1080 \
  --username user --password pass \
  --dns-cache-capacity 20000 --dns-cache-ttl-secs 600 \
  --max-connections 512 \
  --ip-whitelist "192.168.*.*" --ip-whitelist "10.0.0.0/8"
```

Enable debug logs to see DNS cache hit/miss:
- Linux/macOS: `RUST_LOG=debug ...`
- Windows PowerShell: `$env:RUST_LOG = "debug"; ...`

## Configuration (CLI)
- --address string (default 127.0.0.1)
- --port u16 (default 1080)
- --allow-anonymous bool (default false)
- --username string
- --password string
- --dns-cache-capacity u64 (default 10000)
- --dns-cache-ttl-secs u64 (default 300)
- --max-connections usize (default 1024)
- --ip-whitelist [CIDR or IPv4 wildcard], repeatable

## Releases

GitHub Actions builds for Linux, macOS, and Windows. Artifacts are attached to releases.

Manual release steps:
- Create tag: `git tag v0.1.0 && git push origin v0.1.0`
- Workflow will build and publish using `gh` CLI.

## License

MIT
