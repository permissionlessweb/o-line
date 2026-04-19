# Networking

## Akash Ingress + TLS

- Port **80** with `accept:` in SDL -> Akash HTTP ingress (NOT raw NodePort)
- Akash provider nginx-ingress **terminates TLS** — container receives plain HTTP
- Use `listen 80` in container nginx (never `listen 443 ssl`)
- SDL: port 443 with accept is WRONG — always use port 80
- Cloudflare CNAME with `proxied: true` for HTTP services

## P2P Transport

- P2P DNS domains MUST use `proxied: false` (DNS-only, no Cloudflare proxy)
- `P2P_EXT_PORT` env var passes actual Akash NodePort (may differ from SDL port)
- Persistent peers must be refreshed from live RPC `net_info` — stale IPs cause 0-peer isolation

## openssh Gotchas (0.11.6)

- `connect_mux(dst)` accepts `ssh://[user@]host[:port]` — NOT `user@host:port`
- `ssh_dest_path()` must strip http/https scheme before building ssh:// URI
- Default `known_hosts_check` is `KnownHosts::Add` — fine for ephemeral Akash nodes

## openssh-sftp-client (0.15.4)

- Use `create(true).truncate(true)` NOT `create_new(true)` — create_new fails on retry if file exists

## Statesync

Use `rpc.terp.chaintools.tech:443` (rpc.terp.network is dead).
