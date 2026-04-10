# ── VPN / WireGuard ───────────────────────────────────────────────────────────

# Bootstrap WireGuard on pfSense.
#
# Required env vars:
#   PFSENSE_PASSWORD  — store encryption + SSH password
#
# Optional env vars:
#   VPN_SERVER_ADDR   — VPN subnet (default: 10.99.0.1/24)
#   VPN_PORT          — UDP listen port (default: 51820)
#   VPN_IFACE         — WireGuard interface (default: wg0)
#   VPN_ENDPOINT      — WAN endpoint hint (e.g. 1.2.3.4:51820)
#   PFSENSE_LABEL     — firewall label (auto-selects if only one)
#
# Example:
#   PFSENSE_PASSWORD=<pw> just vpn-bootstrap
#   PFSENSE_PASSWORD=<pw> VPN_SERVER_ADDR=10.88.0.1/24 just vpn-bootstrap
vpn-bootstrap:
    #!/usr/bin/env bash
    set -euo pipefail
    args=(bootstrap)
    [[ -n "${VPN_SERVER_ADDR:-}" ]] && args+=(--server-addr "$VPN_SERVER_ADDR")
    [[ -n "${VPN_PORT:-}"        ]] && args+=(--port "$VPN_PORT")
    [[ -n "${VPN_IFACE:-}"       ]] && args+=(--iface "$VPN_IFACE")
    [[ -n "${VPN_ENDPOINT:-}"    ]] && args+=(--endpoint "$VPN_ENDPOINT")
    [[ -n "${PFSENSE_LABEL:-}"   ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# Add a WireGuard peer and optionally push config to a client machine.
#
# Required:
#   PEER_NAME  — peer name (e.g. "laptop", "alice")
#
# Optional:
#   PEER_ADDR       — VPN address (auto-assigned if not set)
#   PEER_ALLOWED_IPS — allowed IPs (default: 0.0.0.0/0)
#   PEER_PUSH_TO    — push config to [user@]host[:port]
#   PFSENSE_LABEL   — firewall label
#   PFSENSE_PASSWORD — store password
#
# Example:
#   PEER_NAME=laptop PFSENSE_PASSWORD=<pw> just vpn-add-peer
#   PEER_NAME=laptop PEER_PUSH_TO=alice@192.168.1.50 PFSENSE_PASSWORD=<pw> just vpn-add-peer
vpn-add-peer:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${PEER_NAME:?PEER_NAME is required (e.g. PEER_NAME=laptop just vpn-add-peer)}"
    args=(add-peer "$PEER_NAME")
    [[ -n "${PEER_ADDR:-}"        ]] && args+=(--peer-addr "$PEER_ADDR")
    [[ -n "${PEER_ALLOWED_IPS:-}" ]] && args+=(--allowed-ips "$PEER_ALLOWED_IPS")
    [[ -n "${PEER_PUSH_TO:-}"     ]] && args+=(--push-to "$PEER_PUSH_TO")
    [[ -n "${PFSENSE_LABEL:-}"    ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# Revoke a WireGuard peer.
#
# Required:
#   PEER_NAME  — peer name to revoke
#
# Example:
#   PEER_NAME=laptop PFSENSE_PASSWORD=<pw> just vpn-revoke-peer
vpn-revoke-peer:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${PEER_NAME:?PEER_NAME is required (e.g. PEER_NAME=laptop just vpn-revoke-peer)}"
    args=(revoke-peer "$PEER_NAME")
    [[ -n "${PFSENSE_LABEL:-}" ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# List all VPN peers from the store.
#
# Example:
#   PFSENSE_PASSWORD=<pw> just vpn-list
vpn-list:
    #!/usr/bin/env bash
    set -euo pipefail
    args=(list)
    [[ -n "${PFSENSE_LABEL:-}" ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# Show WireGuard status from pfSense (`wg show wg0`).
#
# Example:
#   PFSENSE_PASSWORD=<pw> just vpn-status
vpn-status:
    #!/usr/bin/env bash
    set -euo pipefail
    args=(status)
    [[ -n "${PFSENSE_LABEL:-}" ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# Configure DDNS for the WireGuard WAN endpoint.
#
# Required:
#   DDNS_PROVIDER  — duckdns or cloudflare
#   DDNS_DOMAIN    — subdomain (e.g. myvpn for duckdns, or vpn.example.com for cloudflare)
#   DDNS_TOKEN     — API token
#
# Example:
#   DDNS_PROVIDER=duckdns DDNS_DOMAIN=myvpn DDNS_TOKEN=<token> PFSENSE_PASSWORD=<pw> just vpn-ddns
vpn-ddns:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${DDNS_PROVIDER:?DDNS_PROVIDER is required (duckdns or cloudflare)}"
    : "${DDNS_DOMAIN:?DDNS_DOMAIN is required}"
    args=(ddns --provider "$DDNS_PROVIDER" --domain "$DDNS_DOMAIN")
    [[ -n "${DDNS_TOKEN:-}"    ]] && args+=(--token "$DDNS_TOKEN")
    [[ -n "${PFSENSE_LABEL:-}" ]] && args+=(--firewall "$PFSENSE_LABEL")
    PFSENSE_PASSWORD="${PFSENSE_PASSWORD:-}" cargo run --bin oline -- vpn "${args[@]}"

# ── VPN Tests ────────────────────────────────────────────────────────────────
# Moved to testing.just → `just test vpn`, `just test vpn-e2e`
