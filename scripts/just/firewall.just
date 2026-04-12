# ── Firewall / pfSense ────────────────────────────────────────────────────────

# Raw bootstrap — pass any flags directly.
# Prerequisite: SSH pubkey on pfSense (web GUI or ssh-copy-id).
#
# Usage:
#   just pfsense admin@192.168.1.1 -i ~/.ssh/oline-server --client-ip 192.168.1.1
#   just pfsense admin@192.168.1.1 -i ~/.ssh/oline-server --reset
pfsense *args:
    bash plays/audible/pfsense-bootstrap.sh {{args}}

# Open WAN SSH + ProxyJump + tunnels to a LAN server through pfSense.
# Can be run from EITHER the oline-server (LAN side) OR the client device.
# Context is auto-detected: if CLIENT_IP matches a local IP, runs in client mode
# and writes SSH config directly to ~/.ssh/config; otherwise pushes to client.
#
# Required env vars:
#   CLIENT_IP     — client WAN IP (e.g. 192.168.1.1)
#
# Optional env vars (with defaults):
#   PF_LAN          — pfSense LAN/host IP         [192.168.1.1]
#   PF_USER         — pfSense SSH user             [admin]
#   PF_KEY          — SSH key for pfSense access   [~/.ssh/oline-server OR ~/.ssh/oline-client]
#   PF_P         — pfSense SSH port             [22]
#   CLIENT_KEY      — client SSH key (embedded in generated config)  [~/.ssh/oline-client]
#   PROXY_TARGET    — USER@IP to reach via ProxyJump  [rhonine@123.456.1.123]
#   TUNNELS         — space-separated LOCAL:HOST:PORT
#   STATIC_IP       — MAC:IP for DHCP static mapping
#   CLIENT_USER     — SSH user on client (server mode only, for auto-push)
#   CLIENT_LAN_IP   — client's LAN IP (server mode only, for auto-push)
#   REVERSE_TUNNEL  — USER@HOST[:PORT] pfSense calls home here on boot
#                     e.g. "root@192.168.1.101:2222" → groot:2222 → pfSense:22
#
# Examples (from server):
#   CLIENT_IP=192.168.1.1 just pfsense-connect
#   CLIENT_IP=192.168.1.1 REVERSE_TUNNEL=root@192.168.1.101:2222 just pfsense-connect
#
# Examples (from client device):
#   CLIENT_IP=192.168.1.1 PF_KEY=~/.ssh/oline-client just pfsense-connect
pfsense-connect:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${CLIENT_IP:?CLIENT_IP is required (e.g. CLIENT_IP=192.168.1.1 just pfsense-connect)}"
    args=(
        "${PF_USER:-admin}@${PF_LAN:-192.168.1.1}"
        -i "${PF_KEY:-$HOME/.ssh/oline-server}"
        --client-ip "$CLIENT_IP"
        --client-key "${CLIENT_KEY:-~/.ssh/oline-client}"
    )
    [[ -n "${PF_P:-}" ]] && args+=(-p "$PF_P")
    [[ -n "${PROXY_TARGET:-}" ]] && args+=(--proxy "$PROXY_TARGET")
    [[ -n "${STATIC_IP:-}" ]] && args+=(--static-ip "$STATIC_IP")
    [[ -n "${CLIENT_USER:-}" ]] && args+=(--client-user "$CLIENT_USER")
    [[ -n "${CLIENT_LAN_IP:-}" ]] && args+=(--client-lan-ip "$CLIENT_LAN_IP")
    for tun in ${TUNNELS:-}; do
        args+=(--tunnel "$tun")
    done
    [[ -n "${REVERSE_TUNNEL:-}" ]] && args+=(--reverse-tunnel "$REVERSE_TUNNEL")
    bash plays/audible/pfsense-bootstrap.sh "${args[@]}"

# Reset all oline-managed pfSense rules (firewall + NAT).
#
# Optional env vars:
#   PF_LAN  [192.168.1.1]  PF_USER [admin]  PF_KEY [~/.ssh/oline-server]
pfsense-reset:
    #!/usr/bin/env bash
    set -euo pipefail
    bash plays/audible/pfsense-bootstrap.sh \
        "${PF_USER:-admin}@${PF_LAN:-192.168.1.1}" \
        -i "${PF_KEY:-$HOME/.ssh/oline-server}" \
        ${PF_P:+-p $PF_P} \
        --reset

# Change pfSense LAN subnet (fixes WAN/LAN collision).
#
# Required: NEW_LAN — new LAN gateway IP (e.g. 192.168.2.1)
# Optional: PF_LAN [192.168.1.1]  PF_USER [admin]  PF_KEY [~/.ssh/oline-server]
pfsense-resubnet:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${NEW_LAN:?NEW_LAN is required (e.g. NEW_LAN=192.168.2.1 just pfsense-resubnet)}"
    bash plays/audible/pfsense-bootstrap.sh \
        "${PF_USER:-admin}@${PF_LAN:-192.168.1.1}" \
        -i "${PF_KEY:-$HOME/.ssh/oline-server}" \
        ${PF_P:+-p $PF_P} \
        --resubnet "$NEW_LAN"

# ── Service Exposure ─────────────────────────────────────────────────────────
# Manage which oline-server ports are accessible via SSH tunnel.
# Run ON oline-server (groot).
#
# SSH PermitOpen enforcement (run with sudo to restrict to listed ports only):
#   sudo just expose add opencode 49976 --desc "OpenCode web UI"
#   sudo just expose status
#   sudo just expose apply
#
# Examples (no sudo = registry only, no SSH enforcement):
#   just expose add opencode 49976 --desc "OpenCode web UI"
#   just expose add grafana   3000 --desc "Grafana dashboard"
#   just expose remove grafana
#   just expose list
#   just expose status
# Set EXPOSE_SUDO=1 to run with sudo (needed for SSH PermitOpen enforcement):
#   EXPOSE_SUDO=1 just expose restrict
#   EXPOSE_SUDO=1 just expose apply
expose *args:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ "${EXPOSE_SUDO:-}" == "1" ]]; then
        sudo bash plays/audible/expose.sh {{args}}
    else
        bash plays/audible/expose.sh {{args}}
    fi

# ── Tunnel Management ────────────────────────────────────────────────────────
# Manage SSH tunnels through pfSense to LAN services (APIs, UIs, etc).
# Run on the client device (e.g. chevy-tahoe).
#
# Recommended workflow:
#   # 1. On oline-server: register services
#   just expose add opencode 49976 --desc "OpenCode web UI"
#
#   # 2. On client: sync service list + start tunnel
#   just tunnel sync   # pulls registry, sets up LocalForward entries
#   just tunnel up     # each service at http://localhost:PORT
#
# Manual port pin (bypasses registry sync):
#   just tunnel add 192.168.1.101:49976
#   just tunnel list
#   just tunnel up
#   just tunnel down
tunnel *args:
    bash plays/audible/pfsense-tunnel.sh {{args}}

# ── Firewall Tests ───────────────────────────────────────────────────────────
# Moved to testing.just → `just test firewall`, `just test firewall-integration`, etc.
