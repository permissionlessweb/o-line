#!/usr/bin/env bash
# pfsense-tunnel.sh — SOCKS proxy + port tunnels through pfSense to LAN.
#
# Default mode: SOCKS proxy — all localhost ports on the remote server
# are accessible without configuring individual ports.
#
# Usage:
#   pfsense-tunnel.sh up                         Start SOCKS proxy (all ports)
#   pfsense-tunnel.sh down                       Stop proxy
#   pfsense-tunnel.sh status                     Show proxy status
#   pfsense-tunnel.sh test   [HOST:PORT]         Test connectivity
#   pfsense-tunnel.sh add    HOST:PORT [--local-port N]   Pin a specific port
#   pfsense-tunnel.sh remove HOST:PORT           Remove a pinned port
#   pfsense-tunnel.sh list                       Show pinned ports
#
# After `up`, access oline-server services:
#   curl --socks5 localhost:1080 http://localhost:49976
#   # Or configure browser SOCKS5 proxy → localhost:1080
#   # Or use pinned ports for direct localhost:PORT access
#
# Environment:
#   PF_WAN        pfSense WAN IP          [192.168.1.168]
#   PF_USER       pfSense SSH user        [admin]
#   PF_KEY        SSH key (client side)    [~/.ssh/oline-client]
#   PF_PORT       pfSense SSH port        [22]
#   TUNNEL_USER   user on tunnel target   [rhonine]
#   TUNNEL_HOST   tunnel target IP         [192.168.1.101]
#   SOCKS_PORT    local SOCKS proxy port  [1080]
#   SSH_CONFIG    SSH config path          [~/.ssh/config]
set -euo pipefail

PF_WAN="${PF_WAN:-192.168.1.168}"
PF_USER="${PF_USER:-admin}"
PF_KEY="${PF_KEY:-$HOME/.ssh/oline-client}"
PF_PORT="${PF_PORT:-22}"
TUNNEL_USER="${TUNNEL_USER:-rhonine}"
TUNNEL_HOST="${TUNNEL_HOST:-192.168.1.101}"
SOCKS_PORT="${SOCKS_PORT:-1080}"
SSH_CONFIG="${SSH_CONFIG:-$HOME/.ssh/config}"
TUNNEL_HOST_LABEL="oline-tunnels"
PF_HOST_LABEL="pfsense"
PID_FILE="/tmp/oline-tunnels.pid"
PAC_FILE="/tmp/oline-proxy.pac"

# ── Helpers ──────────────────────────────────────────────────────────────────

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo "  $*"; }

port_in_use() { lsof -i :"$1" &>/dev/null; }

# Detect the active macOS network interface (Wi-Fi, Ethernet, etc.)
get_active_interface() {
    local svc
    # Get the network service name for the default route interface
    local iface
    iface=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}') || true
    [[ -z "$iface" ]] && return
    # Map interface name (en0, en1) to networksetup service name (Wi-Fi, Ethernet)
    while IFS= read -r svc; do
        local dev
        dev=$(networksetup -listallhardwareports 2>/dev/null | awk -v s="$svc" '
            $0 ~ "Hardware Port: "s { found=1; next }
            found && /^Device:/ { print $2; exit }
        ') || true
        if [[ "$dev" == "$iface" ]]; then
            echo "$svc"
            return
        fi
    done < <(networksetup -listallnetworkservices 2>/dev/null | tail -n +2)
}

find_free_port() {
    local port="$1"
    while port_in_use "$port"; do port=$((port + 1)); done
    echo "$port"
}

# ── SSH Config Management ───────────────────────────────────────────────────

ensure_config() {
    mkdir -p "$(dirname "$SSH_CONFIG")"
    [[ -f "$SSH_CONFIG" ]] || touch "$SSH_CONFIG"

    # pfSense jump host
    if ! grep -q "^Host ${PF_HOST_LABEL}$" "$SSH_CONFIG" 2>/dev/null; then
        info "Adding Host ${PF_HOST_LABEL} to $SSH_CONFIG"
        printf '\n%s\n' \
            "Host ${PF_HOST_LABEL}" \
            "  HostName ${PF_WAN}" \
            "  User ${PF_USER}" \
            "  Port ${PF_PORT}" \
            "  IdentityFile ${PF_KEY}" \
            "  StrictHostKeyChecking no" \
            "  UserKnownHostsFile /dev/null" \
        >> "$SSH_CONFIG"
    fi

    # Tunnel host (ProxyJump through pfSense → oline-server)
    if ! grep -q "^Host ${TUNNEL_HOST_LABEL}$" "$SSH_CONFIG" 2>/dev/null; then
        info "Adding Host ${TUNNEL_HOST_LABEL} to $SSH_CONFIG"
        printf '\n%s\n' \
            "Host ${TUNNEL_HOST_LABEL}" \
            "  HostName ${TUNNEL_HOST}" \
            "  User ${TUNNEL_USER}" \
            "  IdentityFile ${PF_KEY}" \
            "  ProxyJump ${PF_HOST_LABEL}" \
            "  DynamicForward ${SOCKS_PORT}" \
            "  ServerAliveInterval 30" \
            "  ServerAliveCountMax 3" \
        >> "$SSH_CONFIG"
    fi
}

host_block_lines() {
    local label="$1"
    awk -v label="$label" '
        /^Host / { if (found) { print start, NR-1; found=0 }; if ($2 == label) { found=1; start=NR } }
        END { if (found) print start, NR }
    ' "$SSH_CONFIG"
}

get_forwards() {
    local range
    range=$(host_block_lines "$TUNNEL_HOST_LABEL")
    [[ -z "$range" ]] && return
    local start end
    read -r start end <<< "$range"
    sed -n "${start},${end}p" "$SSH_CONFIG" | grep "LocalForward" | sed 's/^[[:space:]]*//' || true
}

get_socks_port() {
    local range
    range=$(host_block_lines "$TUNNEL_HOST_LABEL")
    [[ -z "$range" ]] && { echo "$SOCKS_PORT"; return; }
    local start end
    read -r start end <<< "$range"
    local port
    port=$(sed -n "${start},${end}p" "$SSH_CONFIG" | grep "DynamicForward" | awk '{print $2}' | head -1 || true)
    echo "${port:-$SOCKS_PORT}"
}

# ── Commands ─────────────────────────────────────────────────────────────────

cmd_up() {
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        info "Already running (PID $(cat "$PID_FILE")). Use '$0 down' first."
        return 0
    fi

    ensure_config

    local sport
    sport=$(get_socks_port)

    # Check SOCKS port
    if port_in_use "$sport"; then
        die "Port $sport already in use. Set SOCKS_PORT=<port> or stop the existing process."
    fi

    echo "Starting tunnel to ${TUNNEL_HOST} via pfSense (${PF_WAN}) ..."
    ssh -f -N -o ExitOnForwardFailure=yes "${TUNNEL_HOST_LABEL}" 2>/dev/null

    sleep 1
    local pid
    pid=$(pgrep -f "ssh.*-N.*${TUNNEL_HOST_LABEL}" 2>/dev/null | head -1 || true)
    if [[ -n "$pid" ]]; then
        echo "$pid" > "$PID_FILE"
        echo "Tunnel active (PID ${pid})."
    else
        die "Failed to start tunnel. Run: ssh -v -N ${TUNNEL_HOST_LABEL}"
    fi

    echo ""
    echo "  SOCKS proxy:  localhost:${sport}"

    # Show pinned LocalForward ports
    local forwards
    forwards=$(get_forwards)
    if [[ -n "$forwards" ]]; then
        echo ""
        echo "  Pinned ports (direct localhost access):"
        while IFS= read -r line; do
            local lport remote
            lport=$(echo "$line" | awk '{print $2}')
            remote=$(echo "$line" | awk '{print $3}')
            echo "    http://localhost:${lport}  ->  ${remote}"
        done <<< "$forwards"
    fi

    # Write PAC file — routes 127.0.0.1/localhost through SOCKS, everything else direct.
    # PAC files override macOS/browser localhost proxy bypass.
    cat > "$PAC_FILE" <<PACEOF
function FindProxyForURL(url, host) {
  if (host === "127.0.0.1" || host === "localhost") {
    return "SOCKS5 127.0.0.1:${sport}; SOCKS 127.0.0.1:${sport}; DIRECT";
  }
  return "DIRECT";
}
PACEOF

    # Enable macOS auto-proxy using the PAC file
    local iface
    iface=$(get_active_interface)
    if [[ -n "$iface" ]]; then
        echo ""
        echo "  Enabling proxy on ${iface} ..."
        # Disable plain SOCKS proxy (PAC supersedes it)
        networksetup -setsocksfirewallproxystate "$iface" off 2>/dev/null || true
        # Enable PAC-based auto-proxy
        networksetup -setautoproxyurl "$iface" "file://${PAC_FILE}" 2>/dev/null && \
        networksetup -setautoproxystate "$iface" on 2>/dev/null && \
            echo "  Done — browse http://127.0.0.1:<port> directly." || \
            echo "  Warning: could not set auto-proxy (try with sudo)."
    fi

    echo ""
    echo "  Browse any service on ${TUNNEL_HOST}: http://127.0.0.1:<port>"
    echo "  Stop: $0 down"
}

cmd_down() {
    # Turn off macOS auto-proxy (PAC) and SOCKS proxy
    local iface
    iface=$(get_active_interface)
    if [[ -n "$iface" ]]; then
        networksetup -setautoproxystate "$iface" off 2>/dev/null || true
        networksetup -setsocksfirewallproxystate "$iface" off 2>/dev/null || true
        echo "macOS proxy disabled on ${iface}."
    fi
    rm -f "$PAC_FILE"

    local stopped=0
    if [[ -f "$PID_FILE" ]]; then
        local pid
        pid=$(cat "$PID_FILE")
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid"
            echo "Tunnel stopped (PID ${pid})."
            stopped=1
        fi
        rm -f "$PID_FILE"
    fi

    if [[ "$stopped" -eq 0 ]]; then
        local pid
        pid=$(pgrep -f "ssh.*-N.*${TUNNEL_HOST_LABEL}" 2>/dev/null | head -1 || true)
        if [[ -n "$pid" ]]; then
            kill "$pid"
            echo "Tunnel stopped (PID ${pid})."
        else
            echo "No tunnel running."
        fi
    fi
}

cmd_status() {
    if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        local pid sport
        pid=$(cat "$PID_FILE")
        sport=$(get_socks_port)
        echo "Tunnel: running (PID ${pid})"
        echo "  SOCKS proxy: localhost:${sport}"

        local iface
        iface=$(get_active_interface)
        if [[ -n "$iface" ]]; then
            local proxy_state
            proxy_state=$(networksetup -getautoproxyurl "$iface" 2>/dev/null | grep "Enabled" | head -1 || true)
            echo "  Auto-proxy PAC (${iface}): ${proxy_state:-unknown}"
        fi

        local forwards
        forwards=$(get_forwards)
        if [[ -n "$forwards" ]]; then
            echo "  Pinned ports:"
            while IFS= read -r line; do
                local lport remote
                lport=$(echo "$line" | awk '{print $2}')
                remote=$(echo "$line" | awk '{print $3}')
                echo "    localhost:${lport} -> ${remote}"
            done <<< "$forwards"
        fi
    else
        echo "Tunnel: not running"
        echo "  Start: $0 up"
    fi
}

cmd_test() {
    local target="${1:-}"
    local failures=0

    # Test 1: pfSense SSH
    echo "Testing pfSense SSH (${PF_WAN}:${PF_PORT}) ..."
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=5 \
        -i "$PF_KEY" -p "$PF_PORT" \
        "${PF_USER}@${PF_WAN}" '/bin/sh -c "echo ok"' &>/dev/null; then
        info "OK — pfSense SSH"
    else
        info "FAIL — cannot SSH to pfSense"
        failures=$((failures + 1))
    fi

    # Test 2: ProxyJump
    ensure_config
    echo "Testing ProxyJump to ${TUNNEL_HOST} ..."
    if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=10 \
        "${TUNNEL_HOST_LABEL}" 'echo ok' &>/dev/null; then
        info "OK — ProxyJump to ${TUNNEL_HOST}"
    else
        info "FAIL — cannot reach ${TUNNEL_HOST} via ProxyJump"
        failures=$((failures + 1))
    fi

    # Test 3: Specific port
    if [[ -n "$target" ]]; then
        local tport="${target##*:}"
        echo "Testing port ${tport} on ${TUNNEL_HOST} ..."
        if ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            -o BatchMode=yes -o ConnectTimeout=10 \
            "${TUNNEL_HOST_LABEL}" "nc -z 127.0.0.1 ${tport} 2>/dev/null && echo OPEN || echo CLOSED" 2>/dev/null | grep -q OPEN; then
            info "OK — port ${tport} open"
        else
            info "FAIL — port ${tport} not reachable"
            failures=$((failures + 1))
        fi
    fi

    # Test 4: SOCKS proxy
    local sport
    sport=$(get_socks_port)
    if port_in_use "$sport"; then
        echo "Testing SOCKS proxy (localhost:${sport}) ..."
        if [[ -n "$target" ]]; then
            local tport="${target##*:}"
            if curl -s --socks5-hostname "localhost:${sport}" --connect-timeout 5 "http://127.0.0.1:${tport}" -o /dev/null -w "%{http_code}" 2>/dev/null | grep -qE '^[1-5]'; then
                info "OK — SOCKS proxy reaches port ${tport}"
            else
                info "FAIL — SOCKS proxy cannot reach port ${tport}"
                failures=$((failures + 1))
            fi
        else
            info "OK — SOCKS port ${sport} listening"
        fi
    else
        info "SOCKS proxy not running (start: $0 up)"
    fi

    echo ""
    [[ "$failures" -eq 0 ]] && echo "All tests passed." || echo "${failures} test(s) failed."
    return "$failures"
}

cmd_add() {
    local target="${1:?Usage: $0 add HOST:PORT [--local-port N]}"
    shift
    local local_port=""

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-port) local_port="$2"; shift 2 ;;
            *) die "Unknown option: $1" ;;
        esac
    done

    local thost="${target%%:*}"
    local tport="${target##*:}"
    [[ -z "$tport" || "$tport" == "$thost" ]] && die "Invalid target — use HOST:PORT"

    [[ -z "$local_port" ]] && local_port="$tport"
    local actual_port
    actual_port=$(find_free_port "$local_port")
    [[ "$actual_port" != "$local_port" ]] && info "Port $local_port in use, using $actual_port"
    local_port="$actual_port"

    ensure_config

    local forward_line="LocalForward ${local_port} 127.0.0.1:${tport}"
    if grep -q "LocalForward ${local_port} .*:${tport}" "$SSH_CONFIG" 2>/dev/null; then
        info "Already pinned: localhost:${local_port} -> ${thost}:${tport}"
        return 0
    fi

    local range end
    range=$(host_block_lines "$TUNNEL_HOST_LABEL")
    [[ -z "$range" ]] && die "Could not find Host ${TUNNEL_HOST_LABEL} block"
    read -r _ end <<< "$range"

    # Insert after the last line of the block using a temp file (portable, no sed -i quirks)
    { head -n "$end" "$SSH_CONFIG"; echo "  ${forward_line}"; tail -n +"$((end + 1))" "$SSH_CONFIG"; } > "${SSH_CONFIG}.tmp"
    mv "${SSH_CONFIG}.tmp" "$SSH_CONFIG"

    echo "Pinned: localhost:${local_port} -> ${thost}:${tport}"
    echo "  Direct access (no SOCKS needed): http://localhost:${local_port}"
    echo "  Restart: $0 down && $0 up"
}

cmd_remove() {
    local target="${1:?Usage: $0 remove HOST:PORT}"
    local tport="${target##*:}"

    if grep -q "LocalForward .* .*:${tport}$" "$SSH_CONFIG" 2>/dev/null; then
        sed -i.bak "/LocalForward .* .*:${tport}$/d" "$SSH_CONFIG"
        rm -f "${SSH_CONFIG}.bak"
        echo "Removed pin for port ${tport}."
        echo "  (Still accessible via SOCKS proxy)"
        echo "  Restart: $0 down && $0 up"
    else
        echo "No pin found for port ${tport}"
    fi
}

cmd_sync() {
    # Fetch the access mode + service registry from oline-server and update
    # the oline-tunnels SSH config block accordingly:
    #
    #   unrestricted → DynamicForward (SOCKS proxy, all ports)
    #   restricted   → LocalForward per registered service (no SOCKS)
    ensure_config

    echo "Syncing from ${TUNNEL_HOST} ..."

    # Fetch both mode and service list in one SSH connection
    local expose_bin="bash \${EXPOSE_PATH:-~/.oline/expose.sh}"
    local remote_out
    remote_out=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o BatchMode=yes -o ConnectTimeout=10 \
        "${TUNNEL_HOST_LABEL}" \
        "${expose_bin} list --json 2>/dev/null || echo '[]'; echo; ${expose_bin} 2>/dev/null | grep -i '^Current mode:' || echo 'Current mode: all'" \
        2>/dev/null) || {
        echo "ERROR: could not reach ${TUNNEL_HOST} via ${TUNNEL_HOST_LABEL}." >&2
        echo "  Make sure the tunnel is configured: just tunnel up" >&2
        exit 1
    }

    # Extract mode line
    local mode="all"
    local mode_line
    mode_line=$(echo "$remote_out" | grep -i "^Current mode:" | head -1 || true)
    [[ "$mode_line" =~ restricted ]] && mode="restricted"

    echo "  Server mode: ${mode}"

    # Parse JSON service list
    local -a names ports descs
    local json_section
    json_section=$(echo "$remote_out" | sed -n '/^\[/,/^\]/p')
    while IFS= read -r line; do
        local name port desc
        name=$(echo "$line" | sed 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        port=$(echo "$line" | sed 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/')
        desc=$(echo "$line" | sed 's/.*"desc"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/')
        [[ "$name" =~ ^[a-zA-Z] ]] && [[ "$port" =~ ^[0-9]+$ ]] || continue
        names+=("$name"); ports+=("$port"); descs+=("$desc")
    done < <(echo "$json_section" | grep '"name"')

    # Find and rebuild the oline-tunnels SSH config block
    local range
    range=$(host_block_lines "$TUNNEL_HOST_LABEL")
    [[ -z "$range" ]] && { echo "ERROR: Host ${TUNNEL_HOST_LABEL} not in ${SSH_CONFIG}" >&2; exit 1; }
    local start end
    read -r start end <<< "$range"

    local tmp
    tmp=$(mktemp)
    {
        head -n "$((start - 1))" "$SSH_CONFIG"
        # Block body stripped of any existing forward directives
        sed -n "${start},${end}p" "$SSH_CONFIG" \
            | grep -v "^[[:space:]]*LocalForward " \
            | grep -v "^[[:space:]]*DynamicForward "
        # Insert the right forward directive(s) based on mode
        if [[ "$mode" == "all" ]]; then
            printf '  DynamicForward %s\n' "$SOCKS_PORT"
        else
            for i in "${!ports[@]}"; do
                printf '  LocalForward %s 127.0.0.1:%s\n' "${ports[$i]}" "${ports[$i]}"
            done
        fi
        tail -n +"$((end + 1))" "$SSH_CONFIG"
    } > "$tmp"
    mv "$tmp" "$SSH_CONFIG"

    echo ""
    if [[ "$mode" == "all" ]]; then
        echo "  DynamicForward set — SOCKS proxy on localhost:${SOCKS_PORT}"
        echo "  All ports on ${TUNNEL_HOST} will be accessible via SOCKS."
        if [[ "${#names[@]}" -gt 0 ]]; then
            echo ""
            echo "  Registered services (accessible via SOCKS or direct curl --socks5):"
            for i in "${!names[@]}"; do
                printf '    %-20s  localhost:%-6s  %s\n' "${names[$i]}" "${ports[$i]}" "${descs[$i]}"
            done
        fi
    else
        if [[ "${#names[@]}" -eq 0 ]]; then
            echo "  Warning: restricted mode but no services registered on server."
            echo "  Run on server: expose add NAME PORT --desc TEXT"
        else
            echo "  LocalForward entries set for ${#names[@]} service(s):"
            for i in "${!names[@]}"; do
                printf '    %-20s  http://localhost:%s    (%s)\n' \
                    "${names[$i]}" "${ports[$i]}" "${descs[$i]}"
            done
        fi
    fi

    echo ""
    echo "  Apply: just tunnel down && just tunnel up"
}

cmd_list() {
    local sport
    sport=$(get_socks_port)

    echo "SOCKS proxy: localhost:${sport} (all ports)"
    echo ""

    local forwards
    forwards=$(get_forwards)
    if [[ -n "$forwards" ]]; then
        echo "Pinned ports (direct localhost access, no SOCKS config):"
        while IFS= read -r line; do
            local lport remote
            lport=$(echo "$line" | awk '{print $2}')
            remote=$(echo "$line" | awk '{print $3}')
            local mark="  "
            port_in_use "$lport" && mark="* "
            echo "  ${mark}localhost:${lport} -> ${remote}"
        done <<< "$forwards"
        echo ""
        echo "  * = active"
    else
        echo "No pinned ports. Add one for direct access:"
        echo "  $0 add 192.168.1.101:49976"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────────────

CMD="${1:-help}"
shift 2>/dev/null || true

case "$CMD" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    status) cmd_status ;;
    test)   cmd_test "$@" ;;
    add)    cmd_add "$@" ;;
    remove) cmd_remove "$@" ;;
    list)   cmd_list ;;
    sync)   cmd_sync ;;
    *)
        cat <<EOF
pfsense-tunnel.sh — SSH tunnel through pfSense to LAN services

Commands:
  up                              Start tunnel + pinned forwards
  down                            Stop tunnel
  status                          Show tunnel status + pinned ports
  sync                            Pull service registry from oline-server;
                                  auto-configure LocalForward for each service
  test   [HOST:PORT]              Test connectivity
  add    HOST:PORT [--local-port N]  Pin a port for direct localhost access
  remove HOST:PORT                Remove a pinned port
  list                            Show pinned ports

Recommended workflow:
  # 1. On oline-server: register services
  expose add opencode 49976 --desc "OpenCode web UI"
  expose add grafana   3000 --desc "Grafana dashboard"

  # 2. On client: sync and start
  just tunnel sync   # pulls service list, sets up LocalForward entries
  just tunnel up     # connect — each service at http://localhost:PORT

Environment:
  PF_WAN=${PF_WAN}  PF_USER=${PF_USER}  PF_KEY=${PF_KEY}
  TUNNEL_HOST=${TUNNEL_HOST}  TUNNEL_USER=${TUNNEL_USER}
  SOCKS_PORT=${SOCKS_PORT}  SSH_CONFIG=${SSH_CONFIG}
EOF
        ;;
esac
