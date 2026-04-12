#!/bin/bash
# apply_firewall_rules.sh — Read config.json and apply iptables rules.
# Called by mock pfSsh.php on filter_configure() and by mock easyrule.
# Simulates real pfSense pf behavior so e2e tests validate actual network access.
# NOTE: Do NOT use set -e — if iptables fails mid-script after flush, we'd leave all rules empty.
# Instead, handle errors per-command.

CONFIG="/conf/config.json"

# Find WAN and LAN interfaces by their IP
WAN_IFACE=$(ip -4 -o addr show | grep "10\.99\.2\." | awk '{print $2}' | head -1)
LAN_IFACE=$(ip -4 -o addr show | grep "10\.99\.1\." | awk '{print $2}' | head -1)

[ -z "$WAN_IFACE" ] && { echo "apply_firewall_rules: WAN interface not found" >&2; exit 1; }

# ── Flush ────────────────────────────────────────────────────────────────────
# Use ACCEPT policy so non-WAN traffic (LAN, loopback, Docker bridge) is never blocked.
iptables -P INPUT ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT ACCEPT
iptables -F INPUT
iptables -F FORWARD
iptables -t nat -F PREROUTING
iptables -t nat -F POSTROUTING

# ── Always allow established/related on WAN ──────────────────────────────────
iptables -A INPUT -i "$WAN_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A INPUT -i "$WAN_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -A FORWARD -i "$WAN_IFACE" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || \
  iptables -A FORWARD -i "$WAN_IFACE" -m state --state ESTABLISHED,RELATED -j ACCEPT

# ── Filter pass rules from config (BEFORE blockpriv so explicit pass wins) ──
# Pass rules are higher priority than blockpriv in pfSense — they are evaluated top-to-bottom.
# A UDP pass rule for WireGuard port must match before RFC1918 block rules.
FILTER_COUNT=$(jq '.filter.rule | length' "$CONFIG" 2>/dev/null || echo 0)
for i in $(seq 0 $((FILTER_COUNT - 1))); do
    FTYPE=$(jq -r ".filter.rule[$i].type // empty" "$CONFIG")
    FIFACE=$(jq -r ".filter.rule[$i].interface // empty" "$CONFIG")
    [ "$FTYPE" != "pass" ] && continue
    [ "$FIFACE" != "wan" ] && continue

    FPROTO=$(jq -r ".filter.rule[$i].protocol // \"tcp\"" "$CONFIG")
    FSRC=$(jq -r ".filter.rule[$i].source.address // empty" "$CONFIG")
    FDPORT=$(jq -r ".filter.rule[$i].destination.port // empty" "$CONFIG")

    if [ -n "$FDPORT" ]; then
        if [ -n "$FSRC" ] && [ "$FSRC" != "null" ]; then
            iptables -A INPUT -i "$WAN_IFACE" -p "$FPROTO" -s "$FSRC" --dport "$FDPORT" -j ACCEPT
        else
            iptables -A INPUT -i "$WAN_IFACE" -p "$FPROTO" --dport "$FDPORT" -j ACCEPT
        fi
    fi
done

# ── easyrule pass rules (BEFORE blockpriv) ────────────────────────────────────
# Format: easyrule: pass wan tcp 10.99.2.161 any 22
if [ -f /var/log/easyrule.log ]; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "pass wan"; then
            PROTO=$(echo "$line" | awk '{print $4}')
            SRC=$(echo "$line" | awk '{print $5}')
            DPORT=$(echo "$line" | awk '{print $7}')
            if [ -n "$PROTO" ] && [ -n "$DPORT" ] && [ "$SRC" != "any" ]; then
                iptables -A INPUT -i "$WAN_IFACE" -p "$PROTO" -s "$SRC" --dport "$DPORT" -j ACCEPT
            fi
        fi
    done < /var/log/easyrule.log
fi

# ── blockpriv: DROP RFC1918 on WAN (after explicit pass rules) ───────────────
BLOCKPRIV=$(jq -r '.interfaces.wan.blockpriv // empty' "$CONFIG" 2>/dev/null)
if [ "$BLOCKPRIV" = "true" ]; then
    iptables -A INPUT -i "$WAN_IFACE" -s 10.0.0.0/8 -j DROP
    iptables -A INPUT -i "$WAN_IFACE" -s 172.16.0.0/12 -j DROP
    iptables -A INPUT -i "$WAN_IFACE" -s 192.168.0.0/16 -j DROP
    iptables -A FORWARD -i "$WAN_IFACE" -s 10.0.0.0/8 -j DROP
    iptables -A FORWARD -i "$WAN_IFACE" -s 172.16.0.0/12 -j DROP
    iptables -A FORWARD -i "$WAN_IFACE" -s 192.168.0.0/16 -j DROP
fi

# ── NAT port forwards from config ───────────────────────────────────────────
NAT_COUNT=$(jq '.nat.rule | length' "$CONFIG" 2>/dev/null || echo 0)
for i in $(seq 0 $((NAT_COUNT - 1))); do
    WPORT=$(jq -r ".nat.rule[$i].destination.port" "$CONFIG")
    TARGET=$(jq -r ".nat.rule[$i].target" "$CONFIG")
    TPORT=$(jq -r ".nat.rule[$i][\"local-port\"]" "$CONFIG")
    PROTO=$(jq -r ".nat.rule[$i].protocol // \"tcp\"" "$CONFIG")

    if [ -n "$WPORT" ] && [ "$WPORT" != "null" ] && [ -n "$TARGET" ] && [ "$TARGET" != "null" ]; then
        # DNAT: WAN:WPORT → TARGET:TPORT
        iptables -t nat -A PREROUTING -i "$WAN_IFACE" -p "$PROTO" --dport "$WPORT" \
            -j DNAT --to-destination "${TARGET}:${TPORT}"
        # Allow forwarding
        iptables -A FORWARD -i "$WAN_IFACE" -p "$PROTO" -d "$TARGET" --dport "$TPORT" -j ACCEPT
    fi
done

# ── MASQUERADE for LAN return traffic ────────────────────────────────────────
# Covers both NAT'd traffic and VPN clients forwarded to LAN.
if [ -n "$LAN_IFACE" ]; then
    iptables -t nat -A POSTROUTING -o "$LAN_IFACE" -j MASQUERADE
fi

# ── WireGuard forwarding ──────────────────────────────────────────────────────
# Allow forwarding between WireGuard interfaces and LAN/WAN.
# Detected dynamically after wg0 comes up.
WG_IFACE=$(ip link show 2>/dev/null | grep -oP 'wg\d+' | head -1)
if [ -n "$WG_IFACE" ] && [ -n "$LAN_IFACE" ]; then
    iptables -A FORWARD -i "$WG_IFACE" -o "$LAN_IFACE" -j ACCEPT
    iptables -A FORWARD -i "$LAN_IFACE" -o "$WG_IFACE" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
    iptables -A FORWARD -i "$LAN_IFACE" -o "$WG_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
fi

# ── Default DROP on WAN ──────────────────────────────────────────────────────
# Only WAN traffic hits these — LAN/loopback/Docker bridge use ACCEPT policy.
iptables -A INPUT -i "$WAN_IFACE" -j DROP
iptables -A FORWARD -i "$WAN_IFACE" -j DROP
