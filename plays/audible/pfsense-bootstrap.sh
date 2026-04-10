#!/usr/bin/env bash
# pfsense-bootstrap.sh — Configure pfSense WAN SSH + proxy access in one command.
#
# PREREQUISITE: SSH pubkey on pfSense (web GUI or ssh-copy-id).
#
# Usage (from LAN-side device, e.g. oline-server):
#   # Open WAN SSH + ProxyJump to internal server:
#   pfsense-bootstrap.sh admin@192.168.1.1 -i ~/.ssh/oline-server \
#     --client-ip 192.168.1.1 \
#     --client-key ~/.ssh/oline-client \
#     --proxy rhonine@123.456.1.123
#
#   # Tunnel LAN services to client (APIs, UIs, etc.):
#   pfsense-bootstrap.sh admin@192.168.1.1 -i ~/.ssh/oline-server \
#     --client-ip 192.168.1.1 \
#     --client-key ~/.ssh/oline-client \
#     --tunnel 8080:192.168.1.101:8080 \
#     --tunnel 3000:192.168.1.101:3000
#
#   # Reset all oline-managed rules:
#   pfsense-bootstrap.sh admin@192.168.1.1 -i ~/.ssh/oline-server --reset
#
# After running, paste the generated SSH config on your client device.
# Then: ssh oline-101         (ProxyJump SSH)
#       ssh -N oline-tunnels  (port forwards, Ctrl-C to close)
#
# All rules use "oline:" prefixed descriptions for clean --reset.
set -eo pipefail

# ── Args ──────────────────────────────────────────────────────────────────────

PFSENSE="${1:?Usage: $0 admin@host [-i key] [-p port] [--client-ip IP] [--client-lan-ip IP] [--client-key KEY] [--client-user USER] [--proxy USER@IP] [--tunnel LOCAL:HOST:PORT] [--reset] [--resubnet IP]}"
shift

KEY=""
CLIENT_IP=""
CLIENT_KEY=""
CLIENT_USER=""
CLIENT_LAN_IP=""
PROXY_TARGETS=""
TUNNELS=""
STATIC_MAPS=""
NAT_RULES=""
NAT_USER=""
DO_RESET=""
RESUBNET_IP=""
PF_PORT="22"
REVERSE_TUNNEL=""       # user@host[:back-port] — pfSense calls home here on boot
REVERSE_TUNNEL_INFO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    -i)           KEY="$2"; shift 2 ;;
    -p|--port)    PF_PORT="$2"; shift 2 ;;
    --client-ip)  CLIENT_IP="$2"; shift 2 ;;
    --client-key) CLIENT_KEY="$2"; shift 2 ;;
    --client-user) CLIENT_USER="$2"; shift 2 ;;
    --client-lan-ip) CLIENT_LAN_IP="$2"; shift 2 ;;
    --proxy)      PROXY_TARGETS="$PROXY_TARGETS $2"; shift 2 ;;
    --tunnel)     TUNNELS="$TUNNELS $2"; shift 2 ;;
    --static-ip)  STATIC_MAPS="$STATIC_MAPS $2"; shift 2 ;;
    --nat)        NAT_RULES="$NAT_RULES $2"; shift 2 ;;
    --nat-user)   NAT_USER="$2"; shift 2 ;;
    --reset)      DO_RESET="1"; shift ;;
    --resubnet)   RESUBNET_IP="$2"; shift 2 ;;
    --reverse-tunnel) REVERSE_TUNNEL="$2"; shift 2 ;;
    *)            echo "Unknown: $1"; exit 1 ;;
  esac
done

SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10 -p $PF_PORT"
[[ -n "$KEY" ]] && SSH_OPTS="$SSH_OPTS -i $KEY"

# ── Helpers ───────────────────────────────────────────────────────────────────

pf_ssh()  { ssh $SSH_OPTS "$PFSENSE" "/bin/sh -c \"$*\""; }
pf_php()  { ssh $SSH_OPTS "$PFSENSE" /usr/local/sbin/pfSsh.php; }

WAN_IP=""
WAN_IF=""
LAN_IP="${PFSENSE#*@}"
SUBNET_COLLISION=""

# IS_CLIENT=1 when this script is running on the client device itself.
# Detected by comparing local IPs against CLIENT_IP / CLIENT_LAN_IP.
# When set: SSH config is written locally instead of pushed via SSH, and
# self-targeting SSH calls are skipped.
IS_CLIENT=""

detect_context() {
  local target="${CLIENT_LAN_IP:-$CLIENT_IP}"
  [[ -z "$target" ]] && return 0

  # Collect all local IP addresses (works on Linux and macOS)
  local our_ips
  our_ips=$(
    { hostname -I 2>/dev/null; \
      ifconfig 2>/dev/null | awk '/inet /{print $2}' | sed 's|/.*||'; } \
    | tr ' ' '\n' | grep -v '^127\.' | grep -v '^$' | sort -u || true
  )

  local ip
  for ip in $our_ips; do
    if [[ "$ip" == "$CLIENT_IP" || "$ip" == "$CLIENT_LAN_IP" ]]; then
      IS_CLIENT=1
      echo "  Context: client device ($ip) — SSH config will be written locally"
      return 0
    fi
  done
  echo "  Context: server/LAN device — SSH config will be pushed to client"
}

# SSH to client device (chevy-tahoe) — used for pushing config + two-way access
# Uses CLIENT_LAN_IP (reachable from oline-server on LAN) if set, else CLIENT_IP.
# After ensure_client_key_access, uses BatchMode (no password prompts).
# No-op when running on the client device itself (IS_CLIENT=1).
CLIENT_TARGET=""
CLIENT_KEY_OK=""

client_target() {
  CLIENT_TARGET="${CLIENT_LAN_IP:-$CLIENT_IP}"
}

client_ssh() {
  [[ -n "$IS_CLIENT" ]] && return 1        # we ARE the client — never SSH to self
  [[ -z "$CLIENT_TARGET" || -z "$CLIENT_USER" ]] && return 1
  local client_ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
  [[ -n "$CLIENT_KEY_OK" ]] && client_ssh_opts="$client_ssh_opts -o BatchMode=yes"
  [[ -n "$KEY" ]] && client_ssh_opts="$client_ssh_opts -i $KEY"
  ssh $client_ssh_opts "${CLIENT_USER}@${CLIENT_TARGET}" "$@"
}

# One-time: install server key on client (may prompt for password).
# Skipped when running on the client (IS_CLIENT=1) — we're already here.
ensure_client_key_access() {
  if [[ -n "$IS_CLIENT" ]]; then
    CLIENT_KEY_OK=1   # we are the client, no SSH needed
    return 0
  fi
  [[ -z "$CLIENT_TARGET" || -z "$CLIENT_USER" ]] && return 1
  # Already have key access?
  local test_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"
  [[ -n "$KEY" ]] && test_opts="$test_opts -i $KEY"
  if ssh $test_opts "${CLIENT_USER}@${CLIENT_TARGET}" "echo ok" &>/dev/null; then
    CLIENT_KEY_OK=1
    return 0
  fi
  # No key access — use ssh-copy-id (will prompt for password once)
  echo "  Key access not set up. Running ssh-copy-id (enter client password once) ..."
  local copy_opts=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null)
  [[ -n "$KEY" ]] && copy_opts+=(-i "$KEY")
  if ssh-copy-id "${copy_opts[@]}" "${CLIENT_USER}@${CLIENT_TARGET}"; then
    CLIENT_KEY_OK=1
    return 0
  fi
  echo "  Warning: ssh-copy-id failed. Client SSH will not be available."
  return 1
}

# Write an SSH config block to a local file, replacing any existing oline block.
write_local_ssh_config() {
  local config_block="$1"
  local ssh_config="${HOME}/.ssh/config"
  local marker_start="# ── oline-managed (do not edit) ──"
  local marker_end="# ── end oline-managed ──"
  local full_block="${marker_start}
${config_block}
${marker_end}"

  mkdir -p "${HOME}/.ssh"
  if grep -q "${marker_start}" "${ssh_config}" 2>/dev/null; then
    cp "${ssh_config}" "${ssh_config}.bak"
    awk -v block="${full_block}" \
      '/^# ── oline-managed/ { skip=1; printf "%s\n", block; next }
       /^# ── end oline-managed/ { skip=0; next }
       !skip { print }' \
      "${ssh_config}.bak" > "${ssh_config}"
    echo "  SSH config updated locally (${ssh_config})."
  else
    printf '%s\n' "${full_block}" >> "${ssh_config}"
    echo "  SSH config written locally (${ssh_config})."
  fi
}

# ── Steps ─────────────────────────────────────────────────────────────────────

step_verify_access() {
  echo "==> Verifying SSH access to $PFSENSE ..."
  pf_ssh "echo ok" || {
    echo "FAIL: Cannot SSH to $PFSENSE"
    echo "Add your pubkey first: System > User Manager > admin > Authorized Keys"
    exit 1
  }

  # Fetch WAN + LAN IPs from pfSense
  local info
  info=$(printf '%s\n' \
    'parse_config(true);' \
    'echo "WAN=" . $config["interfaces"]["wan"]["ipaddr"];' \
    'echo "LAN=" . $config["interfaces"]["lan"]["ipaddr"];' \
    'echo "LANSUB=" . $config["interfaces"]["lan"]["subnet"];' \
    'exec' \
    'exit' \
  | pf_php 2>/dev/null)

  local parsed_wan parsed_lan parsed_sub
  parsed_wan=$(echo "$info" | sed -n 's/.*WAN=\([0-9][0-9.]*\).*/\1/p' | head -1)
  parsed_lan=$(echo "$info" | sed -n 's/.*LAN=\([0-9][0-9.]*\).*/\1/p' | head -1)
  parsed_sub=$(echo "$info" | sed -n 's/.*LANSUB=\([0-9]*\).*/\1/p' | head -1)

  [[ -n "$parsed_wan" ]] && WAN_IP="$parsed_wan"
  [[ -n "$parsed_lan" ]] && LAN_IP="$parsed_lan"

  echo "  LAN: ${LAN_IP}/${parsed_sub:-?}"

  # Fetch WAN interface name + DHCP fallback IP in one pfSsh.php call
  local wan_info
  wan_info=$(printf '%s\n' \
    'parse_config(true);' \
    'echo "WANIF=" . $config["interfaces"]["wan"]["if"];' \
    'exec' 'exit' \
  | pf_php 2>/dev/null)
  WAN_IF=$(echo "$wan_info" | sed -n 's/.*WANIF=\([a-z]*[0-9]*\).*/\1/p' | head -1)
  echo "  WAN IF: ${WAN_IF:-unknown}"

  # WAN is usually DHCP — get actual IP from the WAN interface
  if [[ -z "$WAN_IP" ]]; then
    WAN_IP=$(pf_ssh "ifconfig ${WAN_IF:-re0} 2>/dev/null | grep 'inet ' | awk '{print \\\$2}'" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
  fi
  echo "  WAN: ${WAN_IP:-unknown}"

  # Detect subnet collision
  local WAN_PREFIX="${WAN_IP%.*}"
  local LAN_PREFIX="${LAN_IP%.*}"
  if [[ -n "$WAN_PREFIX" && "$WAN_PREFIX" == "$LAN_PREFIX" ]]; then
    SUBNET_COLLISION=1
    echo ""
    echo "  WARNING: WAN ($WAN_IP) and LAN ($LAN_IP) are on the same subnet!"
    if [[ -n "$CLIENT_IP" ]]; then
      echo "  Will add host route for $CLIENT_IP via WAN interface to fix routing."
    else
      echo "  Fix: --resubnet 192.168.2.1 (changes LAN to 192.168.2.0/24)"
    fi
  fi
}

step_resubnet() {
  [[ -z "$RESUBNET_IP" ]] && return 0
  local PREFIX="${RESUBNET_IP%.*}"
  echo "==> Changing LAN subnet: $LAN_IP -> $RESUBNET_IP/24 ..."
  echo "  DHCP range: ${PREFIX}.100 - ${PREFIX}.199"

  # Write the config and regenerate firewall/NAT rules for new subnet
  printf '%s\n' \
    'parse_config(true);' \
    "\$config[\"interfaces\"][\"lan\"][\"ipaddr\"] = \"$RESUBNET_IP\";" \
    "\$config[\"interfaces\"][\"lan\"][\"subnet\"] = \"24\";" \
    "if (is_array(\$config[\"dhcpd\"][\"lan\"])) {" \
    "  \$config[\"dhcpd\"][\"lan\"][\"range\"][\"from\"] = \"${PREFIX}.100\";" \
    "  \$config[\"dhcpd\"][\"lan\"][\"range\"][\"to\"]   = \"${PREFIX}.199\";" \
    "}" \
    'write_config("oline: resubnet LAN");' \
    'filter_configure();' \
    'exec' \
    'exit' \
  | pf_php

  # Fire-and-forget reload — this WILL kill our SSH session
  echo "  Config written. Reloading (connection will drop) ..."
  ssh $SSH_OPTS -o ConnectTimeout=3 "$PFSENSE" \
    "/bin/sh -c 'nohup /etc/rc.reload_interfaces >/dev/null 2>&1 &'" 2>/dev/null || true

  # Update target for all subsequent steps
  PFSENSE="${PFSENSE%%@*}@$RESUBNET_IP"
  LAN_IP="$RESUBNET_IP"

  # Renew our own DHCP to get on the new subnet (retry with backoff)
  echo "  Renewing DHCP on this machine ..."
  local IFACE
  IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || echo "en0")
  for attempt in 1 2 3; do
    sudo ipconfig set "$IFACE" DHCP 2>/dev/null || \
      { sudo dhclient -r 2>/dev/null; sudo dhclient 2>/dev/null; } || true
    sleep $((attempt * 2))
    # Check if we got an IP on the new subnet
    if ip addr show "$IFACE" 2>/dev/null | grep -q "${PREFIX}\." || \
       ifconfig "$IFACE" 2>/dev/null | grep -q "${PREFIX}\."; then
      break
    fi
  done

  # Wait for pfSense at new IP
  echo "  Waiting for pfSense at $RESUBNET_IP ..."
  for i in $(seq 1 20); do
    if pf_ssh "echo ok" &>/dev/null; then
      echo "  Reachable at $RESUBNET_IP."
      # Re-apply firewall rules now that interfaces are on the new subnet
      echo "  Regenerating firewall rules ..."
      printf '%s\n' \
        'parse_config(true);' \
        'filter_configure();' \
        'exec' 'exit' \
      | pf_php 2>/dev/null || true
      return 0
    fi
    sleep 3
  done
  echo "  FAIL: Cannot reach pfSense at $RESUBNET_IP after 60s."
  echo "  Manually renew DHCP and retry."
  exit 1
}

step_static_ip() {
  [[ -z "$STATIC_MAPS" ]] && return 0
  for sm in $STATIC_MAPS; do
    local MAC="${sm%%:*}"
    local rest="${sm#*:}"
    # Handle MAC with dashes or colons — normalize to colons
    MAC=$(echo "$MAC" | tr '-' ':' | tr '[:upper:]' '[:lower:]')
    # rest could be IP or IP:hostname
    local SIP="${rest%%:*}"
    local SHOST="${rest#*:}"
    [[ "$SHOST" == "$SIP" ]] && SHOST=""

    echo "==> Static DHCP: ${MAC} -> ${SIP}${SHOST:+ ($SHOST)} ..."
    printf '%s\n' \
      'parse_config(true);' \
      'if (!is_array($config["dhcpd"]["lan"]["staticmap"])) { $config["dhcpd"]["lan"]["staticmap"] = array(); }' \
      '$found = false;' \
      'foreach ($config["dhcpd"]["lan"]["staticmap"] as &$m) {' \
      "  if (\$m[\"mac\"] === \"$MAC\") { \$m[\"ipaddr\"] = \"$SIP\"; \$found = true; break; }" \
      '}' \
      'unset($m);' \
      'if (!$found) {' \
      "  \$config[\"dhcpd\"][\"lan\"][\"staticmap\"][] = array(" \
      "    \"mac\"    => \"$MAC\"," \
      "    \"ipaddr\" => \"$SIP\"," \
      "    \"descr\"  => \"oline: ${SHOST:-static}\"" \
      '  );' \
      '}' \
      "write_config(\"oline: static IP $SIP for $MAC\");" \
      'exec' \
      'exit' \
    | pf_php
    echo "  Done. Device will get ${SIP} on next DHCP renewal."
  done
}

step_reset() {
  [[ -z "$DO_RESET" ]] && return 0
  echo "==> Clearing all oline-managed rules ..."
  printf '%s\n' \
    'parse_config(true);' \
    '$removed = 0;' \
    'if (is_array($config["nat"]["rule"])) {' \
    '  $keep = array();' \
    '  foreach ($config["nat"]["rule"] as $r) {' \
    '    if (isset($r["descr"]) && strpos($r["descr"], "oline:") === 0) { $removed++; }' \
    '    else { $keep[] = $r; }' \
    '  }' \
    '  $config["nat"]["rule"] = $keep;' \
    '}' \
    'if (is_array($config["filter"]["rule"])) {' \
    '  $keep = array();' \
    '  foreach ($config["filter"]["rule"] as $r) {' \
    '    if (isset($r["descr"]) && strpos($r["descr"], "oline:") === 0) { $removed++; }' \
    '    else { $keep[] = $r; }' \
    '  }' \
    '  $config["filter"]["rule"] = $keep;' \
    '}' \
    'if ($removed > 0) {' \
    '  write_config("oline: reset — removed $removed rules");' \
    '  filter_configure();' \
    '  echo "Removed $removed oline rules.\n";' \
    '} else {' \
    '  echo "No oline rules found.\n";' \
    '}' \
    'exec' \
    'exit' \
  | pf_php
}

step_disable_blockpriv() {
  echo "==> Disabling 'Block private networks' on WAN ..."
  printf '%s\n' \
    'parse_config(true);' \
    'if (isset($config["interfaces"]["wan"]["blockpriv"])) {' \
    '  unset($config["interfaces"]["wan"]["blockpriv"]);' \
    '  write_config("oline: disable blockpriv on WAN");' \
    '  filter_configure();' \
    '  echo "Disabled.\n";' \
    '} else {' \
    '  echo "Already disabled.\n";' \
    '}' \
    'exec' \
    'exit' \
  | pf_php
}

step_pubkey_only() {
  echo "==> Enforcing pubkey-only SSH ..."
  printf '%s\n' \
    'parse_config(true);' \
    '$config["system"]["ssh"]["sshdkeyonly"] = "enabled";' \
    'write_config("oline: pubkey-only SSH");' \
    'exec' \
    'exit' \
  | pf_php
  pf_ssh "/etc/rc.d/sshd onerestart" 2>/dev/null || true
}

step_wan_rules() {
  [[ -z "$CLIENT_IP" ]] && return 0
  echo "==> Adding WAN firewall pass rule for $CLIENT_IP ..."
  # Add as a config filter rule (not easyrule) so filter_configure() compiles
  # it with reply-to — critical when WAN/LAN share the same subnet.
  printf '%s\n' \
    'parse_config(true);' \
    'if (!is_array($config["filter"]["rule"])) { $config["filter"]["rule"] = array(); }' \
    "\$config[\"filter\"][\"rule\"][] = array(" \
    "  \"type\"        => \"pass\"," \
    "  \"interface\"   => \"wan\"," \
    "  \"ipprotocol\"  => \"inet\"," \
    "  \"protocol\"    => \"tcp\"," \
    "  \"source\"      => array(\"address\" => \"$CLIENT_IP\")," \
    "  \"destination\" => array(\"port\" => \"22\")," \
    "  \"statetype\"   => \"keep state\"," \
    "  \"descr\"       => \"oline: WAN SSH $CLIENT_IP\"" \
    ");" \
    "write_config(\"oline: WAN SSH rule for $CLIENT_IP\");" \
    'filter_configure();' \
    'exec' \
    'exit' \
  | pf_php
}

step_nat_forwards() {
  [[ -z "$NAT_RULES" ]] && return 0
  for nr in $NAT_RULES; do
    IFS=: read -r WPORT TIP TPORT <<< "$nr"
    echo "==> NAT: WAN:$WPORT -> $TIP:$TPORT ..."
    printf '%s\n' \
      'parse_config(true);' \
      'if (!is_array($config["nat"]["rule"])) { $config["nat"]["rule"] = array(); }' \
      "\$config[\"nat\"][\"rule\"][] = array(" \
      "  \"interface\"          => \"wan\"," \
      "  \"protocol\"           => \"tcp\"," \
      "  \"source\"             => array(\"address\" => \"$CLIENT_IP\")," \
      "  \"destination\"        => array(\"network\" => \"wanip\", \"port\" => \"$WPORT\")," \
      "  \"target\"             => \"$TIP\"," \
      "  \"local-port\"         => \"$TPORT\"," \
      "  \"descr\"              => \"oline: SSH $TIP:$TPORT\"," \
      "  \"associated-rule-id\" => \"pass\"" \
      ");" \
      "write_config(\"oline: NAT WAN:$WPORT -> $TIP:$TPORT\");" \
      'filter_configure();' \
      'exec' \
      'exit' \
    | pf_php
  done
}

step_collision_routes() {
  [[ -z "$SUBNET_COLLISION" ]] && return 0

  # Get LAN interface name from config
  local lan_if
  lan_if=$(printf '%s\n' \
    'parse_config(true);' \
    'echo "LANIF=" . $config["interfaces"]["lan"]["if"];' \
    'exec' 'exit' \
  | pf_php 2>/dev/null | sed -n 's/.*LANIF=\([a-z]*[0-9]*\).*/\1/p' | head -1)

  local wan_if="${WAN_IF:-re0}"
  echo "==> Fixing subnet collision routes (WAN=$wan_if, LAN=${lan_if:-?}) ..."

  # Apply routes immediately (active session)
  if [[ -n "$CLIENT_IP" ]]; then
    echo "  $CLIENT_IP -> $wan_if (WAN)"
    pf_ssh "route delete -host $CLIENT_IP 2>/dev/null; route add -host $CLIENT_IP -iface $wan_if" 2>/dev/null || \
      echo "  Warning: route add failed for $CLIENT_IP"
  fi

  if [[ -n "$NAT_RULES" && -n "$lan_if" ]]; then
    for nr in $NAT_RULES; do
      IFS=: read -r WPORT TIP TPORT <<< "$nr"
      echo "  $TIP -> $lan_if (LAN)"
      pf_ssh "route delete -host $TIP 2>/dev/null; route add -host $TIP -iface $lan_if" 2>/dev/null || \
        echo "  Warning: route add failed for $TIP"
    done
  fi

  # ── Persist routes via shellcmd so they survive reboots ───────────────────
  # pfSense shellcmd entries run via /etc/rc.shellcmd at boot.
  # We write a single script that re-adds all collision routes, then register
  # it as a shellcmd.  Idempotent — replaces any existing oline-routes entry.
  echo "==> Persisting collision routes across reboots ..."

  local ROUTE_CMDS="route delete -host $CLIENT_IP 2>/dev/null; route add -host $CLIENT_IP -iface $wan_if"
  if [[ -n "$NAT_RULES" && -n "$lan_if" ]]; then
    for nr in $NAT_RULES; do
      IFS=: read -r WPORT TIP TPORT <<< "$nr"
      ROUTE_CMDS="$ROUTE_CMDS; route delete -host $TIP 2>/dev/null; route add -host $TIP -iface $lan_if"
    done
  fi

  # Write startup script to pfSense persistent filesystem
  local ROUTE_SCRIPT="/usr/local/etc/rc.d/oline-routes.sh"
  pf_ssh "cat > $ROUTE_SCRIPT" <<SCRIPT
#!/bin/sh
# oline: restore WAN host routes after reboot (subnet collision fix)
${ROUTE_CMDS//; /
}
SCRIPT
  pf_ssh "chmod +x $ROUTE_SCRIPT" 2>/dev/null || true
  echo "  Startup script: $ROUTE_SCRIPT"
  echo "  Routes will be restored automatically on every boot."
}

step_persist_authorized_keys() {
  echo "==> Persisting SSH authorized keys to config.xml ..."
  # Read current authorized_keys from filesystem and save into config.xml.
  # pfSense recreates /root/.ssh/authorized_keys from config.xml on boot, so
  # keys only written to the filesystem are lost on reboot.  This step is
  # idempotent — it merges any existing keys already in config with filesystem.
  printf '%s\n' \
    'parse_config(true);' \
    '$fs_keys = @file_get_contents("/root/.ssh/authorized_keys");' \
    '$fs_keys = trim($fs_keys ?? "");' \
    '$cfg_b64  = isset($config["system"]["user"][0]["authorizedkeys"])' \
    '          ? $config["system"]["user"][0]["authorizedkeys"] : "";' \
    '$cfg_keys = trim(base64_decode($cfg_b64));' \
    '// Merge: split both into lines, deduplicate, rejoin' \
    '$all = array_merge(' \
    '  $cfg_keys ? explode("\n", $cfg_keys) : [],' \
    '  $fs_keys  ? explode("\n", $fs_keys)  : []);' \
    '$unique = array_values(array_unique(array_filter(array_map("trim", $all))));' \
    '$merged = implode("\n", $unique);' \
    'if (!$merged) { echo "No keys found to persist.\n"; exec; exit; }' \
    '$config["system"]["user"][0]["authorizedkeys"] = base64_encode($merged);' \
    'write_config("oline: persist authorized_keys to config.xml");' \
    'echo count($unique) . " key(s) persisted to config.xml.\n";' \
    'exec' \
    'exit' \
  | pf_php
}

step_reverse_tunnel() {
  # Optional: REVERSE_TUNNEL=user@host[:back-port] — pfSense calls home to this
  # server on boot, creating an SSH reverse tunnel so you can always reach
  # pfSense even after a reboot, regardless of WAN routing or firewall rules.
  #
  # Activated by --reverse-tunnel user@host[:back-port]
  # e.g. --reverse-tunnel root@192.168.1.101:2222
  #   → groot:2222 forwards to pfSense:22
  #   → ssh -p 2222 admin@192.168.1.101  reaches pfSense from anywhere on LAN
  [[ -z "$REVERSE_TUNNEL" ]] && return 0

  local rt_user rt_host rt_port
  local rt_target="${REVERSE_TUNNEL}"
  rt_user="${rt_target%%@*}"
  rt_target="${rt_target#*@}"
  rt_host="${rt_target%%:*}"
  rt_port="${rt_target##*:}"
  [[ "$rt_port" == "$rt_host" ]] && rt_port="2222"

  echo "==> Setting up reverse SSH tunnel (pfSense → ${rt_user}@${rt_host}:${rt_port}) ..."

  # Generate an SSH keypair on pfSense for the call-home connection (if absent)
  local TUNNEL_KEY="/root/.ssh/oline-tunnel"
  local tunnel_pubkey
  tunnel_pubkey=$(pf_ssh "
    if [ ! -f ${TUNNEL_KEY} ]; then
      ssh-keygen -t ed25519 -f ${TUNNEL_KEY} -N '' -C 'oline-pfsense-tunnel' >/dev/null 2>&1
    fi
    cat ${TUNNEL_KEY}.pub
  " 2>/dev/null | tail -1)

  if [[ -z "$tunnel_pubkey" ]]; then
    echo "  Warning: could not generate/read tunnel key on pfSense. Skipping."
    return 0
  fi
  echo "  Tunnel pubkey: ${tunnel_pubkey:0:40}..."

  # Install the pfSense tunnel key on the call-home server (groot/reverse target).
  # Strategy:
  #   - If IS_CLIENT (running on chevy-tahoe): groot is reachable directly on LAN.
  #     Try with CLIENT_KEY first, then $KEY, then prompt.
  #   - If on server (groot itself): install directly into local authorized_keys.
  #   - Otherwise: SSH with $KEY.
  echo "  Installing tunnel key on ${rt_user}@${rt_host} ..."

  local install_cmd="mkdir -p ~/.ssh && grep -qF '${tunnel_pubkey}' ~/.ssh/authorized_keys 2>/dev/null || printf '%s\n' '${tunnel_pubkey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys"
  local installed=""

  # Check if groot is ourselves (running on the call-home server)
  local our_ips
  our_ips=$(
    { hostname -I 2>/dev/null; \
      ifconfig 2>/dev/null | awk '/inet /{print $2}' | sed 's|/.*||'; } \
    | tr ' ' '\n' | grep -v '^$' | sort -u || true
  )
  local ip
  for ip in $our_ips; do
    if [[ "$ip" == "$rt_host" ]]; then
      # We ARE the call-home server — install the key locally
      eval "$install_cmd" 2>/dev/null && installed=1
      echo "  Key installed locally (running on ${rt_host})."
      break
    fi
  done

  if [[ -z "$installed" ]]; then
    local groot_ssh_opts="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"

    # Try keys in order: CLIENT_KEY → $KEY → no key (agent/default)
    local tried_keys=()
    [[ -n "$CLIENT_KEY" ]] && tried_keys+=("$CLIENT_KEY")
    [[ -n "$KEY" && "$KEY" != "$CLIENT_KEY" ]] && tried_keys+=("$KEY")
    tried_keys+=("")   # last resort: SSH agent / default key

    for try_key in "${tried_keys[@]}"; do
      local opts="$groot_ssh_opts"
      [[ -n "$try_key" ]] && opts="$opts -i $try_key"
      if ssh $opts "${rt_user}@${rt_host}" "$install_cmd" 2>/dev/null; then
        installed=1
        echo "  Key installed on ${rt_host}."
        break
      fi
    done
  fi

  if [[ -z "$installed" ]]; then
    echo "  Warning: could not install tunnel key on ${rt_host} automatically."
    echo "  Add this line to ${rt_user}@${rt_host}:~/.ssh/authorized_keys manually:"
    echo "  ${tunnel_pubkey}"
  fi

  # Write the persistent reverse tunnel startup script on pfSense
  local TUNNEL_SCRIPT="/usr/local/etc/rc.d/oline-tunnel.sh"
  pf_ssh "cat > $TUNNEL_SCRIPT" <<SCRIPT
#!/bin/sh
# oline: reverse SSH tunnel — pfSense calls home to ${rt_user}@${rt_host}
# Port ${rt_port} on ${rt_host} forwards back to pfSense:22
# Usage from ${rt_host}: ssh -p ${rt_port} admin@127.0.0.1
LOCK=/tmp/oline-tunnel.pid
SLEEP=30

start_tunnel() {
  ssh -N -R ${rt_port}:localhost:22 \\
      -i ${TUNNEL_KEY} \\
      -o StrictHostKeyChecking=no \\
      -o UserKnownHostsFile=/dev/null \\
      -o ServerAliveInterval=30 \\
      -o ServerAliveCountMax=3 \\
      -o ExitOnForwardFailure=yes \\
      -o BatchMode=yes \\
      ${rt_user}@${rt_host} &
  echo \$! > \$LOCK
}

stop_tunnel() {
  if [ -f \$LOCK ]; then
    kill "\$(cat \$LOCK)" 2>/dev/null
    rm -f \$LOCK
  fi
}

watch_tunnel() {
  while true; do
    if [ -f \$LOCK ] && kill -0 "\$(cat \$LOCK)" 2>/dev/null; then
      sleep \$SLEEP
    else
      rm -f \$LOCK
      start_tunnel
      sleep \$SLEEP
    fi
  done
}

stop_tunnel
# Wait for network to be ready after boot
sleep 5
start_tunnel
# Background watchdog
watch_tunnel &
SCRIPT

  pf_ssh "chmod +x $TUNNEL_SCRIPT" 2>/dev/null || true

  # Register key in pfSense config so it survives rebuild
  pf_ssh "
    ${TUNNEL_KEY}.pub exists or exit
    true
  " 2>/dev/null || true

  echo "  Startup script: $TUNNEL_SCRIPT"
  echo "  Starting tunnel now ..."
  pf_ssh "$TUNNEL_SCRIPT" 2>/dev/null &
  sleep 3

  echo ""
  echo "  ✓ Reverse tunnel active."
  echo "  From ${rt_host}: ssh -p ${rt_port} admin@127.0.0.1"
  REVERSE_TUNNEL_INFO="groot:${rt_port} → pfSense:22 (via ${rt_host})"
}

step_ssh_config() {
  [[ -z "$PROXY_TARGETS" && -z "$TUNNELS" ]] && return 0
  [[ -z "$WAN_IP" ]] && return 0

  local PF_USER="${PFSENSE%%@*}"
  local KEY_LINE=""
  [[ -n "$CLIENT_KEY" ]] && KEY_LINE="  IdentityFile $CLIENT_KEY"

  # Build the SSH config as a string
  local CONFIG=""

  # pfSense jump host
  CONFIG+="Host pfsense
  HostName $WAN_IP
  User $PF_USER
  Port $PF_PORT
${KEY_LINE}
  StrictHostKeyChecking no
  UserKnownHostsFile /dev/null
"

  # ProxyJump targets
  for pt in $PROXY_TARGETS; do
    local PUSER="${pt%%@*}"
    local PIP="${pt#*@}"
    local ALIAS="oline-${PIP##*.}"
    CONFIG+="
Host $ALIAS
  HostName $PIP
  User $PUSER
${KEY_LINE}
  ProxyJump pfsense
"
  done

  # Tunnel host (SOCKS + pinned forwards through oline-server)
  CONFIG+="
Host oline-tunnels
  HostName ${TUNNEL_TARGET_HOST:-$WAN_IP}
  User ${TUNNEL_TARGET_USER:-$PF_USER}
${KEY_LINE}
  ProxyJump pfsense
  DynamicForward 1080
  ServerAliveInterval 30
  ServerAliveCountMax 3
"

  # Deliver the SSH config: write locally (client mode) or push via SSH (server mode)
  if [[ -n "$IS_CLIENT" ]]; then
    # ── Running on the client device — write config here ──────────────────────
    echo "==> Writing SSH config locally ..."
    write_local_ssh_config "$CONFIG"

  elif [[ -n "$CLIENT_USER" && -n "$CLIENT_TARGET" ]]; then
    # ── Running on server — push config to client via SSH ─────────────────────
    echo "==> Setting up client SSH access (${CLIENT_USER}@${CLIENT_TARGET}) ..."

    if ! ensure_client_key_access; then
      echo "  Falling back to printing SSH config."
      echo ""
      echo "────────────────────────────────────────────────────────"
      echo "$CONFIG"
      echo "────────────────────────────────────────────────────────"
    else
      echo "  Key access to client: OK"

      # Install this server's pubkey on the client for two-way SSH (server → client)
      local server_pubkey=""
      for kf in ~/.ssh/oline-server.pub ~/.ssh/id_ed25519.pub ~/.ssh/id_rsa.pub; do
        [[ -f "$kf" ]] && { server_pubkey="$kf"; break; }
      done
      if [[ -n "$server_pubkey" ]]; then
        echo "  Installing server pubkey on client for two-way SSH ..."
        local pubkey_data
        pubkey_data=$(cat "$server_pubkey")
        client_ssh "mkdir -p ~/.ssh && grep -qF '${pubkey_data}' ~/.ssh/authorized_keys 2>/dev/null || echo '${pubkey_data}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys" 2>/dev/null && \
          echo "  Two-way SSH enabled." || \
          echo "  Warning: could not install server pubkey on client."
      fi

      # Push SSH config block to client
      echo "  Pushing SSH config to client ..."
      local MARKER_START="# ── oline-managed (do not edit) ──"
      local MARKER_END="# ── end oline-managed ──"
      local BLOCK="${MARKER_START}
${CONFIG}
${MARKER_END}"

      if client_ssh "grep -q '${MARKER_START}' ~/.ssh/config 2>/dev/null" 2>/dev/null; then
        client_ssh "
          cp ~/.ssh/config ~/.ssh/config.bak
          awk -v block='$(echo "$BLOCK" | sed "s/'/'\\''/g")' '
            /^# ── oline-managed/ { skip=1; print block; next }
            /^# ── end oline-managed/ { skip=0; next }
            !skip { print }
          ' ~/.ssh/config.bak > ~/.ssh/config
        " 2>/dev/null && echo "  SSH config updated on client." || \
          echo "  Warning: could not update SSH config."
      else
        client_ssh "mkdir -p ~/.ssh && cat >> ~/.ssh/config" <<< "$BLOCK" 2>/dev/null && \
          echo "  SSH config written to client." || \
          echo "  Warning: could not write SSH config."
      fi
    fi

  else
    # ── No client target — print config for manual copy ───────────────────────
    echo "==> Generated SSH config (paste into ~/.ssh/config on your client device):"
    echo ""
    echo "────────────────────────────────────────────────────────"
    echo "$CONFIG"
    echo "────────────────────────────────────────────────────────"
  fi

  echo ""
  if [[ -n "$PROXY_TARGETS" ]]; then
    local LAST_PT="${PROXY_TARGETS##* }"
    local LAST_IP="${LAST_PT#*@}"
    echo "  SSH to LAN host:  ssh oline-${LAST_IP##*.}"
  fi
  echo "  Start tunnels:    just tunnel up"
}

# Derive tunnel target from proxy targets (first proxy = tunnel destination)
TUNNEL_TARGET_HOST=""
TUNNEL_TARGET_USER=""
_set_tunnel_target() {
  if [[ -n "$PROXY_TARGETS" ]]; then
    local first="${PROXY_TARGETS# }"
    first="${first%% *}"
    TUNNEL_TARGET_USER="${first%%@*}"
    TUNNEL_TARGET_HOST="${first#*@}"
  fi
}


step_verify_wan() {
  [[ -z "$WAN_IP" || -z "$CLIENT_IP" ]] && return 0
  local PF_USER="${PFSENSE%%@*}"
  local KEY_OPT=""
  [[ -n "$KEY" ]] && KEY_OPT="-i $KEY"
  local SSH_COMMON="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o BatchMode=yes -o ConnectTimeout=10"

  # Detect context: are we on the LAN (oline-server) or the client?
  # If we can reach pfSense at LAN_IP directly, we're on the LAN side.
  local on_lan=""
  if ssh $SSH_COMMON -p "$PF_PORT" $KEY_OPT "$PFSENSE" "/bin/sh -c 'echo ok'" &>/dev/null; then
    on_lan=1
  fi

  echo ""
  echo "==> Verifying connectivity ..."

  if [[ -n "$on_lan" ]]; then
    # Running on oline-server (LAN side) — test outward to client
    echo "  Context: LAN side (oline-server)"

    # Test pfSense WAN reachability
    echo -n "  pfSense WAN ($WAN_IP:$PF_PORT) ... "
    if ssh $SSH_COMMON $KEY_OPT "${PF_USER}@${WAN_IP}" "/bin/sh -c 'echo ok'" &>/dev/null; then
      echo "OK"
    else
      echo "FAIL (expected if WAN/LAN collision — use ProxyJump)"
    fi

    # Test SSH to client (LAN IP or WAN IP)
    local client_target="${CLIENT_LAN_IP:-$CLIENT_IP}"
    if [[ -n "$CLIENT_USER" ]]; then
      echo -n "  SSH to client ${CLIENT_USER}@${client_target} ... "
      if client_ssh "echo ok" &>/dev/null; then
        echo "OK"
      else
        echo "FAIL"
        echo "    -> Check: client SSH enabled? Key installed?"
      fi
    fi

    # Test NAT forwards
    for nr in $NAT_RULES; do
      IFS=: read -r WPORT TIP TPORT <<< "$nr"
      echo -n "  NAT target $TIP:$TPORT ... "
      if ssh $SSH_COMMON $KEY_OPT -p "$TPORT" "${NAT_USER:-$USER}@${TIP}" "echo ok" &>/dev/null; then
        echo "OK"
      else
        echo -n "tcp "
        if timeout 3 bash -c "echo >/dev/tcp/$TIP/$TPORT" 2>/dev/null; then
          echo "OPEN (SSH auth may differ)"
        else
          echo "FAIL"
        fi
      fi
    done
  else
    # Running on client side — test inward to pfSense + LAN
    echo "  Context: client side (WAN)"

    echo -n "  SSH to pfSense WAN ($WAN_IP:$PF_PORT) ... "
    if ssh $SSH_COMMON $KEY_OPT "${PF_USER}@${WAN_IP}" "/bin/sh -c 'echo ok'" &>/dev/null; then
      echo "OK"
    else
      echo "FAIL"
      echo "    -> WAN/LAN subnet collision? Run with --resubnet 192.168.2.1"
    fi

    # Test ProxyJump to LAN hosts
    for pt in $PROXY_TARGETS; do
      local PUSER="${pt%%@*}"
      local PIP="${pt#*@}"
      echo -n "  ProxyJump to ${PUSER}@${PIP} via pfSense ... "
      if ssh $SSH_COMMON $KEY_OPT \
        -o "ProxyCommand=ssh $SSH_COMMON $KEY_OPT -W %h:%p ${PF_USER}@${WAN_IP}" \
        "${PUSER}@${PIP}" "echo ok" &>/dev/null; then
        echo "OK"
      else
        echo "FAIL"
      fi
    done

    # Test NAT port forwards from WAN side
    for nr in $NAT_RULES; do
      IFS=: read -r WPORT TIP TPORT <<< "$nr"
      echo -n "  NAT WAN:$WPORT -> $TIP:$TPORT ... "
      if ssh $SSH_COMMON $KEY_OPT -p "$WPORT" "${NAT_USER:-$USER}@${WAN_IP}" "echo ok" &>/dev/null; then
        echo "OK"
      else
        echo "FAIL"
      fi
    done
  fi
}

step_summary() {
  local PF_USER="${PFSENSE%%@*}"
  local PF_WAN="${WAN_IP:-<WAN-IP>}"
  local KEY_FLAG=""
  [[ -n "$CLIENT_KEY" ]] && KEY_FLAG="-i $CLIENT_KEY "
  [[ -z "$KEY_FLAG" && -n "$KEY" ]] && KEY_FLAG="-i $KEY "

  echo ""
  echo "=== pfSense bootstrap complete ==="
  echo "  pfSense LAN: ${PF_USER}@${LAN_IP}"
  echo "  pfSense WAN: $PF_WAN"
  [[ -n "$CLIENT_IP" ]] && echo "  Client WAN:  $CLIENT_IP"
  [[ -n "$CLIENT_LAN_IP" ]] && echo "  Client LAN:  $CLIENT_LAN_IP"
  [[ -n "$PROXY_TARGETS" ]] && echo "  Proxy:       SSH ProxyJump through pfSense"
  [[ -n "$TUNNELS" ]] && echo "  Tunnels:     ssh -N oline-tunnels"
  [[ -n "$REVERSE_TUNNEL_INFO" ]] && echo "  Call-home:   $REVERSE_TUNNEL_INFO"

  [[ -z "$CLIENT_IP" ]] && return 0

  echo ""
  echo "  ── Verify from client ($CLIENT_IP) ──"
  echo ""
  echo "  # SSH to pfSense via WAN"
  echo "  ssh ${KEY_FLAG}${PF_USER}@${PF_WAN} \"/bin/sh -c 'echo ok'\""

  for pt in $PROXY_TARGETS; do
    local PUSER="${pt%%@*}"
    local PIP="${pt#*@}"
    echo ""
    echo "  # SSH to $PIP via ProxyJump through pfSense"
    echo "  ssh ${KEY_FLAG}-o ProxyCommand=\"ssh ${KEY_FLAG}-W %h:%p ${PF_USER}@${PF_WAN}\" ${PUSER}@${PIP} 'echo ok'"
  done

  if [[ -n "$TUNNELS" ]]; then
    echo ""
    echo "  # Start all tunnels (Ctrl-C to stop)"
    echo "  ssh -N oline-tunnels"
    echo ""
    echo "  # Tunnels available at:"
    for tun in $TUNNELS; do
      IFS=: read -r LPORT THOST TPORT <<< "$tun"
      echo "    localhost:$LPORT -> $THOST:$TPORT"
    done
  fi
}

# ── Run ───────────────────────────────────────────────────────────────────────
# Add/remove/reorder steps here.

STEPS=(
  step_verify_access
  detect_context
  step_resubnet
  step_static_ip
  step_reset
  step_disable_blockpriv
  step_pubkey_only
  step_persist_authorized_keys
  step_wan_rules
  step_nat_forwards
  step_collision_routes
  step_reverse_tunnel
  step_ssh_config
  step_verify_wan
  step_summary
)

_set_tunnel_target
client_target
for step in "${STEPS[@]}"; do
  $step
done
