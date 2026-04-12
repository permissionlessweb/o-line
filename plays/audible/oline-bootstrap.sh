#!/bin/bash
# oline-bootstrap.sh — SSH bootstrap for vanilla cosmos-omnibus containers
#
# Fetched at runtime via SDL command/args:
#   curl -fsSL ${OLINE_ENTRYPOINT_URL} -o /tmp/wrapper.sh; bash /tmp/wrapper.sh
#
# Combines what the old oline-omnibus Dockerfile (apt-get install openssh-server)
# and entrypoint.sh (SSH key setup, sshd launch) did into a single fetchable script.
#
# After this script starts sshd, oline connects via SSH, delivers TLS certs,
# then invokes /tmp/wrapper.sh again with OLINE_PHASE=start to run the cosmos
# node setup (the full oline-entrypoint.sh handles that phase).

set -e
[ "$DEBUG" = "2" ] && set -x

die() { echo "ERROR: $*" >&2; exit 1; }

[ -n "$SSH_PUBKEY" ] || die "SSH_PUBKEY is required"

# ── Install openssh-server ──────────────────────────────────────────────────
if ! command -v sshd >/dev/null 2>&1 && ! [ -x /usr/sbin/sshd ] && ! [ -x /sbin/sshd ]; then
  echo "[oline-bootstrap] Installing openssh-server..."
  _installed=0
  for _try in 1 2 3; do
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -qq 2>&1 | tail -3 || true
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssh-server 2>&1 \
        && _installed=1 && break
    elif command -v apk >/dev/null 2>&1; then
      apk add --no-cache openssh 2>&1 && _installed=1 && break
    else
      echo "[oline-bootstrap] No supported package manager found" && break
    fi
    echo "[oline-bootstrap] openssh install attempt $_try failed, retrying in 5s..."
    sleep 5
  done
  [ "$_installed" = "0" ] && die "openssh-server install failed after 3 tries"
fi

# ── Locate sshd binary ─────────────────────────────────────────────────────
SSHD_BIN=$(command -v sshd 2>/dev/null \
  || { [ -x /usr/sbin/sshd ] && echo /usr/sbin/sshd; } \
  || { [ -x /sbin/sshd ]     && echo /sbin/sshd; } \
  || true)
[ -z "$SSHD_BIN" ] && die "sshd not found after install"

# ── Authorize SSH key ───────────────────────────────────────────────────────
mkdir -p /root/.ssh
echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# ── Configure sshd ──────────────────────────────────────────────────────────
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
printf '\nPermitRootLogin yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config

mkdir -p /tmp/tls

# ── Persist env vars for start phase ────────────────────────────────────────
# SSH sessions get a minimal environment; save SDL vars so OLINE_PHASE=start
# can restore them.
export -p | grep -v 'OLINE_PHASE' > /tmp/oline-env.sh

echo "[oline-bootstrap] Bootstrap complete — sshd started."
# Run sshd in background; keep the shell as PID 1 so container stdout stays
# open for provider log streaming. The start-phase script writes to
# /proc/1/fd/1 which is this shell's stdout — visible via lease-logs / TUI.
"$SSHD_BIN" -D &
wait
