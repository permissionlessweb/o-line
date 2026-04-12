#!/bin/bash
# oline-omnibus entrypoint — SSH bootstrap for Akash-deployed nodes.
#
# Sets up sshd, authorizes the oline deployer's public key, persists the SDL
# environment, and hands off to sshd. The oline orchestrator connects via
# SSH/SFTP to push scripts (entrypoint, tls-setup, chain.json, nginx configs)
# then signals the node to start.
#
# Required env: SSH_PUBKEY

set -e

die() { echo "ERROR: $*" >&2; exit 1; }

[ -n "$SSH_PUBKEY" ] || die "SSH_PUBKEY is required"

# ── Raise fd limit ───────────────────────────────────────────────────────────
# Akash providers share inotify/fd pools across all pods on a node. Raise our
# soft limit so the kernel doesn't reject new watchers for log collection.
ulimit -n 65536 2>/dev/null || true

# ── Authorize deployer key ───────────────────────────────────────────────────
mkdir -p /root/.ssh
echo "$SSH_PUBKEY" >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

# ── Configure sshd ──────────────────────────────────────────────────────────
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
# Log to stderr only (-e) — avoids syslog/journald fd overhead.
# LogLevel QUIET suppresses per-connection auth logs that the provider's
# log collector would otherwise create fsnotify watchers for.
printf '\nPermitRootLogin yes\nPubkeyAuthentication yes\nLogLevel QUIET\n' >> /etc/ssh/sshd_config

# ── Prepare working dirs ────────────────────────────────────────────────────
mkdir -p /tmp/tls

# ── Persist SDL env vars ─────────────────────────────────────────────────────
# SSH sessions begin with a minimal environment — SDL vars won't be present
# otherwise. Save them so the start phase can restore them.
export -p | grep -v 'OLINE_PHASE' > /tmp/oline-env.sh

echo "Bootstrap complete — sshd started. oline will connect shortly."
# Run sshd in background; keep the shell as PID 1 so container stdout stays
# open for provider log streaming. The start-phase script writes to
# /proc/1/fd/1 which is this shell's stdout — visible via lease-logs / TUI.
/usr/sbin/sshd -D -e &
wait
