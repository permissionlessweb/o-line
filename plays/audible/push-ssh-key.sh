#!/bin/bash
# push-ssh-key.sh
#
# Push an SSH public key to one or more remote hosts (pfSense, servers, etc.).
# Handles pfSense's restricted shell by wrapping commands in /bin/sh -c.
# Idempotent — safe to run multiple times (sort -u deduplicates).
#
# Usage:
#   ./push-ssh-key.sh                          # interactive prompts
#   ./push-ssh-key.sh admin@192.168.1.1        # specify target
#   ./push-ssh-key.sh admin@192.168.1.1 root@10.0.0.50
#
# Environment variables (override prompts):
#   SSH_PUBKEY_FILE   — path to public key (default: ~/.ssh/oline-fw.pub)
#   SSH_PASSWORD      — password for target hosts (skips prompt)
#   SSH_P          — port (default: 22)

set -euo pipefail

log()  { echo "[push-key] $*"; }
die()  { echo "[push-key] ERROR: $*" >&2; exit 1; }
ok()   { echo "[push-key] OK: $*"; }

# ── 1. Resolve public key ────────────────────────────────────────────────────

PUBKEY_FILE="${SSH_PUBKEY_FILE:-$HOME/.ssh/oline-fw.pub}"

if [ ! -f "$PUBKEY_FILE" ]; then
    log "No pubkey found at $PUBKEY_FILE"

    # Check for common key files
    for candidate in "$HOME/.ssh/id_ed25519.pub" "$HOME/.ssh/id_rsa.pub"; do
        if [ -f "$candidate" ]; then
            log "Found existing key: $candidate"
            printf "  Use %s? [Y/n] " "$candidate"
            read -r ans
            if [ -z "$ans" ] || [ "$ans" = "y" ] || [ "$ans" = "Y" ]; then
                PUBKEY_FILE="$candidate"
                break
            fi
        fi
    done

    # Generate if still not found
    if [ ! -f "$PUBKEY_FILE" ]; then
        log "Generating new ed25519 key pair → $HOME/.ssh/oline-fw"
        ssh-keygen -t ed25519 -f "$HOME/.ssh/oline-fw" -N "" -q
        PUBKEY_FILE="$HOME/.ssh/oline-fw.pub"
    fi
fi

PUBKEY=$(cat "$PUBKEY_FILE")
log "Public key: $PUBKEY_FILE"
log "  ${PUBKEY:0:50}..."

# ── 2. Resolve targets ───────────────────────────────────────────────────────

TARGETS=("$@")

if [ ${#TARGETS[@]} -eq 0 ]; then
    printf "  Target host(s) — [user@]host[:port], space-separated:\n  > "
    read -r -a TARGETS
fi

[ ${#TARGETS[@]} -eq 0 ] && die "No targets specified"

# ── 3. Resolve password ──────────────────────────────────────────────────────

if [ -z "${SSH_PASSWORD:-}" ]; then
    printf "  SSH password for targets: "
    read -rs SSH_PASSWORD
    echo
fi

[ -z "$SSH_PASSWORD" ] && die "Password required"

# ── 4. Check sshpass ──────────────────────────────────────────────────────────

if ! command -v sshpass >/dev/null 2>&1; then
    die "sshpass not found. Install it first:
  macOS:  brew install hudochenkov/sshpass/sshpass
  Debian: apt install sshpass"
fi

# ── 5. Push key to each target ────────────────────────────────────────────────

# Pipe pubkey via stdin to avoid shell quoting issues with /bin/sh -c
INSTALL_CMD='mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys && sort -u ~/.ssh/authorized_keys -o ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys'

FAILED=0
SUCCEEDED=0

for target in "${TARGETS[@]}"; do
    # Parse [user@]host[:port]
    user="admin"
    host="$target"
    port="${SSH_P:-22}"

    if [[ "$target" == *"@"* ]]; then
        user="${target%%@*}"
        host="${target#*@}"
    fi
    if [[ "$host" == *":"* ]]; then
        port="${host##*:}"
        host="${host%:*}"
    fi

    log "Pushing key to ${user}@${host}:${port} ..."

    # Install key — pipe pubkey via stdin, /bin/sh -c bypasses pfSense menu
    # PubkeyAuthentication=no forces password auth so sshpass works
    # (avoids conflict with passphrase-protected keys in ~/.ssh/)
    if echo "$PUBKEY" | sshpass -p "$SSH_PASSWORD" ssh \
        -o PubkeyAuthentication=no \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 \
        -p "$port" \
        "${user}@${host}" \
        "/bin/sh -c '${INSTALL_CMD}'"; then

        # Verify key-based auth works
        privkey="${PUBKEY_FILE%.pub}"
        if [ -f "$privkey" ]; then
            if ssh -i "$privkey" \
                -o StrictHostKeyChecking=no \
                -o UserKnownHostsFile=/dev/null \
                -o BatchMode=yes \
                -o ConnectTimeout=10 \
                -p "$port" \
                "${user}@${host}" \
                "echo ok" >/dev/null 2>&1; then
                ok "${user}@${host} — key installed and verified"
            else
                log "${user}@${host} — key installed but verification failed (may still work)"
            fi
        else
            ok "${user}@${host} — key installed (no private key found to verify)"
        fi
        SUCCEEDED=$((SUCCEEDED + 1))
    else
        log "FAILED: ${user}@${host} — could not connect or install key"
        FAILED=$((FAILED + 1))
    fi
done

# ── 6. Summary ────────────────────────────────────────────────────────────────

echo
log "=== Done ==="
log "  Succeeded: $SUCCEEDED"
[ "$FAILED" -gt 0 ] && log "  Failed:    $FAILED"
log "  Key file:  $PUBKEY_FILE"
log ""
log "  Test:  ssh -i ${PUBKEY_FILE%.pub} <user>@<host> '/bin/sh -c \"echo ok\"'"
log ""
log "  When oline is installed:"
log "    oline firewall bootstrap --host <PFSENSE_IP> --pubkey $PUBKEY_FILE"
