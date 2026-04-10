# ── Private Helpers ───────────────────────────────────────────────────────────
# Shared boilerplate used by test/e2e recipes across domain files.
# Private recipes are hidden from `just --list`.

# Resolve OMNIBUS_IMAGE from arg > env > .env file.
# Prints the resolved image name to stdout; exits 1 if unset.
[private]
_resolve-omnibus fallback="":
    #!/usr/bin/env bash
    _dotenv=".env"
    _read_env() { grep -m1 "^$1=" "$_dotenv" 2>/dev/null | cut -d= -f2-; }
    IMG="${fallback:-${E2E_OMNIBUS_IMAGE:-${OMNIBUS_IMAGE:-$([ -f "$_dotenv" ] && _read_env OMNIBUS_IMAGE || true)}}}"
    [ -z "$IMG" ] && { echo "ERROR: OMNIBUS_IMAGE not set (export or add to .env)" >&2; exit 1; }
    echo "$IMG"

# Ensure Akash devnet is running; start if possible, fail if prerequisites missing.
[private]
_ensure-akash-devnet:
    #!/usr/bin/env bash
    set -euo pipefail
    if ./tests/akash-devnet.sh status 2>/dev/null | grep -q running; then
        exit 0
    fi
    if ./tests/akash-devnet.sh check 2>/dev/null; then
        echo "[akash] Starting devnet..."
        ./tests/akash-devnet.sh wait >/dev/null
    else
        echo "ERROR: Akash devnet prerequisites not met (run: just akash-setup)" >&2
        exit 1
    fi

# Assert Docker daemon is reachable.
[private]
_require-docker:
    #!/usr/bin/env bash
    command -v docker &>/dev/null && docker info &>/dev/null 2>&1 \
        || { echo "ERROR: Docker not available" >&2; exit 1; }
