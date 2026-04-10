# ── Akash Devnet Lifecycle (DEPRECATED — use ict-rs tests via `just test akash`) ──
# These recipes manage the shell-script-based devnet. Kept for manual debugging
# but ict-rs Docker tests are the primary path.
# NOTE: `just test akash-shell` now runs the Rust test (akash_parallel.rs) via ict-rs.

# DEPRECATED: use `just test akash` instead
akash-setup:
    ./tests/akash-devnet.sh setup

akash-start:
    ./tests/akash-devnet.sh start

akash-wait:
    ./tests/akash-devnet.sh wait

akash-stop:
    ./tests/akash-devnet.sh stop

akash-clean:
    ./tests/akash-devnet.sh clean

akash-status:
    ./tests/akash-devnet.sh status

akash-info:
    ./tests/akash-devnet.sh info

# ── local-terp lifecycle ─────────────────────────────────────────────────────

start-localterp nowait="":
    #!/usr/bin/env bash
    if [ "{{nowait}}" = "nowait" ]; then
        ./tests/localterp.sh start
    else
        ./tests/localterp.sh wait
    fi

stop-localterp:
    ./tests/localterp.sh stop
