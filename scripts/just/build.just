# ── Build & Dev ──────────────────────────────────────────────────────────────

# Check compilation without building
check:
    cargo check

# Build debug binary
build:
    cargo build

# Build optimized release binary
release:
    cargo build --release

# Install to ~/.cargo/bin
install:
    cargo install --path .

# Install using vendored crates (no network required)
install-vendored:
    cargo install --path . --frozen --offline

# Dry run: encrypt + deploy with --raw (no .env needed)
dry-run:
    cargo run -- deploy --raw

# Run deploy using encrypted mnemonic from .env
deploy:
    cargo run -- deploy

# Encrypt mnemonic and store in .env
encrypt:
    cargo run -- encrypt

# Run clippy lints
lint:
    cargo clippy -- -D warnings

# Format code
fmt:
    cargo fmt

# Full workspace sync: build binary → CLI docs → tool schemas → team agents.
# One command to bring every generated artifact up to date.
sync: build gen-docs gen-tools team-sync
    @echo "Workspace synced (binary, docs, tools, agents)"

alias s := sync

# ── Docker: oline-omnibus ─────────────────────────────────────────────────────
#
# Two-stage build:
#   1. cosmos-omnibus (generic base) — built from tools/cosmos-omnibus
#   2. oline-omnibus (wrapper)       — adds sshd + oline entrypoint
#
# Local dev builds use `docker build` (single arch, loads into local daemon).
# Publish builds use `docker buildx` (multi-arch, pushes to registries).

omnibus_local_tag := "cosmos-omnibus:generic-local"

# ── Local builds (single arch, no push) ──────────────────────────────────────

# Build generic cosmos-omnibus locally
build-omnibus tag=omnibus_local_tag:
    docker build \
        --build-arg BASE_METHOD=base \
        -t {{tag}} \
        tools/cosmos-omnibus/

# Build oline-omnibus wrapper locally (requires build-omnibus first)
build-wrapper base=omnibus_local_tag tag="oline-omnibus:local":
    docker build \
        --build-arg BASE_IMAGE={{base}} \
        -t {{tag}} \
        docker/oline-omnibus/

# Build both stages locally in one command
build-oline-image: build-omnibus build-wrapper

# ── Multi-arch builds (amd64 + arm64, push to GHCR + Docker Hub) ─────────────

# Build + push generic cosmos-omnibus (multi-arch)
push-omnibus tag="generic":
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg BASE_METHOD=base \
        --tag {{ghcr_omnibus}}-base:{{tag}} \
        --push \
        tools/cosmos-omnibus/

# Build + push oline-omnibus wrapper (multi-arch)
# Usage: just push-oline-omnibus            → uses oline_omnibus_version
#        just push-oline-omnibus v0.2.0     → custom version
push-oline-omnibus tag=oline_omnibus_version:
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg BASE_IMAGE={{ghcr_omnibus}}-base:generic \
        --tag {{ghcr_omnibus}}:{{tag}} \
        --tag {{dh_omnibus}}:{{tag}} \
        --push \
        docker/oline-omnibus/

# Same as above but also tags :latest
push-oline-omnibus-latest tag=oline_omnibus_version:
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --build-arg BASE_IMAGE={{ghcr_omnibus}}-base:generic \
        --tag {{ghcr_omnibus}}:{{tag}} \
        --tag {{ghcr_omnibus}}:latest \
        --tag {{dh_omnibus}}:{{tag}} \
        --tag {{dh_omnibus}}:latest \
        --push \
        docker/oline-omnibus/

# Full publish pipeline: push omnibus base → push oline wrapper + latest
publish-oline-image tag=oline_omnibus_version: (push-omnibus) (push-oline-omnibus-latest tag)

# Clean build artifacts
clean:
    cargo clean
