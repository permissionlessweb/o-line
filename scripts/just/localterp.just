# ── localterp-zk Docker builds ────────────────────────────────────────────────
#
# Multi-arch (amd64 + arm64) builds of terp-core with zk-wasmvm.
# Stages both architecture libs + Go source from sibling repos, then
# uses docker buildx to push to GHCR + Docker Hub.

# Sibling repo paths (relative to o-line root)
terp_core_dir  := "../../terp-core"
zk_wasmvm_dir  := "../../zk-wasmvm"
zk_wasmd_dir   := "../../zk-wasmd"

# Registry targets
ghcr_terp := "ghcr.io/terpnetwork/terp-core"
dh_terp   := "docker.io/terpnetwork/terp-core"

# ── Stage zk dependencies (both arch libs + Go source) ───────────────────────

# Stage both aarch64 + x86_64 wasmvm libs and zk Go source into terp-core/build/
stage-zk-multiarch:
    #!/usr/bin/env bash
    set -euo pipefail
    TC="{{terp_core_dir}}"
    ZK="{{zk_wasmvm_dir}}"
    ZD="{{zk_wasmd_dir}}"

    echo "==> Staging wasmvm libs (both architectures)"
    mkdir -p "$TC/build/wasmvm" "$TC/build/zk-deps/zk-wasmvm" "$TC/build/zk-deps/zk-wasmd"

    for arch in aarch64 x86_64; do
        lib=""
        for candidate in "$ZK/internal/api/libwasmvm_muslc.${arch}.a" \
                         "$ZK/libwasmvm/artifacts/libwasmvm_muslc.${arch}.a"; do
            if [ -f "$candidate" ]; then lib="$candidate"; break; fi
        done
        if [ -z "$lib" ]; then
            echo "ERROR: libwasmvm_muslc.${arch}.a not found in $ZK"
            exit 1
        fi
        cp "$lib" "$TC/build/wasmvm/"
        echo "  staged: libwasmvm_muslc.${arch}.a"
    done

    echo "==> Staging zk-wasmvm Go source"
    rsync -a --delete --exclude='libwasmvm/target/' --exclude='.git/' "$ZK/" "$TC/build/zk-deps/zk-wasmvm/"

    echo "==> Staging zk-wasmd Go source"
    rsync -a --delete --exclude='.git/' "$ZD/" "$TC/build/zk-deps/zk-wasmd/"
    echo "==> Done staging"

# ── Local single-arch build (loads into Docker daemon) ───────────────────────

# Build localterp-zk locally (current arch only, no push)
build-localterp-zk: stage-zk-multiarch
    cd {{terp_core_dir}} && \
    DOCKER_BUILDKIT=1 docker buildx build \
        --target localterp \
        --build-arg WASMVM_SOURCE=local \
        -t terpnetwork/terp-core:localterp-zk --load .

# Build terp-core:local-zk runtime locally (current arch only, no push)
build-terp-zk: stage-zk-multiarch
    cd {{terp_core_dir}} && \
    DOCKER_BUILDKIT=1 docker build \
        -t terpnetwork/terp-core:local-zk \
        --target runtime \
        --build-arg RUNNER_IMAGE=alpine:3.17 \
        --build-arg WASMVM_SOURCE=local \
        -f Dockerfile .

# ── Multi-arch push (amd64 + arm64 → GHCR + Docker Hub) ─────────────────────

# Build + push localterp-zk multi-arch
# Usage: just push-localterp-zk                → tag "localterp-zk"
#        just push-localterp-zk localterp-zk-v2 → custom tag
push-localterp-zk tag="localterp-zk": stage-zk-multiarch
    cd {{terp_core_dir}} && \
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --target localterp \
        --build-arg WASMVM_SOURCE=local \
        --tag {{ghcr_terp}}:{{tag}} \
        --tag {{dh_terp}}:{{tag}} \
        --push .

# Build + push localterp-zk multi-arch and also tag :latest
push-localterp-zk-latest tag="localterp-zk": stage-zk-multiarch
    cd {{terp_core_dir}} && \
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --target localterp \
        --build-arg WASMVM_SOURCE=local \
        --tag {{ghcr_terp}}:{{tag}} \
        --tag {{ghcr_terp}}:latest \
        --tag {{dh_terp}}:{{tag}} \
        --tag {{dh_terp}}:latest \
        --push .

# Build + push terp-core runtime (zk, alpine) multi-arch
push-terp-zk tag="zk": stage-zk-multiarch
    cd {{terp_core_dir}} && \
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --target runtime \
        --build-arg RUNNER_IMAGE=alpine:3.17 \
        --build-arg WASMVM_SOURCE=local \
        --tag {{ghcr_terp}}:{{tag}} \
        --tag {{dh_terp}}:{{tag}} \
        --push .

# Clean staged zk build artifacts from terp-core
clean-zk-stage:
    rm -rf {{terp_core_dir}}/build/zk-deps {{terp_core_dir}}/build/wasmvm
    @echo "Cleaned staged zk dependencies"
