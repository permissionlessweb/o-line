#!/bin/sh

# ── Settings ──────────────────────────────────────────────────────────────────
minio_ipfs_version := "v0.0.9"
ghcr_image         := "ghcr.io/permissionlessweb/minio-ipfs"
dh_image           := "docker.io/permissionlessweb/minio-ipfs"

# ── oline-sdl ─────────────────────────────────────────────────────────────────
install:
    @cd plays/oline-sdl && just install

# ── minio-ipfs ────────────────────────────────────────────────────────────────

# Build and test minio-ipfs locally (current platform only)
test-minio-ipfs:
    @cd plays/instant-replay &&\
    docker build -t minio-ipfs:latest . &&\
    E2E_IMAGE=minio-ipfs:latest ./e2e-test.sh

# Build minio-ipfs for linux/amd64+arm64 and push to GHCR + Docker Hub
# Usage: just build-push-minio-ipfs            → uses minio_ipfs_version
#        just build-push-minio-ipfs v0.0.3     → custom tag
build-push-minio-ipfs tag=minio_ipfs_version:
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag {{ghcr_image}}:{{tag}} \
        --tag {{dh_image}}:{{tag}} \
        --push \
        plays/instant-replay

# Same as above but also retags :latest
build-push-minio-ipfs-latest tag=minio_ipfs_version:
    docker buildx build \
        --platform linux/amd64,linux/arm64 \
        --tag {{ghcr_image}}:{{tag}} \
        --tag {{ghcr_image}}:latest \
        --tag {{dh_image}}:{{tag}} \
        --tag {{dh_image}}:latest \
        --push \
        plays/instant-replay