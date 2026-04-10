# Sites / Minio tests
#
#   just test sites all    — all sites tests (Docker + Akash)
#   just test sites docker — S3→IPFS pipeline + SiteStore round-trip
#   just test sites akash  — deploy g.yml to local Akash
#   just test sites minio  — build and test minio-ipfs image

import '../helpers.just'

set working-directory := "../../.."

# All sites tests (Docker + Akash)
all minio_image='ghcr.io/permissionlessweb/minio-ipfs:v0.0.9': _require-docker
    E2E_MINIO_IMAGE={{minio_image}} cargo test --features testing --test sites_standalone -- --nocapture --ignored

# S3→IPFS pipeline + SiteStore round-trip (Docker, no Akash)
docker minio_image='ghcr.io/permissionlessweb/minio-ipfs:v0.0.9': _require-docker
    E2E_MINIO_IMAGE={{minio_image}} cargo test --features testing --test sites_standalone test_minio_ipfs_dual_use -- --nocapture --ignored

# Deploy g.yml to local Akash via IctAkashNetwork
akash minio_image='ghcr.io/permissionlessweb/minio-ipfs:v0.0.9': _require-docker
    E2E_MINIO_IMAGE={{minio_image}} cargo test --features testing --test sites_standalone test_sites_deploy_to_akash -- --nocapture --ignored

# Build and test minio-ipfs image locally
minio: _require-docker
    @cd plays/instant-replay &&\
    docker build -t minio-ipfs:latest . &&\
    E2E_IMAGE=minio-ipfs:latest ./e2e-test.sh
