# oline-omnibus: thin wrapper around any cosmos-omnibus image.
#
# Pre-installs openssh-server and provides an entrypoint that bootstraps
# sshd so the oline orchestrator can connect via SSH/SFTP to push scripts
# and signal the node to start.
#
# Build with a locally-built omnibus (default):
#   just build-oline-image
#
# Or wrap a remote image:
#   just wrapper-image ghcr.io/akash-network/cosmos-omnibus:v1.2.38-generic

ARG BASE_IMAGE=cosmos-omnibus:generic-local
FROM ${BASE_IMAGE}

RUN apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        openssh-server && \
    rm -rf /var/lib/apt/lists/* && \
    mkdir -p /run/sshd

COPY entrypoint.sh /oline-entrypoint.sh
RUN chmod +x /oline-entrypoint.sh

ENTRYPOINT ["/oline-entrypoint.sh"]
