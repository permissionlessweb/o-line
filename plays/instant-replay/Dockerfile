ARG ALPINE_VERSION=3.21
ARG GO_VERSION=1.24

# ── Stage 1: build MinIO + mc from source ────────────────────────────────────
FROM golang:${GO_VERSION}-alpine AS build-minio

ARG MINIO_VERSION=RELEASE.2025-10-15T17-29-55Z
ARG MC_VERSION=RELEASE.2025-08-13T08-35-41Z

RUN apk add --no-cache git

# Build MinIO server
RUN git clone --depth 1 --branch ${MINIO_VERSION} https://github.com/minio/minio.git /src/minio && \
    cd /src/minio && \
    go build -trimpath -tags kqueue -o /tmp/minio .

# Build mc client
RUN git clone --depth 1 --branch ${MC_VERSION} https://github.com/minio/mc.git /src/mc && \
    cd /src/mc && \
    go build -trimpath -o /tmp/mc .

# ── Stage 2: fetch other binaries ────────────────────────────────────────────
FROM alpine:${ALPINE_VERSION} AS fetch

ARG S6_OVERLAY_VERSION=3.2.0.2
ARG KUBO_VERSION=0.32.1

RUN apk add --no-cache curl tar xz

WORKDIR /tmp

# s6-overlay
RUN curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-noarch.tar.xz" \
      -o s6-overlay-noarch.tar.xz && \
    curl -fsSL "https://github.com/just-containers/s6-overlay/releases/download/v${S6_OVERLAY_VERSION}/s6-overlay-$(uname -m).tar.xz" \
      -o s6-overlay-arch.tar.xz

# Kubo (IPFS)
RUN ARCH=$(case "$(uname -m)" in x86_64) echo "amd64";; aarch64) echo "arm64";; *) echo "$(uname -m)";; esac) && \
    curl -fsSL "https://dist.ipfs.tech/kubo/v${KUBO_VERSION}/kubo_v${KUBO_VERSION}_linux-${ARCH}.tar.gz" \
      -o kubo.tar.gz && \
    tar xzf kubo.tar.gz kubo/ipfs && \
    mv kubo/ipfs /tmp/ipfs

# ── Stage 2: runtime ────────────────────────────────────────────────────────
FROM alpine:${ALPINE_VERSION}

# Extract s6-overlay
COPY --from=fetch /tmp/s6-overlay-noarch.tar.xz /tmp/
COPY --from=fetch /tmp/s6-overlay-arch.tar.xz /tmp/
RUN tar -C / -Jxpf /tmp/s6-overlay-noarch.tar.xz && \
    tar -C / -Jxpf /tmp/s6-overlay-arch.tar.xz && \
    rm /tmp/s6-overlay-*.tar.xz

# Install runtime dependencies
RUN apk add --no-cache \
    bash \
    ca-certificates \
    curl \
    jq \
    shadow \
    libc6-compat \
    nginx \
    certbot \
    certbot-nginx \
    gettext

# Copy binaries from build stages
COPY --from=fetch /tmp/ipfs /usr/local/bin/ipfs
COPY --from=build-minio /tmp/minio /usr/local/bin/minio
COPY --from=build-minio /tmp/mc /usr/local/bin/mc
RUN chmod +x /usr/local/bin/ipfs /usr/local/bin/minio /usr/local/bin/mc

# Create app user and directories
RUN addgroup -g 1000 app && \
    adduser -u 1000 -G app -D -h /home/app app && \
    mkdir -p /data/ipfs /data/minio

# Copy rootfs overlay (s6 services, scripts, utilities)
COPY rootfs/ /

# Make all scripts executable
RUN chmod +x /etc/s6-overlay/scripts/* && \
    chmod +x /etc/s6-overlay/s6-rc.d/svc-ipfs/run && \
    chmod +x /etc/s6-overlay/s6-rc.d/svc-autopin/run && \
    chmod +x /etc/s6-overlay/s6-rc.d/svc-minio/run && \
    chmod +x /etc/s6-overlay/s6-rc.d/svc-nginx/run && \
    chmod +x /usr/local/bin/ipfs-pin && \
    chmod +x /usr/local/bin/healthcheck

# Environment defaults
ENV MINIO_ENABLED="true" \
    MINIO_ROOT_USER="minioadmin" \
    MINIO_ROOT_PASSWORD="minioadmin" \
    MINIO_BUCKET="snapshots" \
    MINIO_PORT=9000 \
    MINIO_CONSOLE_PORT=9001 \
    IPFS_GATEWAY_PORT=8081 \
    IPFS_PROFILE=server \
    AUTOPIN_INTERVAL=300 \
    AUTOPIN_PATTERNS="*.tar.gz,*.tar.zst,*.tar.lz4,*.tar.xz" \
    PUID=1000 \
    PGID=1000

EXPOSE 80 443 8081 9000 9001

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD /usr/local/bin/healthcheck

VOLUME ["/data/ipfs", "/data/minio"]

ENTRYPOINT ["/init"]
