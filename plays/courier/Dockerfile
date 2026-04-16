# ── Stage 1: Build static binary with musl ──
# Use the target platform's native rust image so no cross-compiler is needed.
FROM rust:1.87-alpine AS builder

RUN apk add --no-cache musl-dev pkgconf

WORKDIR /build
COPY Cargo.toml Cargo.lock* ./
COPY src/ src/

# Detect the native musl target and build a fully static binary.
# Since we're using the target-platform rust image (not BUILDPLATFORM),
# the native target is always correct — no cross-compilation needed.
RUN RUST_TARGET=$(rustc -vV | grep host | awk '{print $2}') && \
    RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --release --target $RUST_TARGET && \
    cp /build/target/$RUST_TARGET/release/courier /build/courier

# ── Stage 2: Scratch image — just the binary ──
FROM scratch

# Copy the static binary
COPY --from=builder /build/courier /courier

# Copy CA certificates for HTTPS fetching
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt

# Create data directory
WORKDIR /srv/bootstrap

ENV COURIER_PORT=8080
ENV COURIER_DATA_DIR=/srv/bootstrap
ENV COURIER_SHUTDOWN_TIMEOUT=3600
ENV COURIER_EXPECTED_PEERS=0
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

EXPOSE 8080

ENTRYPOINT ["/courier"]
