ARG DEBIAN_VERSION=buster
ARG BUILD_IMAGE=default
ARG BUILD_METHOD=source
ARG GOLANG_VERSION=1.22.9-bookworm
ARG BASE_IMAGE=golang:${GOLANG_VERSION}
ARG DEBIAN_IMAGE=debian:${DEBIAN_VERSION}

#
# Default build environment for standard Tendermint chains
#
FROM ${BASE_IMAGE} AS build_base

ARG PROJECT
ARG PROJECT_BIN=$PROJECT
ARG INSTALL_PACKAGES

RUN apt-get update && \
  apt-get install --no-install-recommends --assume-yes curl unzip pv ${INSTALL_PACKAGES} && \
  apt-get clean

#
# Optional build environment when libwasmvm.so is required
#
FROM build_base AS build_wasmvm

ARG WASMVM_VERSION=v1.5.4
ARG WASMVM_URL=https://raw.githubusercontent.com/CosmWasm/wasmvm/${WASMVM_VERSION}/api/libwasmvm.so
ADD ${WASMVM_URL} /lib/libwasmvm.so

#
# Default build from source method
#
FROM build_base AS build_source

ARG VERSION
ARG REPOSITORY
ARG BUILD_CMD="make install"
ARG BUILD_DIR=/data

RUN git clone $REPOSITORY /data
WORKDIR $BUILD_DIR
RUN git checkout $VERSION

#
# Optional build environment for Skip support
#
FROM build_source AS build_skip

# Get MEV_TENDERMINT_VERSION from
# https://raw.githubusercontent.com/skip-mev/config/main/$CHAIN_ID/mev-tendermint_version.txt
ARG MEV_TENDERMINT_VERSION

RUN go mod edit -replace github.com/tendermint/tendermint=github.com/skip-mev/mev-tendermint@$MEV_TENDERMINT_VERSION && \
    go mod tidy

#
# Final build environment
# Note optional `BUILD_METHOD` argument controls the base image
#
FROM build_${BUILD_METHOD} AS build

ARG BUILD_PATH=$GOPATH/bin
RUN $BUILD_CMD

RUN ldd $BUILD_PATH/$PROJECT_BIN | tr -s '[:blank:]' '\n' | grep '^/' | \
    xargs -I % sh -c 'mkdir -p $(dirname deps%); cp % deps%;'

RUN mv $BUILD_PATH/$PROJECT_BIN /bin/$PROJECT_BIN

#
# Default image
#
FROM ${DEBIAN_IMAGE} AS default

ARG PROJECT
ARG PROJECT_BIN=$PROJECT
ARG BUILD_DIR=/data

COPY --from=build /bin/$PROJECT_BIN /bin/$PROJECT_BIN
COPY --from=build $BUILD_DIR/deps/ /

#
# Optional image to install from binary
#
FROM build_base AS binary

ARG BINARY_URL

RUN curl -Lo /bin/$PROJECT_BIN $BINARY_URL
RUN chmod +x /bin/$PROJECT_BIN

#
# Optional image to install from binary zip
#
FROM build_base AS binary_zip

ARG BINARY_URL
ARG BINARY_ZIP_PATH

RUN curl -Lo /bin/$PROJECT_BIN.zip $BINARY_URL
RUN unzip /bin/$PROJECT_BIN.zip -d /bin && rm /bin/$PROJECT_BIN.zip
RUN if [ -n "$BINARY_ZIP_PATH" ]; then \
      mv /bin/${BINARY_ZIP_PATH} /bin; \
    fi
RUN chmod +x /bin/$PROJECT_BIN

#
# ZSTD build
#
FROM gcc:12 AS zstd_build

ARG ZTSD_SOURCE_URL="https://github.com/facebook/zstd/releases/download/v1.5.6/zstd-1.5.6.tar.gz"

ENV VIRTUAL_ENV=/opt/venv
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

RUN apt-get update && \
      apt-get install --no-install-recommends --assume-yes meson ninja-build && \
      apt-get clean && \
    mkdir -p /tmp/zstd && \
    cd /tmp/zstd && \
    curl -Lo zstd.source $ZTSD_SOURCE_URL && \
    file zstd.source | grep -q 'gzip compressed data' && mv zstd.source zstd.source.gz && gzip -d zstd.source.gz && \
    file zstd.source | grep -q 'tar archive' && mv zstd.source zstd.source.tar && tar -xf zstd.source.tar --strip-components=1 && rm zstd.source.tar && \
    LDFLAGS=-static \
    meson setup \
      -Dbin_programs=true \
      -Dstatic_runtime=true \
      -Ddefault_library=static \
      -Dzlib=disabled -Dlzma=disabled -Dlz4=disabled \
      build/meson builddir-st && \
    ninja -C builddir-st && \
    ninja -C builddir-st install && \
    /usr/local/bin/zstd -v

#
# Final Omnibus image
# Note optional `BUILD_IMAGE` argument controls the base image
#
FROM ${BUILD_IMAGE} AS omnibus
LABEL org.opencontainers.image.source https://github.com/terpnetwork/o-line

RUN apt-get update && \
  apt-get install --no-install-recommends --assume-yes ca-certificates apt-transport-https curl wget file unzip liblz4-tool gnupg2 jq pv && \
  apt-get clean

# install caddy 
RUN echo "deb [trusted=yes] https://apt.fury.io/caddy/ /" | tee -a /etc/apt/sources.list.d/caddy-fury.list
RUN apt-get update && apt-get install -y caddy

COPY --from=zstd_build /usr/local/bin/zstd /bin/

ARG PROJECT
ARG PROJECT_BIN
ARG PROJECT_DIR
ARG CONFIG_DIR
ARG START_CMD
ARG INIT_CMD
ARG VERSION
ARG REPOSITORY

ENV PROJECT=$PROJECT
ENV PROJECT_BIN=$PROJECT_BIN
ENV PROJECT_DIR=$PROJECT_DIR
ENV CONFIG_DIR=$CONFIG_DIR
ENV START_CMD=$START_CMD
ENV INIT_CMD=$INIT_CMD
ENV VERSION=$VERSION
ENV REPOSITORY=$REPOSITORY

ENV MONIKER=my-omnibus-node

EXPOSE 26656 \
       26657 \
       1317  \
       9090  \
       8080

# Install AWS
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
  && unzip awscliv2.zip -d /usr/src && rm -f awscliv2.zip \
  && /usr/src/aws/install --bin-dir /usr/bin

# Install Storj DCS uplink client
RUN curl -L https://github.com/storj/storj/releases/latest/download/uplink_linux_amd64.zip -o uplink_linux_amd64.zip && \
  unzip -o uplink_linux_amd64.zip && \
  install uplink /usr/bin/uplink && \
  rm -f uplink uplink_linux_amd64.zip

# Copy scripts
COPY run.sh snapshot.sh /usr/bin/
RUN chmod +x /usr/bin/run.sh /usr/bin/snapshot.sh
ENTRYPOINT ["run.sh"]
CMD []
