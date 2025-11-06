# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.25.3-alpine3.22@sha256:aee43c3ccbf24fdffb7295693b6e33b21e01baec1b2a55acc351fde345e9ec34 AS builder

ARG GO_LDFLAGS

# Add make and git
RUN apk --no-cache add --update make git

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make go-deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" tbcd

# Run stage
FROM cgr.dev/chainguard/static@sha256:d4c20db9cb2dbf1ac9ec77f9dbc11080a78514a5f9b96096965550dbd1c73e09

# Build metadata
ARG VERSION
ARG VCS_REF
ARG BUILD_DATE
LABEL org.opencontainers.image.created=$BUILD_DATE \
      org.opencontainers.image.authors="Hemi Labs" \
      org.opencontainers.image.url="https://github.com/hemilabs/heminetwork" \
      org.opencontainers.image.source="https://github.com/hemilabs/heminetwork" \
      org.opencontainers.image.version=$VERSION \
      org.opencontainers.image.revision=$VCS_REF \
      org.opencontainers.image.vendor="Hemi Labs" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.title="Tiny Bitcoin Daemon" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Tiny Bitcoin Daemon" \
      org.label-schema.url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Hemi Labs" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Copy binary
COPY --from=builder /build/bin/tbcd /usr/local/bin/tbcd

# Environment variables
ENV TBC_ADDRESS=""
ENV TBC_AUTO_INDEX=""
ENV TBC_BLOCK_CACHE_SIZE=""
ENV TBC_BLOCKHEADER_CACHE_SIZE=""
ENV TBC_BLOCK_SANITY=""
ENV TBC_HEMI_INDEX=""
ENV TBC_LEVELDB_HOME="/etc/tbcd/"
ENV TBC_LISTEN_ADDRESS=""
ENV TBC_LOG_LEVEL=""
ENV TBC_MAX_CACHED_KEYSTONES=""
ENV TBC_MAX_CACHED_TXS=""
ENV TBC_MEMPOOL_ENABLED=""
ENV TBC_NETWORK=""
ENV TBC_PEERS_WANTED=""
ENV TBC_PPROF_ADDRESS=""
ENV TBC_SEEDS=""

WORKDIR /etc/tbcd/
ENTRYPOINT ["/usr/local/bin/tbcd"]
