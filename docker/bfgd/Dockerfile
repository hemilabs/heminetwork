# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.25.5-alpine3.22@sha256:3587db7cc96576822c606d119729370dbf581931c5f43ac6d3fa03ab4ed85a10 AS builder

ARG GO_LDFLAGS

# Add make and git
RUN apk --no-cache add --update make git

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make go-deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" bfgd

# Run stage
FROM cgr.dev/chainguard/static@sha256:a301031ffd4ed67f35ca7fa6cf3dad9937b5fa47d7493955a18d9b4ca5412d1a

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
      org.opencontainers.image.title="Bitcoin Finality Governor" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Bitcoin Finality Governor" \
      org.label-schema.url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Hemi Labs" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Copy binary
COPY --from=builder /build/bin/bfgd /usr/local/bin/bfgd

# Environment variables
ENV BFG_EXBTC_ADDRESS=""
ENV BFG_EXBTC_INITIAL_CONNECTIONS=""
ENV BFG_EXBTC_MAX_CONNECTIONS=""
ENV BFG_PUBLIC_KEY_AUTH=""
ENV BFG_BTC_START_HEIGHT=""
ENV BFG_LOG_LEVEL=""
ENV BFG_POSTGRES_URI=""
ENV BFG_PUBLIC_ADDRESS=""
ENV BFG_PRIVATE_ADDRESS=""
ENV BFG_PROMETHEUS_ADDRESS=""
ENV BFG_PPROF_ADDRESS=""
ENV BFG_REQUEST_LIMIT=""
ENV BFG_REQUEST_TIMEOUT=""
ENV BFG_TRUSTED_PROXIES=""
ENV BFG_REMOTE_IP_HEADERS=""

WORKDIR /etc/bfgd/
ENTRYPOINT ["/usr/local/bin/bfgd"]
