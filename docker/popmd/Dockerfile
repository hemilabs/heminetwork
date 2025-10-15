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
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" popmd

# Run stage
FROM cgr.dev/chainguard/static@sha256:b00a88ca2a8136cdbd86a8aa834c3f69c17debb295a38055f7babfc2c9f9a02b

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
      org.opencontainers.image.title="PoP Miner" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="PoP Miner" \
      org.label-schema.url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Hemi Labs" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Copy binary
COPY --from=builder /build/bin/popmd /usr/local/bin/popmd

# Environment variables
ENV POPM_LOG_LEVEL=""
ENV POPM_BTC_PRIVKEY=""
ENV POPM_BFG_URL=""
ENV POPM_BTC_CHAIN_NAME=""
ENV POPM_PROMETHEUS_ADDRESS=""
ENV POPM_PPROF_ADDRESS=""
ENV POPM_REMINE_THRESHOLD=""
ENV POPM_STATIC_FEE=""

WORKDIR /etc/popmd/
ENTRYPOINT ["/usr/local/bin/popmd"]
