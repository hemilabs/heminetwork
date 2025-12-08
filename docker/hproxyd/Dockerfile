# Copyright (c) 2025 Hemi Labs, Inc.
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
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" hproxyd

# Run stage
FROM cgr.dev/chainguard/static@sha256:d44809cee093b550944c1f666ff13301f92484bfdd2e53ecaac82b5b6f89647d

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
      org.opencontainers.image.title="hProxy" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="hProxy" \
      org.label-schema.url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Hemi Labs" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Copy binary
COPY --from=builder /build/bin/hproxyd /usr/local/bin/hproxyd

# Environment variables
ENV HPROXY_CLIENT_IDLE_TIMEOUT=""
ENV HPROXY_HVM_URLS=""
ENV HPROXY_METHOD_WHITELIST=""
ENV HPROXY_LOG_LEVEL=""
ENV HPROXY_CONTROL_ADDRESS=""
ENV HPROXY_LISTEN_ADDRESS=""
ENV HPROXY_NETWORK=""
ENV HPROXY_PROMETHEUS_ADDRESS=""
ENV HPROXY_PPROF_ADDRESS=""
ENV HPROXY_POLL_FREQUENCY=""
ENV HPROXY_REQUEST_SIZE=""
ENV HPROXY_REQUEST_TIMEOUT=""

WORKDIR /etc/hproxyd/
ENTRYPOINT ["/usr/local/bin/hproxyd"]
