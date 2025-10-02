# Copyright (c) 2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.25.1-alpine3.22@sha256:b6ed3fd0452c0e9bcdef5597f29cc1418f61672e9d3a2f55bf02e7222c014abd AS builder

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
FROM cgr.dev/chainguard/static@sha256:4cddf8bdcac1480e825d3c17c2f7248d21a774abda0e095cf25c19376b93eab5

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
