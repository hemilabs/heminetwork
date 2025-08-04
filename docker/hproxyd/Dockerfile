# Copyright (c) 2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.24.4-alpine3.22@sha256:68932fa6d4d4059845c8f40ad7e654e626f3ebd3706eef7846f319293ab5cb7a AS builder

ARG GO_LDFLAGS

# Add ca-certificates, timezone data, make and git
RUN apk --no-cache add --update ca-certificates tzdata make git

# Create non-root user
RUN addgroup --gid 65532 hproxyd && \
    adduser --disabled-password --gecos "" \
        --home "/etc/hproxyd/" --shell "/sbin/nologin" \
        -G hproxyd --uid 65532 hproxyd

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make go-deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" hproxyd

# Run stage
FROM scratch

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

# Copy files
COPY --from=builder /etc/group /etc/group
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /build/bin/hproxyd /usr/local/bin/hproxyd

# Environment variables
ENV HPROXY_CLIENT_IDLE_TIMEOUT=""
ENV HPROXY_HVM_URLS=""
ENV HPROXY_LOG_LEVEL=""
ENV HPROXY_CONTROL_ADDRESS=""
ENV HPROXY_LISTEN_ADDRESS=""
ENV HPROXY_NETWORK=""
ENV HPROXY_PROMETHEUS_ADDRESS=""
ENV HPROXY_PPROF_ADDRESS=""
ENV HPROXY_POLL_FREQUENCY=""
ENV HPROXY_REQUEST_TIMEOUT=""

USER hproxyd:hproxyd
WORKDIR /etc/hproxyd/
ENTRYPOINT ["/usr/local/bin/hproxyd"]
