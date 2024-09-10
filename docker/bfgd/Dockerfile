# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.23-alpine3.20@sha256:d0b31558e6b3e4cc59f6011d79905835108c919143ebecc58f35965bf79948f4 AS builder

ARG GO_LDFLAGS

# Add ca-certificates, timezone data, make and git
RUN apk --no-cache add --update ca-certificates tzdata make git

# Create non-root user
RUN addgroup --gid 65532 bfgd && \
    adduser --disabled-password --gecos "" \
        --home "/etc/bfgd/" --shell "/sbin/nologin" \
        -G bfgd --uid 65532 bfgd

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" bfgd

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
      org.opencontainers.image.title="Bitcoin Finality Govener" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Bitcoin Finality Govener" \
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

USER bfgd:bfgd
WORKDIR /etc/bfgd/
ENTRYPOINT ["/usr/local/bin/bfgd"]
