# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM alpine:3.22.0@sha256:8a1f59ffb675680d47db6337b49d22281a139e9d709335b492be023728e11715 AS builder

# Add ca-certificates, timezone data
RUN apk --no-cache add --update ca-certificates tzdata

# Create non-root user
RUN addgroup --gid 65532 tbcd && \
    adduser --disabled-password --gecos "" \
        --home "/etc/tbcd/" --shell "/sbin/nologin" \
        -G tbcd --uid 65532 tbcd

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
      org.opencontainers.image.title="Tiny Bitcoin Daemon" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Tiny Bitcoin Daemon" \
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
COPY tbcd /usr/local/bin/tbcd

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

USER tbcd:tbcd
WORKDIR /etc/tbcd/
ENTRYPOINT ["/usr/local/bin/tbcd"]
