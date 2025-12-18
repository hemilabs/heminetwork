# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

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
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/tbcd /usr/local/bin/tbcd

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
