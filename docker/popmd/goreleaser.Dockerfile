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
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/popmd /usr/local/bin/popmd

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
