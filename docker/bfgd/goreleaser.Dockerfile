# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

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
ARG TARGETPLATFORM
COPY $TARGETPLATFORM/bfgd /usr/local/bin/bfgd

# Environment variables
ENV BFG_EXBTC_ADDRESS=""
ENV BFG_PUBLIC_KEY_AUTH=""
ENV BFG_BTC_START_HEIGHT=""
ENV BFG_LOG_LEVEL=""
ENV BFG_POSTGRES_URI=""
ENV BFG_PUBLIC_ADDRESS=""
ENV BFG_PRIVATE_ADDRESS=""
ENV BFG_PROMETHEUS_ADDRESS=""
ENV BFG_PPROF_ADDRESS=""
ENV BFG_TRUSTED_PROXIES=""
ENV BFG_REMOTE_IP_HEADERS=""

WORKDIR /etc/bfgd/
ENTRYPOINT ["/usr/local/bin/bfgd"]
