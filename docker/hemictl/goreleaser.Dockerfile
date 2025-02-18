# Copyright (c) 2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM alpine:3.20.2@sha256:0a4eaa0eecf5f8c050e5bba433f58c052be7587ee8af3e8b3910ef9ab5fbe9f5 AS builder

# Add ca-certificates, timezone data
RUN apk --no-cache add --update ca-certificates tzdata

# Create non-root user
RUN addgroup --gid 65532 hemictl && \
    adduser --disabled-password --gecos "" \
        --home "/etc/hemictl/" --shell "/sbin/nologin" \
        -G hemictl --uid 65532 hemictl

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
      org.opencontainers.image.title="Hemictl" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Hemictl" \
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
COPY hemictl /usr/local/bin/hemictl

# Environment variables
ENV HEMICTL_BSS_URL=""
ENV HEMICTL_LOG_LEVEL=""

USER hemictl:hemictl
WORKDIR /etc/hemictl/
ENTRYPOINT ["/usr/local/bin/hemictl"]
