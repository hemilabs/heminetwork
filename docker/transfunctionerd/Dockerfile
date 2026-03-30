# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Build stage
FROM golang:1.26.1-alpine3.23@sha256:2389ebfa5b7f43eeafbd6be0c3700cc46690ef842ad962f6c5bd6be49ed82039 AS builder

ARG GO_LDFLAGS

# Add make and git
RUN apk --no-cache add --update make git

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make go-deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off make GO_LDFLAGS="$GO_LDFLAGS" transfunctionerd

# Run stage
FROM cgr.dev/chainguard/static@sha256:2fdfacc8d61164aa9e20909dceec7cc28b9feb66580e8e1a65b9f2443c53b61b
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
      org.opencontainers.image.title="Transfunctioner Daemon" \
      org.label-schema.build-date=$BUILD_DATE \
      org.label-schema.name="Transfunctioner Daemon" \
      org.label-schema.url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-url="https://github.com/hemilabs/heminetwork" \
      org.label-schema.vcs-ref=$VCS_REF \
      org.label-schema.vendor="Hemi Labs" \
      org.label-schema.version=$VERSION \
      org.label-schema.schema-version="1.0"

# Copy binary
COPY --from=builder /build/bin/transfunctionerd /usr/local/bin/transfunctionerd

# Environment variables
ENV TRF_CONNECT=""
ENV TRF_HOME=""
ENV TRF_LISTEN_ADDRESS=""
ENV TRF_LOG_LEVEL=""
ENV TRF_PEERS_WANTED=""
ENV TRF_PPROF_ADDRESS=""
ENV TRF_PREPARAMS_TIMEOUT=""
ENV TRF_PRIVATE_KEY=""
ENV TRF_PROMETHEUS_ADDRESS=""
ENV TRF_DNS=""
ENV TRF_HOSTNAME=""
ENV TRF_SEEDS=""

WORKDIR /etc/transfunctionerd/
ENTRYPOINT ["/usr/local/bin/transfunctionerd"]
