# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# The stand-in for an L1 consensus layer node used by the e2e localnet, see
# main.go.  This image is test infrastructure, it is not released.

# Build stage
# The steps up to "make go-deps" match the Dockerfiles of the daemons so that
# their cached layers are shared when the localnet is built.
FROM golang:1.26.5-alpine3.23@sha256:622e56dbc11a8cfe87cafa2331e9a201877271cbff918af53d3be315f3da88cc AS builder

# Add make and git
RUN apk --no-cache add --update make git

WORKDIR /build/

COPY Makefile .
COPY go.mod .
COPY go.sum .
RUN make go-deps

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off \
	go build -trimpath -o /build/bin/fakebeacon ./e2e/fakebeacon

# Run stage
FROM cgr.dev/chainguard/static@sha256:60582b2ae6074f641094af0f370d4ab241aab271858a66223dcde7eee9f51638

COPY --from=builder /build/bin/fakebeacon /usr/local/bin/fakebeacon

# Environment variables
ENV FAKEBEACON_L1_RPC_URL=""
ENV FAKEBEACON_BEACON_ADDRESS=""
ENV FAKEBEACON_RPC_ADDRESS=""

ENTRYPOINT ["/usr/local/bin/fakebeacon"]
