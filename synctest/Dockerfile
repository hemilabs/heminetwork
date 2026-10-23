# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.27.3-alpine3.24@sha256:b8c9b82affbbb82a020bbcf998dad2ba9516944ac7e883524642a481a9505e9c AS builder

WORKDIR /build/

COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off go build -trimpath -ldflags '-s -w' -o ./bin/synctest

FROM cgr.dev/chainguard/static@sha256:60582b2ae6074f641094af0f370d4ab241aab271858a66223dcde7eee9f51638

COPY --from=builder /build/bin/synctest /usr/local/bin/synctest

WORKDIR /etc/synctest/
ENTRYPOINT ["/usr/local/bin/synctest"]
