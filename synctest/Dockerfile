# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

FROM golang:1.26.3-alpine3.23@sha256:91eda9776261207ea25fd06b5b7fed8d397dd2c0a283e77f2ab6e91bfa71079d AS builder

WORKDIR /build/

COPY go.mod .
COPY go.sum .
RUN go mod download && go mod verify

COPY . .
RUN GOOS=$(go env GOOS) GOARCH=$(go env GOARCH) CGO_ENABLED=0 GOGC=off go build -trimpath -ldflags '-s -w' -o ./bin/synctest

FROM cgr.dev/chainguard/static@sha256:77d8b8925dc27970ec2f48243f44c7a260d52c49cd778288e4ee97566e0cb75b

COPY --from=builder /build/bin/synctest /usr/local/bin/synctest

WORKDIR /etc/synctest/
ENTRYPOINT ["/usr/local/bin/synctest"]
