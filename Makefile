# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# PROJECTPATH is the project root directory.
# This Makefile is stored in the project root directory, so the directory is
# retrieved by getting the directory of this Makefile.
PROJECTPATH = $(abspath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

export GOBIN=$(PROJECTPATH)/bin
export GOCACHE=$(PROJECTPATH)/.gocache
export GOPKG=$(PROJECTPATH)/pkg

GO_LDFLAGS=
DIST=$(PROJECTPATH)/dist

project = heminetwork
version = $(shell git describe --tags 2>/dev/null || echo "v0.0.0")

cmds = \
	bfgd	\
	hemictl	\
	hproxyd	\
	keygen	\
	popmd	\
	tbcd

.PHONY: all clean deps go-deps $(cmds) build install lint lint-deps tidy race test vulncheck \
	vulncheck-deps

all: tidy build lint test install

clean: clean-test
	rm -rf $(GOBIN) $(GOCACHE) $(GOPKG)

clean-test:
	rm -rf $(PROJECTPATH)/service/tbc/.testleveldb/

deps: lint-deps vulncheck-deps go-deps

go-deps:
	go mod download
	go mod tidy
	go mod verify

$(cmds):
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(GOBIN)/$@ ./cmd/$@

build:
	go build ./...

install: $(cmds)

define LICENSE_HEADER
Copyright (c) {{.year}} {{.author}}
Use of this source code is governed by the MIT License,
which can be found in the LICENSE file.
endef
export LICENSE_HEADER

lint:
	$(shell go env GOPATH)/bin/golangci-lint fmt ./...
	$(shell go env GOPATH)/bin/golangci-lint run --fix ./...
	$(shell go env GOPATH)/bin/golicenser -tmpl="$$LICENSE_HEADER" -author="Hemi Labs, Inc." -year-mode=git-range -fix ./...

lint-deps:
	GOBIN=$(shell go env GOPATH)/bin go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1
	GOBIN=$(shell go env GOPATH)/bin go install github.com/joshuasing/golicenser/cmd/golicenser@v0.3
	GOBIN=$(shell go env GOPATH)/bin go install mvdan.cc/gofumpt@v0.8.0

tidy:
	go mod tidy

race:
	go test -v -race ./...

test:
	go test -test.timeout=20m ./...

vulncheck:
	$(shell go env GOPATH)/bin/govulncheck ./...

vulncheck-deps:
	GOBIN=$(shell go env GOPATH)/bin go install golang.org/x/vuln/cmd/govulncheck@latest
