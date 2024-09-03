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
	bssd	\
	extool	\
	hemictl	\
	keygen	\
	popmd	\
	tbcd

.PHONY: all clean deps go-deps $(cmds) build install lint lint-deps tidy race test vulncheck \
	vulncheck-deps

all: lint tidy test build install

clean: clean-test
	rm -rf $(GOBIN) $(GOCACHE) $(GOPKG)

clean-test:
	rm -rf $(PROJECTPATH)/service/tbc/.testleveldb/

deps: lint-deps vulncheck-deps go-deps

go-deps:
	go mod download
	go mod verify

$(cmds):
	go build -trimpath -ldflags "$(GO_LDFLAGS)" -o $(GOBIN)/$@ ./cmd/$@

build:
	go build ./...

install: $(cmds)

lint:
	$(shell go env GOPATH)/bin/goimports -local github.com/hemilabs/heminetwork -w -l .
	$(shell go env GOPATH)/bin/gofumpt -w -l .
	$(shell go env GOPATH)/bin/addlicense -c "Hemi Labs, Inc." -f $(PROJECTPATH)/license_header.txt \
		-ignore "{.idea,.vscode}/**" -ignore ".github/release.yml" -ignore ".github/ISSUE_TEMPLATE/**" \
		-ignore "**/pnpm-{lock,workspace}.yaml" -ignore "**/node_modules/**" .
	go vet ./...

lint-deps:
	GOBIN=$(shell go env GOPATH)/bin go install golang.org/x/tools/cmd/goimports@latest
	GOBIN=$(shell go env GOPATH)/bin go install mvdan.cc/gofumpt@latest
	GOBIN=$(shell go env GOPATH)/bin go install github.com/google/addlicense@latest

staticcheck:
	$(shell go env GOPATH)/bin/staticcheck ./...

staticcheck-deps:
	GOBIN=$(shell go env GOPATH)/bin go install honnef.co/go/tools/cmd/staticcheck@latest

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
