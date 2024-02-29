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
DIST=$(PROJECTPATH)/dist

ifeq ($(GOOS),windows)
BIN_EXT = .exe
endif

project = heminetwork
version = $(shell git describe --tags 2>/dev/null || echo "v0.0.0")

cmds = \
	bfgd \
	bssd \
	extool \
	keygen \
	popmd \
	hemictl

.PHONY: all clean clean-dist deps $(cmds) build install lint lint-deps tidy race test vulncheck \
	vulncheck-deps dist archive sources checksums networktest

all: lint tidy test build install

clean: clean-dist
	rm -rf $(GOBIN) $(GOCACHE) $(GOPKG)

clean-dist:
	rm -rf $(DIST)

deps: lint-deps vulncheck-deps
	go mod download
	go mod verify

$(cmds):
	go build -trimpath -o $(GOBIN)/$@$(BIN_EXT) ./cmd/$@

build:
	go build ./...

install: $(cmds)

lint:
	$(shell go env GOPATH)/bin/goimports -local github.com/hemilabs/heminetwork -w -l .
	$(shell go env GOPATH)/bin/gofumpt -w -l .
	go vet ./...

lint-deps:
	GOBIN=$(shell go env GOPATH)/bin go install golang.org/x/tools/cmd/goimports@latest
	GOBIN=$(shell go env GOPATH)/bin go install mvdan.cc/gofumpt@latest

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

dist:
	mkdir -p $(DIST)

archive: dist install
ifeq ($(GOOS),windows)
	cd $(GOBIN) && zip -r $(DIST)/$(project)_$(version)_$(GOOS)_$(GOARCH).zip *$(BIN_EXT)
else
	cd $(GOBIN) && tar -czvf $(DIST)/$(project)_$(version)_$(GOOS)_$(GOARCH).tar.gz *
endif

sources: dist
	tar --exclude=dist --exclude=bin -czvf $(DIST)/$(project)_$(version)_sources.tar.gz * .gitignore .github

checksums: dist
	cd $(DIST) && shasum -a 256 * > $(project)_$(version)_checksums.txt

networktest:
	HEMI_RUN_NETWORK_TEST=1	\
		go test -count=1 -v -run TestFullNetwork -v -timeout 25m ./e2e/network_test.go
