# Copyright (c) 2024-2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# PROJECTPATH is the project root directory.
# This Makefile is stored in the project root directory, so the directory is
# retrieved by getting the directory of this Makefile.
PROJECTPATH := $(abspath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

GO_LDFLAGS ?=

# Debug build tags.  Enable ceremony initiation commands in hemictl:
#   CONTINUUM_DEBUG=1 make
GO_TAGS =
ifdef CONTINUUM_DEBUG
GO_TAGS += continuum_debug
endif
ifneq ($(GO_TAGS),)
GO_TAGS_FLAG = -tags "$(strip $(GO_TAGS))"
LINT_TAGS_FLAG = --build-tags "$(strip $(GO_TAGS))"
endif
export GOCACHE ?= $(PROJECTPATH)/.gocache
export GOBIN ?= $(shell go env GOPATH)/bin
PROJECT_BIN := $(PROJECTPATH)/bin

# renovate: datasource=github-releases depName=golangci/golangci-lint versioning=semver
GOLANGCI_LINT_VERSION := v2.12.2
# renovate: datasource=github-releases depName=joshuasing/golicenser versioning=semver
GOLICENSER_VERSION := v0.3.1
# renovate: datasource=github-releases depName=mvdan/gofumpt versioning=semver
GOFUMPT_VERSION := v0.10.0
# renovate: datasource=go depName=golang.org/x/vuln versioning=semver
GOVULNCHECK_VERSION := v1.3.0

cmds := \
	bfgd \
	btctool \
	hemictl \
	hproxyd \
	keygen \
	popmd \
	tbcd \
	transfunctionerd

.PHONY: all
all: tidy build lint test install

.PHONY: clean
clean: clean-test
	go clean -cache
	rm -rf $(PROJECT_BIN)

# TODO: This should not be necessary, all test files should be in a tempdir.
.PHONY: clean-test
clean-test:
	rm -rf $(PROJECTPATH)/service/tbc/.testleveldb/

.PHONY: deps
deps: lint-deps vulncheck-deps go-deps

.PHONY: go-deps
go-deps:
	go mod download
	go mod verify

.PHONY: tidy
tidy:
	go mod tidy

.PHONY: build
build:
	go build -trimpath $(GO_TAGS_FLAG) -ldflags "$(GO_LDFLAGS)" ./...

.PHONY: install
install: $(cmds)

.PHONY: $(cmds)
$(cmds):
	go build -trimpath $(GO_TAGS_FLAG) -ldflags "$(GO_LDFLAGS)" -o $(PROJECT_BIN)/$@ ./cmd/$@

.PHONY: test
test:
	go test $(GO_TAGS_FLAG) -timeout=20m -coverprofile=$(PROJECTPATH)/coverage.out \
		-covermode=atomic -ldflags "$(GO_LDFLAGS)" ./...

.PHONY: race
race:
	go test $(GO_TAGS_FLAG) -race -timeout=20m -coverprofile=$(PROJECTPATH)/coverage.out \
		-covermode=atomic -ldflags "$(GO_LDFLAGS)" ./...

.PHONY: cover
cover: test
	go tool cover -html=$(PROJECTPATH)/coverage.out

.PHONY: synctest
synctest:
	go -C $(PROJECTPATH)/synctest test -v -timeout=1m ./...

define LICENSE_HEADER
Copyright (c) {{.year}} {{.author}}
Use of this source code is governed by the MIT License,
which can be found in the LICENSE file.
endef
export LICENSE_HEADER
LICENSE_AUTHOR := Hemi Labs, Inc.

.PHONY: fmt
fmt:
	$(GOBIN)/golangci-lint fmt ./...
	$(GOBIN)/golicenser -tmpl="$$LICENSE_HEADER" -author="$(LICENSE_AUTHOR)" -year-mode=git-range -fix ./...

.PHONY: lint
lint: fmt
	$(GOBIN)/golangci-lint run $(LINT_TAGS_FLAG) --fix ./...

.PHONY: lint-check
lint-check:
	$(GOBIN)/golangci-lint fmt --diff ./...
	$(GOBIN)/golangci-lint run $(LINT_TAGS_FLAG) ./...
	$(GOBIN)/golicenser -tmpl="$$LICENSE_HEADER" -author="$(LICENSE_AUTHOR)" -year-mode=git-range ./...

.PHONY: lint-deps
lint-deps:
	@echo "Installing with $(shell go version)"
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)
	go install github.com/joshuasing/golicenser/cmd/golicenser@$(GOLICENSER_VERSION)
	go install mvdan.cc/gofumpt@$(GOFUMPT_VERSION)

.PHONY: vulncheck
vulncheck:
	$(GOBIN)/govulncheck $(GO_TAGS_FLAG) ./...

.PHONY: vulncheck-deps
vulncheck-deps:
	go install golang.org/x/vuln/cmd/govulncheck@$(GOVULNCHECK_VERSION)
