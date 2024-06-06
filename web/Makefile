# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

PROJECTPATH = $(abspath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

GOROOT=$(shell go env GOROOT)
WEBAPP=$(PROJECTPATH)/webapp
WASM_BINARY=$(WEBAPP)/popminer.wasm

version = $(patsubst v%,%,$(shell git describe --tags 2>/dev/null || echo "v0.0.0"))
commit = $(shell git rev-parse --short HEAD)

.PHONY: all clean wasm www

all: wasm www

clean:
	rm -rf ${WEBAPP}
	rm -rf ${WASM_BINARY}

# TODO(joshuasing): research using binaryen (wasm-opt) to optimise output binary
wasm:
	CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -tags "$(BUILD_TAGS)" \
		-ldflags "-s -w -X main.version=${version} -X main.gitCommit=${commit}" \
		-o ${WASM_BINARY} ./popminer/...

www: wasm
	mkdir -p ${WEBAPP}
	cp www/index.html ${WEBAPP}
	cp www/index.js ${WEBAPP}
	cp www/popminer.js ${WEBAPP}
	cp www/wasm_exec.js ${WEBAPP}
