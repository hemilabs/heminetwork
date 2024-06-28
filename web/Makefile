# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

PROJECTPATH = $(abspath $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))

GOROOT=$(shell go env GOROOT)
WEBAPP=$(PROJECTPATH)/webapp
WWW_DIR=$(PROJECTPATH)/www
POP_MINER_PACKAGE_DIR=$(PROJECTPATH)/packages/pop-miner
WASM_BINARY=$(POP_MINER_PACKAGE_DIR)/wasm/popminer.wasm

version = $(patsubst v%,%,$(shell git describe --tags 2>/dev/null || echo "v0.0.0"))
commit = $(shell git rev-parse --short HEAD)

.PHONY: all clean deps wasm wasm-opt www

all: wasm www

clean:
	rm -rf ${WEBAPP}
	rm -rf ${WASM_BINARY}

deps:
	go mod download
	go mod verify

wasm:
	CGO_ENABLED=0 GOOS=js GOARCH=wasm go build -trimpath -tags "$(BUILD_TAGS)" \
		-ldflags "-s -w -X main.version=${version} -X main.gitCommit=${commit}" \
		-o ${WASM_BINARY} ${PROJECTPATH}/popminer/...

wasm-opt:
	@which wasm-opt || {\
		echo "wasm-opt: wasm-opt must be installed to use this target";\
		echo "wasm-opt: https://github.com/WebAssembly/binaryen";\
		exit 1; }
	wasm-opt -Oz ${WASM_BINARY} -o ${WASM_BINARY}.opt --enable-bulk-memory --intrinsic-lowering
	mv ${WASM_BINARY}.opt ${WASM_BINARY}

www: wasm
	mkdir -p ${WEBAPP}
	cp ${WASM_BINARY} ${WEBAPP}
	cp ${WWW_DIR}/index.html ${WEBAPP}
	cp ${WWW_DIR}/index.js ${WEBAPP}
	cp ${WWW_DIR}/popminer.js ${WEBAPP}
	cp ${WWW_DIR}/wasm_exec.js ${WEBAPP}
