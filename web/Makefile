# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

GOROOT=$(shell go env GOROOT)
GITVERSION=$(shell git rev-parse --short HEAD)
WEBAPP=webapp

.PHONY: all clean prepare wasm www

all: wasm www

clean:
	rm -rf ${WEBAPP}

prepare:
	mkdir -p ${WEBAPP}

wasm: prepare
	GOOS=js GOARCH=wasm go build -trimpath -ldflags "-X main.gitVersion=${GITVERSION}" \
		-o ${WEBAPP}/popminer.wasm ./popminer/popminer.go

www: prepare
	cp www/index.html ${WEBAPP}
	cp www/index.js ${WEBAPP}
	cp www/popminer.js ${WEBAPP}
	cp ${GOROOT}/misc/wasm/wasm_exec.js ${WEBAPP}/wasm_exec.js
