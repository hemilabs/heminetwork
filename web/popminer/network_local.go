// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm && hemi_localnet

package main

// To include the "local" network option in the WASM binary, run `go build`
// with `-tags "hemi_localnet"` to include this file.

const rpcLocal = "ws://localhost:8383"

func init() {
	networks["local"] = networkOptions{
		bfgURL:       rpcLocal + bfgRoute,
		btcChainName: btcChainTestnet3,
	}
}
