// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

const (
	btcChainTestnet3 = "testnet3"
	btcChainMainnet  = "mainnet"

	rpcHemiTestnet = "wss://testnet.rpc.hemi.network"
	rpcHemiDevnet  = "wss://devnet.rpc.hemi.network"
	rpcHemiMainnet = "wss://rpc.hemi.network"

	bfgRoute = "/v1/ws/public"
)

type networkOptions struct {
	bfgURL       string
	btcChainName string
}

var networks = map[string]networkOptions{
	"testnet": {
		bfgURL:       rpcHemiTestnet + bfgRoute,
		btcChainName: btcChainTestnet3,
	},
	"devnet": {
		bfgURL:       rpcHemiDevnet + bfgRoute,
		btcChainName: btcChainTestnet3,
	},
	"mainnet": {
		bfgURL:       rpcHemiMainnet + bfgRoute,
		btcChainName: btcChainMainnet,
	},
}
