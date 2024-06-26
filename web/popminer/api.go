// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import "syscall/js"

// Method represents a method that can be dispatched.
type Method string

const (
	// The following can be dispatched at any time.
	MethodVersion       Method = "version"       // Retrieve WASM version information
	MethodGenerateKey   Method = "generateKey"   // Generate secp256k1 key pair
	MethodStartPoPMiner Method = "startPoPMiner" // Start PoP Miner
	MethodStopPoPMiner  Method = "stopPoPMiner"  // Stop PoP Miner

	// The following can only be dispatched after the PoP Miner is running.
	MethodPing           Method = "ping"           // Ping BFG
	MethodL2Keystones    Method = "l2Keystones"    // Retrieve L2 keystones
	MethodBitcoinBalance Method = "bitcoinBalance" // Retrieve bitcoin balance
	MethodBitcoinInfo    Method = "bitcoinInfo"    // Retrieve bitcoin information
	MethodBitcoinUTXOs   Method = "bitcoinUTXOs"   // Retrieve bitcoin UTXOs
)

// ErrorCode is used to differentiate between error types.
type ErrorCode uint32

const (
	// ErrorCodeInternal is used when the error is internal, either due to an
	// invalid dispatch or a panic.
	ErrorCodeInternal ErrorCode = 1000

	// ErrorCodeInvalidValue is used when an invalid value was provided for
	// a dispatch argument.
	ErrorCodeInvalidValue ErrorCode = 2000
)

// String returns a string value representing the error code.
func (e ErrorCode) String() string {
	switch e {
	case ErrorCodeInternal:
		return "internal error"
	case ErrorCodeInvalidValue:
		return "invalid value"
	default:
		return "unknown"
	}
}

func (e ErrorCode) JSValue() js.Value {
	return jsValueSafe(uint32(e))
}

// Error represents an error that has occurred within the WASM PoP Miner.
type Error struct {
	// Code is a unique identifier used to differentiate between error types.
	Code ErrorCode `json:"code"`

	// Message is the error message.
	Message string `json:"message"`

	// Stack is the Go debug stack (from debug.Stack()) for the error.
	Stack string `json:"stack"`

	// Timestamp is the time the error occurred, in unix seconds.
	Timestamp int64 `json:"timestamp"`
}

// VersionResult contains version information for the WASM PoP Miner.
// Returned by MethodVersion.
type VersionResult struct {
	// Version is the version of the WASM PoP Miner.
	Version string `json:"version"`

	// GitCommit is the SHA-1 hash of the Git commit the WASM binary was built
	// from. The value should be the same as the output from git rev-parse HEAD.
	GitCommit string `json:"gitCommit"`
}

// GenerateKeyResult contains the generated key information.
// Returned by MethodGenerateKey.
type GenerateKeyResult struct {
	// EthereumAddress is the Ethereum address for the generated key.
	EthereumAddress string `json:"ethereumAddress"`

	// Network is the network for which the key was generated.
	Network string `json:"network"`

	// PrivateKey is the generated secpk256k1 private key, encoded as a
	// hexadecimal string.
	PrivateKey string `json:"privateKey"`

	// PublicKey is the generated secp256k1 public key, in the 33-byte
	// compressed format, encoded as a hexadecimal string.
	PublicKey string `json:"publicKey"`

	// PublicKeyHash is the Bitcoin pay-to-pubkey-hash address for the generated
	// key.
	PublicKeyHash string `json:"publicKeyHash"`
}

// PingResult contains information when pinging the BFG server.
// Returned by MethodPing.
type PingResult struct {
	// OriginTimestamp is the time the PoP Miner sent the ping request to BFG,
	// in unix nanoseconds.
	OriginTimestamp int64 `json:"originTimestamp"`

	// Timestamp is the time the BFG server sent the ping response, in unix
	// nanoseconds.
	Timestamp int64 `json:"timestamp"`
}

// L2KeystoneResult contains the requested l2 keystones.
// Returned by MethodL2Keystones.
type L2KeystoneResult struct {
	// L2Keystones contains the requested keystones.
	L2Keystones []L2Keystone `json:"l2Keystones"`
}

// L2Keystone represents an L2 keystone.
type L2Keystone struct {
	// Version is the version of the L2 keystone.
	Version uint8 `json:"version"`

	// L1BlockNumber is the L1 block number for the keystone.
	L1BlockNumber uint32 `json:"l1BlockNumber"`

	// L2BlockNumber is the L2 block number for the keystone.
	L2BlockNumber uint32 `json:"l2BlockNumber"`

	// EPHash is the hash of the L2 block that contains the PoP payout.
	EPHash string `json:"epHash"`

	// ParentEPHash is the parent of the L2 block that contains the PoP payout.
	ParentEPHash string `json:"parentEPHash"`

	// PrevKeystoneEPHash is the hash of the L2 block that contains the previous
	// keystone PoP payout.
	PrevKeystoneEPHash string `json:"prevKeystoneEPHash"`

	// StateRoot is the Ethereum execution payload state root.
	StateRoot string `json:"stateRoot"`
}

// BitcoinBalanceResult contains the balances for the script hash.
// Returned by MethodBitcoinBalance.
type BitcoinBalanceResult struct {
	// Confirmed is the confirmed balance in satoshis.
	Confirmed uint64 `json:"confirmed"`

	// Unconfirmed is the unconfirmed balance in satoshis.
	Unconfirmed int64 `json:"unconfirmed"`
}

// BitcoinInfoResult contains Bitcoin-related information.
// Returned by MethodBitcoinInfo.
type BitcoinInfoResult struct {
	// Height is the current best known Bitcoin block height.
	Height uint64 `json:"height"`
}

// BitcoinUTXOsResult contains the UTXOs for the script hash.
// Returned by MethodBitcoinUTXOs.
type BitcoinUTXOsResult struct {
	// UTXOs contains the UTXOs for the script hash.
	UTXOs []BitcoinUTXO `json:"utxos"`
}

// BitcoinUTXO represents a Bitcoin UTXO.
type BitcoinUTXO struct {
	// Hash is the output's transaction hash, encoded as a hexadecimal string.
	Hash string `json:"hash"`

	// Index is the index of the output in the transaction's list of outputs.
	Index uint32 `json:"index"`

	// Value is the value of the output in satoshis.
	Value int64 `json:"value"`
}
