// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build js && wasm

package main

import (
	"fmt"
	"strings"
	"syscall/js"

	"github.com/hemilabs/heminetwork/service/popm"
)

// Method represents a method that can be dispatched.
type Method string

const (
	// The following can be dispatched at any time.
	MethodVersion                    Method = "version"                    // Retrieve WASM version information
	MethodGenerateKey                Method = "generateKey"                // Generate secp256k1 key pair
	MethodParseKey                   Method = "parseKey"                   // Parses a secp256k1 private and returns key information
	MethodBitcoinAddressToScriptHash Method = "bitcoinAddressToScriptHash" // Bitcoin address to script hash
	MethodStartPoPMiner              Method = "startPoPMiner"              // Start PoP Miner
	MethodStopPoPMiner               Method = "stopPoPMiner"               // Stop PoP Miner
	MethodMinerStatus                Method = "minerStatus"                // PoP Miner status

	// The following can only be dispatched after the PoP Miner is running.
	MethodPing           Method = "ping"           // Ping BFG
	MethodL2Keystones    Method = "l2Keystones"    // Retrieve L2 keystones
	MethodBitcoinBalance Method = "bitcoinBalance" // Retrieve bitcoin balance
	MethodBitcoinInfo    Method = "bitcoinInfo"    // Retrieve bitcoin information
	MethodBitcoinUTXOs   Method = "bitcoinUTXOs"   // Retrieve bitcoin UTXOs

	// Events
	MethodEventListenerAdd    Method = "addEventListener"    // Register event listener
	MethodEventListenerRemove Method = "removeEventListener" // Unregister event listener
)

// ErrorCode is used to differentiate between error types.
type ErrorCode uint32

var _ JSMarshaler = (*ErrorCode)(nil)

const (
	// errorCodeInvalid is the zero value of ErrorCode.
	// This should not be used for anything.
	errorCodeInvalid ErrorCode = 0

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
	case errorCodeInvalid:
		return "invalid error code"
	case ErrorCodeInternal:
		return "internal error"
	case ErrorCodeInvalidValue:
		return "invalid value"
	default:
		return "unknown"
	}
}

// MarshalJS returns a js.Value representing the error code.
func (e ErrorCode) MarshalJS() (js.Value, error) {
	return jsValueOf(uint32(e)), nil
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

// KeyResult contains a secp256k1 key pair and its corresponding Bitcoin
// address and public key hash, and Ethereum address.
//
// Returned by MethodGenerateKey and MethodParseKey.
type KeyResult struct {
	// HemiAddress is the Hemi Ethereum address for the key.
	HemiAddress string `json:"hemiAddress"`

	// Network is the network the addresses were created for.
	Network string `json:"network"`

	// PrivateKey is the secp256k1 private key, encoded as a hexadecimal string.
	PrivateKey string `json:"privateKey"`

	// PublicKey is the secp256k1 public key, in the 33-byte compressed format,
	// encoded as a hexadecimal string.
	PublicKey string `json:"publicKey"`

	// BitcoinPubKeyHash is the Bitcoin pay-to-pubkey-hash address for the key.
	BitcoinPubKeyHash string `json:"bitcoinPubKeyHash"`

	// BitcoinScriptHash is the Bitcoin pay-to-pubkey-hash script hash for the
	// key.
	BitcoinScriptHash string `json:"bitcoinScriptHash"`
}

// BitcoinAddressToScriptHashResult contains the script hash requested for an
// address.
type BitcoinAddressToScriptHashResult struct {
	// Network is the network the address is for.
	Network string `json:"network"`

	// Address is the address the script hash is for.
	Address string `json:"address"`

	// ScriptHash is the script hash for the given address.
	ScriptHash string `json:"scriptHash"`
}

// RecommendedFeeType is the type of recommended fee to use when doing automatic
// fees using the mempool.space REST API.
type RecommendedFeeType string

const (
	RecommendedFeeTypeFastest  RecommendedFeeType = "fastest"
	RecommendedFeeTypeHalfHour RecommendedFeeType = "halfHour"
	RecommendedFeeTypeHour     RecommendedFeeType = "hour"
	RecommendedFeeTypeEconomy  RecommendedFeeType = "economy"
	RecommendedFeeTypeMinimum  RecommendedFeeType = "minimum"
)

// ParseRecommendedFeeType parses the given string as a RecommendedFeeType.
func ParseRecommendedFeeType(s string) (RecommendedFeeType, error) {
	switch strings.ToLower(s) {
	case "fastest":
		return RecommendedFeeTypeFastest, nil
	case "halfHour":
		return RecommendedFeeTypeHalfHour, nil
	case "hour":
		return RecommendedFeeTypeHour, nil
	case "economy":
		return RecommendedFeeTypeEconomy, nil
	case "minimum":
		return RecommendedFeeTypeMinimum, nil
	default:
		return "", fmt.Errorf("unknown recommended fee type: %q", s)
	}
}

// MinerStatusResult contains information about the status of the PoP miner.
// Returned by MethodMinerStatus.
type MinerStatusResult struct {
	// Running is whether the PoP miner is running.
	Running bool `json:"running"`

	// Connecting is whether the PoP miner is currently connected to a BFG
	// server.
	Connected bool `json:"connected"`

	// Fee is the current fee used by the PoP miner for PoP transactions,
	// in sats/vB.
	Fee uint `json:"fee"`
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

// EventType represents a type of event.
type EventType string

const (
	// EventTypeMinerStart is dispatched when the PoP miner has started.
	EventTypeMinerStart EventType = "minerStart"

	// EventTypeMinerStop is dispatched when the PoP miner has exited.
	EventTypeMinerStop EventType = "minerStop"

	// EventTypeMineKeystone is dispatched when the PoP miner is mining an L2
	// keystone.
	EventTypeMineKeystone EventType = "mineKeystone"

	// EventTypeTransactionBroadcast is dispatched when the PoP miner has
	// broadcast a Bitcoin transaction to the network.
	EventTypeTransactionBroadcast EventType = "transactionBroadcast"
)

// popmEvents contains events dispatched by the native PoP Miner.
// These events will be forwarded to JavaScript, however we also dispatch events
// that are specific to the WebAssembly PoP Miner.
var popmEvents = map[popm.EventType]EventType{
	popm.EventTypeMineKeystone:         EventTypeMineKeystone,
	popm.EventTypeTransactionBroadcast: EventTypeTransactionBroadcast,
}

// eventTypes is a map used to parse string event types.
var eventTypes = map[string]EventType{
	"*":                                    "*", // Listen for all events.
	EventTypeMinerStart.String():           EventTypeMinerStart,
	EventTypeMinerStop.String():            EventTypeMinerStop,
	EventTypeMineKeystone.String():         EventTypeMineKeystone,
	EventTypeTransactionBroadcast.String(): EventTypeTransactionBroadcast,
}

// String returns the string representation of the event type.
func (e EventType) String() string {
	return string(e)
}

// MarshalJS returns the JavaScript representation of the event type.
func (e EventType) MarshalJS() (js.Value, error) {
	return jsValueOf(e.String()), nil
}

// EventMinerStop is the data for EventTypeMinerStop.
type EventMinerStop struct {
	Error *Error `json:"error"`
}

// EventMineKeystone is the data for EventTypeMineKeystone.
type EventMineKeystone struct {
	Keystone L2Keystone `json:"keystone"`
}

// EventTransactionBroadcast is the data for EventTypeTransactionBroadcast.
type EventTransactionBroadcast struct {
	Keystone L2Keystone `json:"keystone"`
	TxHash   string     `json:"txHash"`
}
