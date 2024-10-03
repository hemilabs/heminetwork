// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/hemi/electrs"
	"github.com/hemilabs/heminetwork/version"
)

func init() {
	version.Component = "extool"
}

func main() {
	ver := flag.Bool("v", false, "version")
	flag.Parse()
	if *ver {
		fmt.Printf("v%v\n", version.String())
		os.Exit(0)
	}

	address := flag.Arg(0)
	if address == "" {
		log.Fatal("No address specified")
	}

	c, err := electrs.NewClient(address, &electrs.ClientOptions{
		InitialConnections: 1,
		MaxConnections:     1,
	})
	if err != nil {
		log.Fatalf("Failed to create electrs client: %v", err)
	}

	ctx, ctxCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer ctxCancel()

	switch cmd := flag.Arg(1); cmd {
	case "balance":
		scriptHash, err := btcchainhash.NewHashFromStr(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid script hash %q: %v", flag.Arg(2), err)
		}
		balance, err := c.Balance(ctx, scriptHash[:])
		if err != nil {
			log.Fatalf("Failed to get balance: %v", err)
		}
		log.Printf("Balance for %v - confirmed %v, unconfirmed %v", scriptHash, balance.Confirmed, balance.Unconfirmed)

	case "broadcast":
		rtx, err := hex.DecodeString(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid transaction %q: %v", flag.Arg(2), err)
		}
		txid, err := c.Broadcast(ctx, rtx)
		if err != nil {
			log.Fatalf("Failed to broadcast transaction: %v", err)
		}
		log.Printf("Transaction broadcast with hash %x", txid)

	case "raw-block-header":
		height, err := strconv.Atoi(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid height %q: %v", flag.Arg(2), err)
		}
		rbh, err := c.RawBlockHeader(ctx, uint64(height))
		if err != nil {
			log.Fatalf("Failed to get raw block header: %v", err)
		}
		log.Printf("%x", rbh)

	case "raw-transaction":
		txHash, err := btcchainhash.NewHashFromStr(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid transaction hash %q: %v", flag.Arg(2), err)
		}
		rtx, err := c.RawTransaction(ctx, txHash[:])
		if err != nil {
			log.Fatalf("Failed to get raw transaction: %v", err)
		}
		log.Printf("%x", rtx)

	case "transaction":
		txHash, err := btcchainhash.NewHashFromStr(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid transaction hash %q: %v", flag.Arg(2), err)
		}
		txJSON, err := c.Transaction(ctx, txHash[:])
		if err != nil {
			log.Fatalf("Failed to get transaction: %v", err)
		}
		log.Printf("%v", string(txJSON))

	case "transaction-at-position":
		height, err := strconv.Atoi(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid height %q: %v", flag.Arg(2), err)
		}
		index, err := strconv.Atoi(flag.Arg(3))
		if err != nil {
			log.Fatalf("Invalid index %q: %v", flag.Arg(3), err)
		}
		txh, merkleHashes, err := c.TransactionAtPosition(ctx, uint64(height), uint64(index))
		if err != nil {
			log.Fatalf("Failed to get transaction at position: %v (%T)", err, err)
		}
		txHash, err := btcchainhash.NewHash(txh)
		if err != nil {
			log.Fatalf("Failed to create BTC hash from TX hash: %v", err)
		}
		log.Printf("TX hash at height %v, index %v: %v", height, index, txHash)
		log.Printf("Merkle hashes:")
		for _, merkleHash := range merkleHashes {
			log.Printf("%x", merkleHash)
		}

	case "utxos":
		scriptHash, err := btcchainhash.NewHashFromStr(flag.Arg(2))
		if err != nil {
			log.Fatalf("Invalid script hash %q: %v", flag.Arg(2), err)
		}
		utxos, err := c.UTXOs(ctx, scriptHash[:])
		if err != nil {
			log.Fatalf("Failed to get utxos: %v", err)
		}
		log.Printf("Got %d utxos for %v", len(utxos), scriptHash)
		for i, utxo := range utxos {
			utxoHash, err := btcchainhash.NewHash(utxo.Hash)
			if err != nil {
				log.Fatalf("Failed to create BTC hash from UTXO hash: %v", err)
			}
			log.Printf("UTXO %d - %v:%v %v", i, utxoHash, utxo.Index, utxo.Value)
		}

	default:
		log.Fatalf("Unknown command %q", cmd)
	}
}
