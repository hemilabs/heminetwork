// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/hemilabs/heminetwork/ethereum"
)

func privKey() error {
	privKey, err := dcrsecpk256k1.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate secp256k1 private key: %w", err)
	}
	privBytes := privKey.Serialize()
	fmt.Println(hex.EncodeToString(privBytes))
	return nil
}

func btcAddress() error {
	if len(os.Args) < 3 {
		return errors.New("missing private key")
	}

	pk, err := hex.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	privKey := dcrsecpk256k1.PrivKeyFromBytes(pk)
	pubBytes := privKey.PubKey().SerializeCompressed()

	btcAddress, err := btcutil.NewAddressPubKey(pubBytes, &chaincfg.RegressionNetParams)
	if err != nil {
		return fmt.Errorf("new address: %w", err)
	}
	btcAddrHash := btcAddress.AddressPubKeyHash().String()

	fmt.Println(btcAddrHash)
	return nil
}

func ethAddress() error {
	if len(os.Args) < 3 {
		return errors.New("missing private key")
	}

	pk, err := hex.DecodeString(os.Args[2])
	if err != nil {
		return err
	}
	privKey := dcrsecpk256k1.PrivKeyFromBytes(pk)
	ethAddress := ethereum.AddressFromPrivateKey(privKey).String()[2:]

	fmt.Println(ethAddress)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "missing subcommand\n")
		os.Exit(1)
	}

	var err error
	switch os.Args[1] {
	case "privkey":
		err = privKey()
	case "btc":
		err = btcAddress()
	case "eth":
		err = ethAddress()
	default:
		err = fmt.Errorf("unknown subcommand: %v", os.Args[1])
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
