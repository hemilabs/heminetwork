package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

func _main() error {
	pk, err := hex.DecodeString(os.Args[1])
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "no key provided!")
		os.Exit(1)
	}

	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
