// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/version"
)

var (
	net              = flag.String("net", "mainnet", "Generate address of this type")
	secp256k1KeyPair = flag.Bool("secp256k1", false, "Generate a secp256k1 key pair")
	jsonFormat       = flag.Bool("json", false, "print output as JSON")

	welcome string
)

func usage() {
	fmt.Fprintf(os.Stderr, "%v\n", welcome)
	fmt.Fprintf(os.Stderr, "\t%v [-net mainnet|testnet3] [-json] <-secp256k1>\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	version.Component = "keygen"
	welcome = "Key Generator " + version.BuildInfo()
}

func _main() error {
	var btcChainParams *btcchaincfg.Params
	switch *net {
	case "testnet3", "testnet":
		btcChainParams = &btcchaincfg.TestNet3Params
	case "mainnet":
		btcChainParams = &btcchaincfg.MainNetParams
	default:
		return fmt.Errorf("invalid net: %v", *net)
	}

	switch {
	case *secp256k1KeyPair:
		privKey, err := dcrsecpk256k1.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate secp256k1 private key: %w", err)
		}
		btcAddress, err := btcutil.NewAddressPubKey(privKey.PubKey().SerializeCompressed(),
			btcChainParams)
		if err != nil {
			return fmt.Errorf("create BTC address from public key: %v",
				err)
		}
		hash := btcAddress.AddressPubKeyHash().String()
		ethAddress := ethereum.AddressFromPrivateKey(privKey)
		if *jsonFormat {
			type Secp256k1 struct {
				EthereumAddress string `json:"ethereum_address"`
				Network         string `json:"network"`
				PrivateKey      string `json:"private_key"`
				PublicKey       string `json:"public_key"`
				PubkeyHash      string `json:"pubkey_hash"`
			}
			s := &Secp256k1{
				EthereumAddress: ethAddress.String(),
				Network:         *net,
				PrivateKey:      hex.EncodeToString(privKey.Serialize()),
				PublicKey:       hex.EncodeToString(privKey.PubKey().SerializeCompressed()),
				PubkeyHash:      hash,
			}
			js, err := json.MarshalIndent(s, "", "  ")
			if err != nil {
				return fmt.Errorf("marshal: %w", err)
			}
			fmt.Printf("%s\n", js)
		} else {
			fmt.Printf("eth address: %v\n", ethAddress)
			fmt.Printf("network    : %v\n", *net)
			fmt.Printf("private key: %x\n", privKey.Serialize())
			fmt.Printf("public key : %x\n", privKey.PubKey().SerializeCompressed())
			fmt.Printf("pubkey hash:  %v\n", hash)

		}

	default:
		usage()
		return errors.New("invalid flag")
	}

	return nil
}

func main() {
	ver := flag.Bool("v", false, "version")
	flag.Parse()
	if *ver {
		fmt.Printf("v%v\n", version.String())
		os.Exit(0)
	}
	flag.Parse()

	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
