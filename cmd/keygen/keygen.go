// Copyright (c) 2024-2025 Hemi Labs, Inc.
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
	"github.com/btcsuite/btcd/chaincfg"
	dcrsecpk256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/tyler-smith/go-bip39"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/v2/ethereum"
	"github.com/hemilabs/heminetwork/v2/version"
)

var (
	keyType = flag.String("key", "popminer", "generate key type")
	net     = flag.String("net", "mainnet", "Generate address of this type")
	welcome string
)

func usage() {
	fmt.Fprintf(os.Stderr, "%v\n", welcome)
	fmt.Fprintf(os.Stderr, "\t%v [-net=mainnet|testnet3|testnet4] <-key=popminer|secp256k1|hdwallet>\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	version.Component = "keygen"
	welcome = "Key Generator " + version.BuildInfo()
}

func _main() error {
	var btcChainParams *chaincfg.Params
	switch *net {
	case "testnet", "localnet":
		btcChainParams = &chaincfg.RegressionNetParams
	case "testnet3":
		btcChainParams = &chaincfg.TestNet3Params
	case "testnet4":
		btcChainParams = &chaincfg.TestNet4Params
	case "mainnet":
		btcChainParams = &chaincfg.MainNetParams
	default:
		return fmt.Errorf("invalid net: %v", *net)
	}

	switch *keyType {
	case "secp256k1":
		privKey, err := dcrsecpk256k1.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate secp256k1 private key: %w", err)
		}
		privBytes := privKey.Serialize()
		pubBytes := privKey.PubKey().SerializeCompressed()
		type Secp256k1 struct {
			PrivateKey string `json:"private_key"`
			PublicKey  string `json:"public_key"`
		}
		s := Secp256k1{
			PrivateKey: hex.EncodeToString(privBytes),
			PublicKey:  hex.EncodeToString(pubBytes),
		}
		js, err := json.MarshalIndent(s, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		fmt.Printf("%s\n", js)

	case "popminer":
		// Generate secp256k1 key and share it with ethereum.
		privKey, err := dcrsecpk256k1.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate secp256k1 private key: %w", err)
		}
		privBytes := privKey.Serialize()
		pubBytes := privKey.PubKey().SerializeCompressed()

		btcAddress, err := btcutil.NewAddressPubKey(pubBytes, btcChainParams)
		if err != nil {
			return fmt.Errorf("create btc address from public key: %w", err)
		}
		btcAddrHash := btcAddress.AddressPubKeyHash().String()
		ethAddress := ethereum.AddressFromPrivateKey(privKey)

		type PopMinerKey struct {
			Network         string `json:"network"`
			PrivateKey      string `json:"private_key"`
			PublicKey       string `json:"public_key"`
			BitcoinAddress  string `json:"bitcoin_address"`
			EthereumAddress string `json:"ethereum_address"`
		}
		p := PopMinerKey{
			Network:         *net,
			PrivateKey:      hex.EncodeToString(privBytes),
			PublicKey:       hex.EncodeToString(pubBytes),
			BitcoinAddress:  btcAddrHash,
			EthereumAddress: ethAddress.String(),
		}
		js, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		fmt.Printf("%s\n", js)

	case "hdwallet":
		entropy, err := bip39.NewEntropy(256)
		if err != nil {
			return fmt.Errorf("seed: %w", err)
		}
		mnemonic, err := bip39.NewMnemonic(entropy[:])
		if err != nil {
			return fmt.Errorf("mnemonic: %w", err)
		}
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
		if err != nil {
			return fmt.Errorf("new seed: %w", err)
		}
		vc, err := vinzclortho.New(btcChainParams)
		if err != nil {
			return err
		}
		err = vc.Unlock(hex.EncodeToString(seed))
		if err != nil {
			return err
		}
		type HDWalletKey struct {
			Network  string `json:"network"`
			Mnemonic string `json:"mnemonic"`
			RootKey  string `json:"root_key"`
			Seed     string `json:"seed"`
		}

		p := HDWalletKey{
			Network:  *net,
			Mnemonic: mnemonic,
			RootKey:  vc.RootKey(),
			Seed:     hex.EncodeToString(seed),
		}
		js, err := json.MarshalIndent(p, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal: %w", err)
		}
		fmt.Printf("%s\n", js)

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

	if err := _main(); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}
