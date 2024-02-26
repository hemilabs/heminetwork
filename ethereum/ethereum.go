// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ethereum

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func PublicKeyToAddress(publicKey []byte) common.Address {
	hash := crypto.Keccak256(publicKey[1:])
	hash = hash[len(hash)-20:]
	return common.BytesToAddress(hash)
}

func AddressFromPrivateKey(privKey *secp256k1.PrivateKey) common.Address {
	return PublicKeyToAddress(privKey.PubKey().SerializeUncompressed())
}
