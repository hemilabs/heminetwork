// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package ethereum

import (
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"errors"
	"fmt"
)

var (
	ErrInvalidPrivateKey = errors.New("недопустимый закрытый ключ")
	ErrInvalidPublicKey  = errors.New("недопустимый открытый ключ")
	ErrInvalidSignature  = errors.New("недопустимая подпись")
	ErrInvalidAddress    = errors.New("недопустимый адрес Ethereum")
)

func PublicKeyToAddress(publicKey []byte) common.Address {
	hash := crypto.Keccak256(publicKey[1:])
	hash = hash[len(hash)-20:]
	return common.BytesToAddress(hash)
}

func AddressFromPrivateKey(privKey *secp256k1.PrivateKey) common.Address {
	return PublicKeyToAddress(privKey.PubKey().SerializeUncompressed())
}

func GenerateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать ключ: %w", err)
	}
	
	return privateKey, nil
}

func PublicKeyToAddress(pub *ecdsa.PublicKey) (common.Address, error) {
	if pub == nil {
		return common.Address{}, ErrInvalidPublicKey
	}
	
	address := crypto.PubkeyToAddress(*pub)
	return address, nil
}

func VerifySignature(pubKey *ecdsa.PublicKey, message, signature []byte) error {
	if pubKey == nil {
		return ErrInvalidPublicKey
	}
	
	if len(signature) != 65 {
		return ErrInvalidSignature
	}
	
	// Checking the signature
	signatureNoRecoverID := signature[:len(signature)-1]
	valid := crypto.VerifySignature(
		crypto.FromECDSAPub(pubKey),
		message,
		signatureNoRecoverID,
	)
	
	if !valid {
		return ErrInvalidSignature
	}
	
	return nil
}

func ValidateAddress(address common.Address) error {
	if address == common.Address{} {
		return ErrInvalidAddress
	}
	return nil
}
