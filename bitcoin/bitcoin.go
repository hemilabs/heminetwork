// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bitcoin

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

type BlockHeader [80]byte

func (bh *BlockHeader) String() string {
	return hex.EncodeToString(bh[:])
}

func RawBlockHeaderFromSlice(s []byte) (*BlockHeader, error) {
	if len(s) != 80 {
		return nil, errors.New("invalid blockheader size")
	}
	var bh BlockHeader
	copy(bh[:], s)
	return &bh, nil
}

var ErrInvalidMerkle = errors.New("invalid merkle")

func MerkleRootFromBlockHeader(bh *BlockHeader) []byte {
	return bh[36:68]
}

// ValidateMerkleRoot accepts encoded hashes of the hashes in question,
// i.e. the tx hash, merkle proof steps, and merkle root.
// and the index of the transaction.  returns nil if the merkle proof is valid
func ValidateMerkleRoot(txHashEncoded string, merkleProofEncoded []string, txIndex uint32, merkleRootEncoded string) error {
	txHash, err := hex.DecodeString(txHashEncoded)
	if err != nil {
		return err
	}

	merkleProof := [][]byte{}
	for _, v := range merkleProofEncoded {
		decoded, err := hex.DecodeString(v)
		if err != nil {
			return err
		}

		// these are stored in reverse-byte order, reverse each
		slices.Reverse(decoded)
		merkleProof = append(merkleProof, decoded)
	}

	merkleRoot, err := hex.DecodeString(merkleRootEncoded)
	if err != nil {
		return err
	}

	if err := CheckMerkleChain(txHash, txIndex, merkleProof, merkleRoot); err != nil {
		return errors.Join(ErrInvalidMerkle, err)
	}

	return nil
}

func CheckMerkleChain(leaf []byte, index uint32, merkleHashes [][]byte, merkleRoot []byte) error {
	if len(leaf) != chainhash.HashSize {
		return fmt.Errorf("invalid leaf hash length (%d != %d)", len(leaf), chainhash.HashSize)
	}

	b := append([]byte{}, leaf...)
	for _, merkleHash := range merkleHashes {
		if len(merkleHash) != chainhash.HashSize {
			return fmt.Errorf("invalid merkle hash length (%d != %d)", len(merkleHash), chainhash.HashSize)
		}
		if index%2 == 0 {
			// Right.
			b = chainhash.DoubleHashB(append(b, merkleHash...))
		} else {
			// Left.
			b = chainhash.DoubleHashB(append(merkleHash, b...))
		}
		index /= 2
	}

	if len(merkleRoot) != chainhash.HashSize {
		return fmt.Errorf("invalid merkle root length (%d != %d)", len(merkleRoot), chainhash.HashSize)
	}
	if !bytes.Equal(merkleRoot, b) {
		return fmt.Errorf("merkle root mismatch (%x != %x)", merkleRoot, b)
	}
	return nil
}

func SignTx(btx *wire.MsgTx, payToScript []byte, privateKey *dcrsecp256k1.PrivateKey, publicKey *dcrsecp256k1.PublicKey) error {
	if btx == nil {
		return errors.New("btx cannot be nil")
	}

	if !slices.Equal(privateKey.PubKey().SerializeUncompressed(),
		publicKey.SerializeUncompressed()) {
		return errors.New("wrong public key for private key")
	}

	sigHash, err := txscript.CalcSignatureHash(payToScript,
		txscript.SigHashAll, btx, 0,
	)
	if err != nil {
		return fmt.Errorf("calculate signature hash: %w", err)
	}
	pubKeyBytes := publicKey.SerializeCompressed()
	sig := dcrecdsa.Sign(privateKey, sigHash)
	sigBytes := append(sig.Serialize(), byte(txscript.SigHashAll))
	sb := txscript.NewScriptBuilder().AddData(sigBytes).AddData(pubKeyBytes)
	if btx.TxIn[0].SignatureScript, err = sb.Script(); err != nil {
		return fmt.Errorf("build signature script: %w", err)
	}
	return nil
}

func PrivKeyFromHexString(s string) (*dcrsecp256k1.PrivateKey, error) {
	var privKeyBytes [32]byte
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	if len(b) != len(privKeyBytes) {
		return nil, fmt.Errorf("incorrect length (%d != %d)", len(b), len(privKeyBytes))
	}
	copy(privKeyBytes[:], b)
	privKey := new(dcrsecp256k1.PrivateKey)
	overflow := privKey.Key.SetBytes(&privKeyBytes)
	if privKey.Key.IsZeroBit() != 0 || overflow != 0 {
		return nil, errors.New("out of range")
	}
	return privKey, nil
}

func KeysAndAddressFromHexString(s string, chainParams *chaincfg.Params) (*dcrsecp256k1.PrivateKey, *dcrsecp256k1.PublicKey, *btcutil.AddressPubKeyHash, error) {
	privKey, err := PrivKeyFromHexString(s)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("invalid BTC private key: %w", err)
	}

	pubKeyBytes := privKey.PubKey().SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubKeyBytes, chainParams)
	if err != nil {
		return nil, nil, nil,
			fmt.Errorf("create BTC address from public key: %w", err)
	}

	return privKey, privKey.PubKey(), btcAddress.AddressPubKeyHash(), nil
}
