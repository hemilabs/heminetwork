// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"bytes"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btctxscript "github.com/btcsuite/btcd/txscript"
	btcwire "github.com/btcsuite/btcd/wire"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"

	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/pop"
)

// CreateBtcTx creates a Bitcoin transaction for testing purposes.
// Parameters:
//   - t: testing context
//   - btcHeight: Bitcoin block height to use in the transaction
//   - l2Keystone: L2 keystone to include in the transaction
//   - minerPrivateKeyBytes: private key bytes for the miner
//
// Returns the serialized transaction as a byte slice.
func CreateBtcTx(t *testing.T, btcHeight uint64, l2Keystone *hemi.L2Keystone, minerPrivateKeyBytes []byte) []byte {
	btx := &btcwire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(*l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := dcrsecp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)
	publicKey := privateKey.PubKey()
	pubKeyBytes := publicKey.SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubKeyBytes, &btcchaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	payToScript, err := btctxscript.PayToAddrScript(btcAddress.AddressPubKeyHash())
	if err != nil {
		t.Fatal(err)
	}

	if len(payToScript) != 25 {
		t.Fatalf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}

	outPoint := btcwire.OutPoint{Hash: btcchainhash.Hash(FillOutBytes("hash", 32)), Index: 0}
	btx.TxIn = []*btcwire.TxIn{btcwire.NewTxIn(&outPoint, payToScript, nil)}

	changeAmount := int64(100)
	btx.TxOut = []*btcwire.TxOut{btcwire.NewTxOut(changeAmount, payToScript)}

	btx.TxOut = append(btx.TxOut, btcwire.NewTxOut(0, popTxOpReturn))

	sig := dcrecdsa.Sign(privateKey, []byte{})
	sigBytes := append(sig.Serialize(), byte(btctxscript.SigHashAll))
	sigScript, err := btctxscript.NewScriptBuilder().AddData(sigBytes).AddData(pubKeyBytes).Script()
	if err != nil {
		t.Fatal(err)
	}
	btx.TxIn[0].SignatureScript = sigScript

	var buf bytes.Buffer
	if err := btx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

// GetBtcTxPkScript creates a Bitcoin transaction and returns only the PkScript from the second output.
// This is a convenience function for tests that only need the PkScript.
// Parameters:
//   - t: testing context
//   - btcHeight: Bitcoin block height to use in the transaction
//   - l2Keystone: L2 keystone to include in the transaction
//   - minerPrivateKeyBytes: private key bytes for the miner
//
// Returns the PkScript as a byte slice.
func GetBtcTxPkScript(t *testing.T, btcHeight uint64, l2Keystone *hemi.L2Keystone, minerPrivateKeyBytes []byte) []byte {
	btx := &btcwire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(*l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := dcrsecp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)
	publicKey := privateKey.PubKey()
	pubKeyBytes := publicKey.SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubKeyBytes, &btcchaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	payToScript, err := btctxscript.PayToAddrScript(btcAddress.AddressPubKeyHash())
	if err != nil {
		t.Fatal(err)
	}

	if len(payToScript) != 25 {
		t.Fatalf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}

	outPoint := btcwire.OutPoint{Hash: btcchainhash.Hash(FillOutBytes("hash", 32)), Index: 0}
	btx.TxIn = []*btcwire.TxIn{btcwire.NewTxIn(&outPoint, payToScript, nil)}

	changeAmount := int64(100)
	btx.TxOut = []*btcwire.TxOut{btcwire.NewTxOut(changeAmount, payToScript)}

	btx.TxOut = append(btx.TxOut, btcwire.NewTxOut(0, popTxOpReturn))

	sig := dcrecdsa.Sign(privateKey, []byte{})
	sigBytes := append(sig.Serialize(), byte(btctxscript.SigHashAll))
	sigScript, err := btctxscript.NewScriptBuilder().AddData(sigBytes).AddData(pubKeyBytes).Script()
	if err != nil {
		t.Fatal(err)
	}
	btx.TxIn[0].SignatureScript = sigScript

	return btx.TxOut[1].PkScript
}
