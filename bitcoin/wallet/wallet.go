// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"errors"
	"fmt"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"

	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
)

// UtxoPickerMultiple is a simple utxo picker that returns a random set of utxos from
// the provided list that combined have a larger value than amount + fee.
func UtxoPickerMultiple(amount, fee btcutil.Amount, utxos []*tbcapi.UTXO) ([]*tbcapi.UTXO, error) {
	finalUTXO := make([]*tbcapi.UTXO, 0, len(utxos))

	// find large enough utxo
	total := amount + fee
	for k := range utxos {
		finalUTXO = append(finalUTXO, utxos[k])
		total -= utxos[k].Value
		if total > 0 {
			continue
		}

		return finalUTXO, nil
	}

	return nil, errors.New("no suitable utxos found")
}

// UtxoPickerSingle is a simple utxo picker that returns a random utxo from the
// provided list that has a larger value than amount + fee.
func UtxoPickerSingle(amount, fee btcutil.Amount, utxos []*tbcapi.UTXO) (*tbcapi.UTXO, error) {
	// find large enough utxo
	total := amount + fee
	for k := range utxos {
		if utxos[k].Value < total {
			continue
		}
		return utxos[k], nil
	}

	return nil, errors.New("no suitable utxo found")
}

func TransactionCreate(locktime uint32, amount btcutil.Amount, satsPerByte float64, address btcutil.Address, utxos []*tbcapi.UTXO, script []byte) (*wire.MsgTx, map[string][]byte, error) {
	// Create TxOut
	payToScript, err := txscript.PayToAddrScript(address)
	if err != nil {
		return nil, nil, err
	}
	txOut := wire.NewTxOut(int64(amount), payToScript)
	if mempool.IsDust(txOut, mempool.DefaultMinRelayTxFee) {
		return nil, nil, errors.New("amount is dust")
	}

	// Calculate fee for worst case input number and assume there is change
	txSize := txsizes.EstimateSerializeSize(len(utxos), []*wire.TxOut{txOut}, true)
	fee := btcutil.Amount(float64(txSize) * satsPerByte)

	// Find utxo list that is big enough for entire transaction
	utxoList, err := UtxoPickerMultiple(amount, fee, utxos)
	if err != nil {
		return nil, nil, err
	}

	// Calculate fee for real input number and assume there is change
	txSize = txsizes.EstimateSerializeSize(len(utxoList), []*wire.TxOut{txOut}, true)
	fee = btcutil.Amount(float64(txSize) * satsPerByte)

	// Assemble transaction
	tx := wire.NewMsgTx(2) // Latest supported version
	tx.LockTime = locktime
	prevOuts := make(map[string][]byte, len(utxoList))
	for _, utxo := range utxoList {
		outpoint := wire.NewOutPoint(&utxo.TxId, utxo.OutIndex)
		tx.AddTxIn(wire.NewTxIn(outpoint, script, nil))
		prevOuts[outpoint.String()] = script
	}

	// Change
	change := gozer.BalanceFromUtxos(utxoList) - (fee + amount)
	changeTxOut := wire.NewTxOut(int64(change), script)
	if !mempool.IsDust(changeTxOut, mempool.DefaultMinRelayTxFee) {
		tx.AddTxOut(changeTxOut)
	}

	tx.AddTxOut(txOut)

	return tx, prevOuts, nil
}

func PoPTransactionCreate(l2keystone *hemi.L2Keystone, locktime uint32, satsPerByte float64, utxos []*tbcapi.UTXO, script []byte) (*wire.MsgTx, map[string][]byte, error) {
	// Create OP_RETURN
	aks := hemi.L2KeystoneAbbreviate(*l2keystone)
	popTx := pop.TransactionL2{L2Keystone: aks}
	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		return nil, nil, fmt.Errorf("encode pop transaction: %w", err)
	}
	popTxOut := wire.NewTxOut(0, popTxOpReturn)

	// Calculate fee for 1 input and assume there is change
	txSize := txsizes.EstimateSerializeSize(1, []*wire.TxOut{popTxOut}, true)
	fee := btcutil.Amount(float64(txSize) * satsPerByte)

	// Find utxo that is big enough for entire transaction
	utxo, err := UtxoPickerSingle(0, fee, utxos) // no amount, just fees
	if err != nil {
		return nil, nil, err
	}

	// Assemble transaction
	tx := wire.NewMsgTx(2) // Latest supported version
	tx.LockTime = locktime
	outpoint := wire.NewOutPoint(&utxo.TxId, utxo.OutIndex)
	tx.AddTxIn(wire.NewTxIn(outpoint, script, nil))

	// Return previous outs to caller so that they can be signed.
	// This is a bit odd but in a real transaction we have to return all
	// the scripts (and somehow obtain them). Think about this some more.
	prevOuts := map[string][]byte{outpoint.String(): script}

	// Change
	change := utxo.Value - fee
	changeTxOut := wire.NewTxOut(int64(change), script)
	if !mempool.IsDust(changeTxOut, mempool.DefaultMinRelayTxFee) {
		tx.AddTxOut(changeTxOut)
	}

	// OP_RETURN
	tx.AddTxOut(wire.NewTxOut(0, popTxOpReturn))

	return tx, prevOuts, nil
}

func TransactionSign(params *chaincfg.Params, z zuul.Zuul, tx *wire.MsgTx, prevOuts map[string][]byte) error {
	for i, txIn := range tx.TxIn {
		prevPkScript, ok := prevOuts[txIn.PreviousOutPoint.String()]
		if !ok {
			return fmt.Errorf("previous out not found: %v",
				txIn.PreviousOutPoint)
		}
		sigScript, err := txscript.SignTxOutput(params, tx, i,
			prevPkScript, txscript.SigHashAll,
			txscript.KeyClosure(z.LookupKeyByAddr), nil, nil)
		if err != nil {
			return err
		}
		tx.TxIn[i].SignatureScript = sigScript
	}

	return nil
}
