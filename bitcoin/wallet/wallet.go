// Copyright (c) 2025-2026 Hemi Labs, Inc.
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

// PrevOuts maps an outpoint string to the TxOut that produced it, carrying
// both the previous output's pkScript and its amount.  Witness sighash
// algorithms (BIP-143 for segwit v0, BIP-341 for taproot) commit to the
// spent amount, so the amount must be available at signing time.
type PrevOuts map[string]*wire.TxOut

func TransactionCreate(locktime uint32, amount btcutil.Amount, satsPerByte float64, address btcutil.Address, utxos []*tbcapi.UTXO, script []byte) (*wire.MsgTx, PrevOuts, error) {
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
	prevOuts := make(PrevOuts, len(utxoList))
	for _, utxo := range utxoList {
		outpoint := wire.NewOutPoint(&utxo.TxId, utxo.OutIndex)
		tx.AddTxIn(wire.NewTxIn(outpoint, script, nil))
		prevOuts[outpoint.String()] = wire.NewTxOut(int64(utxo.Value), script)
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

func PoPTransactionCreate(l2keystone *hemi.L2Keystone, locktime uint32, satsPerByte float64, utxos []*tbcapi.UTXO, script []byte) (*wire.MsgTx, PrevOuts, error) {
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
	prevOuts := PrevOuts{outpoint.String(): wire.NewTxOut(int64(utxo.Value), script)}

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

// TransactionSign signs every input of tx using keys looked up in z.
// Inputs are dispatched by the script class of their previous output:
// legacy (P2PKH, P2SH, etc.) inputs produce a SignatureScript via the
// standard txscript.SignTxOutput path; native segwit v0 (P2WPKH) inputs
// produce a witness via BIP-143 sighash.  All signatures use SigHashAll.
func TransactionSign(params *chaincfg.Params, z zuul.Zuul, tx *wire.MsgTx, prevOuts PrevOuts) error {
	// Validate every input has a matching prev-out before any
	// sighash computation.  Without this pre-check a caller-
	// supplied incomplete PrevOuts would surface as a nil-deref
	// panic deep inside NewTxSigHashes when it tries to fetch
	// the missing amount for witness sighash midstate.
	for i, txIn := range tx.TxIn {
		if _, ok := prevOuts[txIn.PreviousOutPoint.String()]; !ok {
			return fmt.Errorf("previous out not found: input %d outpoint %v",
				i, txIn.PreviousOutPoint)
		}
	}

	// BIP-143 sighash midstate is reused across all witness inputs in
	// the tx.  Compute once.
	sigHashes := txscript.NewTxSigHashes(tx, prevOutsFetcher(prevOuts))

	for i, txIn := range tx.TxIn {
		prev := prevOuts[txIn.PreviousOutPoint.String()]

		switch txscript.GetScriptClass(prev.PkScript) {
		case txscript.WitnessV0PubKeyHashTy:
			if err := signP2WPKH(params, z, tx, i, prev, sigHashes); err != nil {
				return fmt.Errorf("sign p2wpkh input %d: %w", i, err)
			}

		default:
			sigScript, err := txscript.SignTxOutput(params, tx, i,
				prev.PkScript, txscript.SigHashAll,
				txscript.KeyClosure(z.LookupKeyByAddr), nil, nil)
			if err != nil {
				return err
			}
			tx.TxIn[i].SignatureScript = sigScript
		}
	}

	return nil
}

// signP2WPKH signs a witness v0 pubkey hash input.  The witness program
// is the 20-byte HASH160 of the pubkey; the sighash is computed over
// the P2PKH-equivalent script per BIP-143.  The caller's zuul must
// hold the key for the address derived from the witness program.
func signP2WPKH(params *chaincfg.Params, z zuul.Zuul, tx *wire.MsgTx, idx int, prev *wire.TxOut, sigHashes *txscript.TxSigHashes) error {
	_, addrs, _, err := txscript.ExtractPkScriptAddrs(prev.PkScript, params)
	if err != nil || len(addrs) != 1 {
		return fmt.Errorf("extract p2wpkh address: %w", err)
	}

	priv, ok, err := z.LookupKeyByAddr(addrs[0])
	if err != nil || !ok {
		return fmt.Errorf("lookup key for %s: %w", addrs[0], err)
	}

	witness, err := txscript.WitnessSignature(tx, sigHashes, idx,
		prev.Value, prev.PkScript, txscript.SigHashAll, priv, true)
	if err != nil {
		return fmt.Errorf("witness signature: %w", err)
	}
	tx.TxIn[idx].Witness = witness
	return nil
}

// prevOutsFetcher adapts PrevOuts to txscript.PrevOutputFetcher as
// required by NewTxSigHashes for segwit and taproot sighash calculation.
//
// PrevOuts keys are produced by wire.OutPoint.String; parsing back via
// wire.NewOutPointFromString is a lossless round-trip for well-formed
// keys.  A parse failure means the caller constructed PrevOuts with a
// manually-forged key that does not match any real outpoint, which
// would cause NewTxSigHashes to dereference a nil TxOut downstream.
// Panic with the offending key rather than silently dropping the
// entry and producing a corrupt sighash midstate.
func prevOutsFetcher(p PrevOuts) txscript.PrevOutputFetcher {
	m := make(map[wire.OutPoint]*wire.TxOut, len(p))
	for k, v := range p {
		op, err := wire.NewOutPointFromString(k)
		if err != nil {
			panic(fmt.Sprintf("prevOutsFetcher: malformed outpoint key %q: %v", k, err))
		}
		m[*op] = v
	}
	return txscript.NewMultiPrevOutFetcher(m)
}
