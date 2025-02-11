// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/blockstream"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul/memory"
	"github.com/hemilabs/heminetwork/hemi"
)

func digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

// XXX make this a generic non-testing specific function.
func executeTX(t *testing.T, dump bool, scriptPubKey []byte, tx *btcutil.Tx) error {
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig | txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(scriptPubKey, tx.MsgTx(), 0, flags, nil, nil, -1, nil)
	if err != nil {
		return err
	}
	if dump {
		t.Logf("=== executing tx %v", tx.Hash())
	}
	for i := 0; ; i++ {
		d, err := vm.DisasmPC()
		if dump {
			t.Logf("%v: %v", i, d)
		}
		done, err := vm.Step()
		if err != nil {
			return err
		}
		stack := vm.GetStack()
		if dump {
			t.Logf("%v: stack %v", i, spew.Sdump(stack))
		}
		if done {
			break
		}
	}
	err = vm.CheckErrorCondition(true)
	if err != nil {
		return err
	}

	if dump {
		t.Logf("=== SUCCESS tx %v", tx.Hash())
	}
	return nil
}

func TestIntegration(t *testing.T) {
	// KeyStore for key looksups during signing
	m, err := memory.MemoryNew(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"
	w, err := vinzclortho.VinzClorthoNew(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Unlock(mnemonic)
	if err != nil {
		t.Fatal(err)
	}

	ek, err := w.DeriveHD(0, 0)
	if err != nil {
		t.Fatal(err)
	}
	addr, pub, err := vinzclortho.AddressAndPublicFromExtended(&chaincfg.TestNet3Params, ek)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v", addr)
	t.Logf("%v", pub)

	// Store in key store
	err = m.Put(&zuul.NamedKey{
		Name:       "my private key",
		Account:    0,
		Child:      0,
		HD:         true,
		PrivateKey: ek,
	})
	if err != nil {
		t.Fatal(err)
	}

	pkscript, err := vinzclortho.ScriptFromPubKeyHash(addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%x", pkscript)
	scripthash := vinzclortho.ScriptHashFromScript(pkscript)
	t.Logf("%v", scripthash)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	b, err := blockstream.BlockstreamNew(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	feeEstimates, err := b.FeeEstimates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	feeEstimate, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimate))

	utxos, err := b.UtxosByAddress(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("balance %v: %v", addr, gozer.BalanceFromUtxos(utxos))

	//// pick utxo
	//amount := btcutil.Amount(1000000) // 0.01000000 BTC
	//fee := btcutil.Amount(50000)      // 0.00050000 BTC
	//total := amount + fee             // 0.01050000 BTC
	//utxo, err := UtxoPickerSingle(amount, fee, utxos)
	//if err != nil {
	//	t.Fatal(err)
	//}
	//t.Logf("utxo: %v > %v", btcutil.Amount(utxo.Value), total)

	keystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      0xbadc0ffe,
		L2BlockNumber:      0xdeadbeef,
		ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
		PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
		StateRoot:          digest256([]byte("Hello, world!")),
		EPHash:             digest256([]byte{0xaa, 0x55}),
	}
	tx, prevOut, err := PoPTransactionCreate(keystone, uint32(time.Now().Unix()),
		btcutil.Amount(feeEstimate.SatsPerByte+0.5), utxos, pkscript)
	if err != nil {
		t.Fatal(err)
	}

	err = TransactionSign(&chaincfg.TestNet3Params, m, tx, prevOut)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("tx: %v", spew.Sdump(tx))

	err = executeTX(t, true, tx.TxOut[0].PkScript, btcutil.NewTx(tx))
	if err != nil {
		t.Fatal(err)
	}
}
