// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"context"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/gozer/tbcgozer"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/vinzclortho"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul"
	"github.com/hemilabs/heminetwork/v2/bitcoin/wallet/zuul/memory"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/testutil"
	"github.com/hemilabs/heminetwork/v2/testutil/mock"
)

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
		if err != nil {
			return err
		}
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
	m, err := memory.New(&chaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	mnemonic := "dinosaur banner version pistol need area dream champion kiss thank business shrug explain intact puzzle"
	w, err := vinzclortho.New(&chaincfg.TestNet3Params)
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
	ecpk, err := ek.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}

	// Store in key store
	err = m.PutKey(&zuul.NamedKey{
		Name:       "my private key",
		PrivateKey: ecpk,
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

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	// Create tbc test server with the request handler.
	mtbc := mock.NewMockTBC(ctx, errCh, msgCh, nil, 0, 10)
	defer mtbc.Shutdown()

	tg := tbcgozer.New(mtbc.URL())
	err = tg.Run(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for connection to TBC
	time.Sleep(50 * time.Millisecond)

	feeEstimates, err := tg.FeeEstimates(ctx)
	if err != nil {
		t.Fatal(err)
	}
	feeEstimateForPop, err := gozer.FeeByConfirmations(6, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimateForPop))

	feeEstimateForTx, err := gozer.FeeByConfirmations(2, feeEstimates)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(spew.Sdump(feeEstimateForTx))

	// XXX antonio we want test cases for true as well
	utxos, err := tg.UtxosByAddress(ctx, true, addr, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("balance %v: %v", addr, gozer.BalanceFromUtxos(utxos))

	// // pick utxo
	// amount := btcutil.Amount(1000000) // 0.01000000 BTC
	// fee := btcutil.Amount(50000)      // 0.00050000 BTC
	// total := amount + fee             // 0.01050000 BTC
	// utxo, err := UtxoPickerSingle(amount, fee, utxos)
	// if err != nil {
	//	t.Fatal(err)
	// }
	// t.Logf("utxo: %v > %v", btcutil.Amount(utxo.Value), total)

	keystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      0xbadc0ffe,
		L2BlockNumber:      0xdeadbeef,
		ParentEPHash:       testutil.SHA256([]byte{1, 1, 3, 7}),
		PrevKeystoneEPHash: testutil.SHA256([]byte{0x04, 0x20, 69}),
		StateRoot:          testutil.SHA256([]byte("Hello, world!")),
		EPHash:             testutil.SHA256([]byte{0xaa, 0x55}),
	}

	tx, prevOut, err := TransactionCreate(uint32(time.Now().Unix()),
		btcutil.Amount(550), feeEstimateForTx.SatsPerByte, addr, utxos, pkscript)
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

	popTx, prevOut, err := PoPTransactionCreate(keystone, uint32(time.Now().Unix()),
		feeEstimateForPop.SatsPerByte+0.5, utxos, pkscript)
	if err != nil {
		t.Fatal(err)
	}

	err = TransactionSign(&chaincfg.TestNet3Params, m, popTx, prevOut)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("poptx: %v", spew.Sdump(popTx))

	for _, txout := range popTx.TxOut {
		opCode := txout.PkScript[0]
		if opCode != txscript.OP_RETURN {
			err = executeTX(t, true, txout.PkScript, btcutil.NewTx(popTx))
			if err != nil {
				t.Fatal(err)
			}
		}
	}

	txID, err := tg.BroadcastTx(ctx, tx)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("txID: %v", txID)
}
