// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package wallet

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer"
	"github.com/hemilabs/heminetwork/bitcoin/wallet/gozer/tbcgozer"
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

	connCh := make(chan any)

	// Create tbc test server with the request handler.
	mtbc := mockTBC(ctx, t, connCh)
	defer mtbc.Close()

	tg, err := tbcgozer.Run(ctx, mtbc.URL)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for connection to TBC
	select {
	case <-connCh:
		time.Sleep(10 * time.Millisecond)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

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

	utxos, err := tg.UtxosByAddress(ctx, addr, 0, 0)
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

	tx, prevOut, err := TransactionCreate(uint32(time.Now().Unix()),
		btcutil.Amount(550), btcutil.Amount(feeEstimateForTx.SatsPerByte), addr, utxos, pkscript)
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
		btcutil.Amount(feeEstimateForPop.SatsPerByte+0.5), utxos, pkscript)
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

type handler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
}

func (f handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f.handleFunc(w, r); err != nil {
		panic(err)
	}
}

func mockTBC(ctx context.Context, t *testing.T, connCh chan any) *httptest.Server {
	hf := func(w http.ResponseWriter, r *http.Request) error {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			CompressionMode: websocket.CompressionContextTakeover,
		})
		if err != nil {
			return fmt.Errorf("Failed to accept websocket connection for %s: %w",
				r.RemoteAddr, err)
		}
		defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

		// Always ping, required by protocol.
		ping := &tbcapi.PingRequest{
			Timestamp: time.Now().Unix(),
		}

		wsConn := protocol.NewWSConn(conn)

		if err = tbcapi.Write(r.Context(), wsConn, "0", ping); err != nil {
			return fmt.Errorf("Write ping: %w", err)
		}

		t.Logf("mockTBC: connection from %v", r.RemoteAddr)

		connCh <- r.RemoteAddr

		for {
			cmd, id, _, err := tbcapi.Read(ctx, wsConn)
			if err != nil {
				var ce websocket.CloseError
				if errors.As(err, &ce) {
					return fmt.Errorf("handleWebsocketRead: %w", err)
				}
				if errors.Is(err, io.EOF) {
					return fmt.Errorf("handleWebsocketRead: EOF")
				}

				return fmt.Errorf("handleWebsocketRead: %w", err)
			}

			t.Logf("mockTBC: command is %v", cmd)

			var resp any
			switch cmd {
			case tbcapi.CmdUTXOsByAddressRequest:
				resp = &tbcapi.UTXOsByAddressResponse{
					UTXOs: []*tbcapi.UTXO{
						{
							TxId:     chainhash.Hash{},
							Value:    1000000,
							OutIndex: 1,
						},
					},
				}

			case tbcapi.CmdTxBroadcastRequest:
				resp = tbcapi.TxBroadcastResponse{TxID: &chainhash.Hash{0x0a}}

			case tbcapi.CmdFeeEstimateRequest:
				resp = tbcapi.FeeEstimateResponse{
					FeeEstimates: []*tbcapi.FeeEstimate{
						{Blocks: 1, SatsPerByte: 1},
						{Blocks: 2, SatsPerByte: 1},
						{Blocks: 3, SatsPerByte: 1},
						{Blocks: 4, SatsPerByte: 1},
						{Blocks: 5, SatsPerByte: 1},
						{Blocks: 6, SatsPerByte: 1},
						{Blocks: 7, SatsPerByte: 1},
						{Blocks: 8, SatsPerByte: 1},
						{Blocks: 9, SatsPerByte: 1},
						{Blocks: 10, SatsPerByte: 1},
					},
				}

			default:
				return fmt.Errorf("unknown command: %v", cmd)
			}

			if err = tbcapi.Write(ctx, wsConn, id, resp); err != nil {
				return fmt.Errorf("Failed to handle %s request: %w",
					cmd, err)
			}
		}
	}

	h := handler{handleFunc: hf}

	tbc := httptest.NewServer(h)
	return tbc
}
