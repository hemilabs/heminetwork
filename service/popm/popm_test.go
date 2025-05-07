// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package popm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/coder/websocket"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
)

// Opgeth RPC Messages structs

type jsonrpcSubscriptionNotification struct {
	Version string                `json:"jsonrpc"`
	Method  string                `json:"method"`
	Params  subscriptionResultEnc `json:"params"`
}

type subscriptionResultEnc struct {
	ID     string `json:"subscription"`
	Result any    `json:"result"`
}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc,omitempty"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Error   *jsonError      `json:"error,omitempty"`
	Result  any             `json:"result,omitempty"`
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func TestPopMiner(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	msgCh := make(chan string, 12)
	errCh := make(chan error)

	kssMap, kssList := makeSharedKeystones(40)
	btcTip := uint(kssList[len(kssList)-1].L1BlockNumber)

	// Create opgeth test server with the request handler.
	opgeth := mockOpgeth(ctx, t, kssList, msgCh, errCh)
	defer opgeth.Close()

	// Create tbc test server with the request handler.
	mtbc := mockTBC(ctx, t, kssMap, btcTip, msgCh, errCh)
	defer mtbc.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSource = "tbc"
	cfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c"
	cfg.LogLevel = "popm=TRACE"

	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	// Create pop miner
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Start pop miner
	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_subscribe":          1,
		"kss_getLatestKeystones": 1,
		// tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest: 2,
		// tbcapi.CmdUTXOsByAddressRequest:  keystoneRequestCount,
		// tbcapi.CmdFeeEstimateRequest:     keystoneRequestCount,
		// tbcapi.CmdTxBroadcastRequest:     keystoneRequestCount,
		// tbcapi.CmdBlockHeaderBestRequest: keystoneRequestCount,
	}

	// receive messages and errors from opgeth and tbc
	for {
		select {
		case err = <-errCh:
			t.Fatal(err)
		case n := <-msgCh:
			expectedMsg[n]--
			finished := true
			for msg, k := range expectedMsg {
				if k > 0 {
					t.Logf("Still missing %v messages of type %s", k, msg)
					finished = false
				}
			}
			if finished {
				t.Log("Received all expected messages")
				return
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}

func makeSharedKeystones(n int) (map[chainhash.Hash]*hemi.L2KeystoneAbrev, []hemi.L2Keystone) {
	kssList := make([]hemi.L2Keystone, n)
	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	prevKeystone := &hemi.L2Keystone{
		Version:       1,
		L1BlockNumber: 0xbadc0ffe,
	}
	for ci := range n {
		x := uint8(ci)
		l2Keystone := hemi.L2Keystone{
			Version:            1,
			L1BlockNumber:      prevKeystone.L1BlockNumber + 1,
			L2BlockNumber:      uint32(ci+1) * 25,
			ParentEPHash:       digest256([]byte{x}),
			PrevKeystoneEPHash: digest256([]byte{x, x}),
			StateRoot:          digest256([]byte{x, x, x}),
			EPHash:             digest256([]byte{x, x, x, x}),
		}

		abrevKss := hemi.L2KeystoneAbbreviate(l2Keystone)
		kssMap[*abrevKss.Hash()] = abrevKss
		kssList[ci] = l2Keystone
		prevKeystone = &l2Keystone
	}

	return kssMap, kssList
}

type handler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
	errCh      chan error
	name       string
}

func (f handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f.handleFunc(w, r); err != nil {
		f.errCh <- fmt.Errorf("%s error: %w", f.name, err)
	}
}

func digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

func mockTBC(ctx context.Context, t *testing.T, kssMap map[chainhash.Hash]*hemi.L2KeystoneAbrev, btcTip uint, msgCh chan string, errCh chan error) *httptest.Server {
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

		for {
			cmd, id, payload, err := tbcapi.Read(ctx, wsConn)
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

			go func() {
				select {
				case <-ctx.Done():
					err = ctx.Err()
					return
				case msgCh <- string(cmd):
				}
			}()

			var resp any
			switch cmd {
			case tbcapi.CmdBlockHeaderBestRequest:
				resp = &tbcapi.BlockHeaderBestResponse{
					Height:      8,
					BlockHeader: nil,
				}
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
			case tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest:
				pl, ok := payload.(*tbcapi.BlockKeystoneByL2KeystoneAbrevHashRequest)
				if !ok {
					return fmt.Errorf("unexpected payload format: %v", payload)
				}

				kss, ok := kssMap[pl.L2KeystoneAbrevHash]
				if !ok {
					resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
						Error: protocol.Errorf("unknown keystone: %v", pl.L2KeystoneAbrevHash),
					}
				} else {
					resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
						L2KeystoneAbrev:       kss,
						L2KeystoneBlockHash:   &chainhash.Hash{0x0b, 0x0b},
						L2KeystoneBlockHeight: uint(kss.L1BlockNumber),
						BtcTipBlockHash:       &chainhash.Hash{0x0c, 0x0c},
						BtcTipBlockHeight:     btcTip,
					}
				}
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

	h := handler{handleFunc: hf, errCh: errCh, name: "mockTBC"}

	tbc := httptest.NewServer(h)
	return tbc
}

func mockOpgeth(ctx context.Context, t *testing.T, kssList []hemi.L2Keystone, msgCh chan string, errCh chan error) *httptest.Server {

	hf := func(w http.ResponseWriter, r *http.Request) error {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}

		defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

		t.Logf("mockOpgeth: connection from %v", r.RemoteAddr)

		var lastKeystone int
		for {

			var msg jsonrpcMessage
			_, br, err := c.Read(ctx)
			if err != nil {
				return err
			}
			err = json.Unmarshal(br, &msg)
			if err != nil {
				return err
			}

			t.Logf("mockOpgeth: command is %s", msg.Method)

			go func() {
				select {
				case <-ctx.Done():
					err = ctx.Err()
					return
				case msgCh <- msg.Method:
				}
			}()

			switch msg.Method {
			case "kss_subscribe":
				subResp := jsonrpcMessage{
					Version: "2.0",
					ID:      1,
					Result:  "0x5a395650bce324475634d746a831c227",
				}

				p, err := json.Marshal(subResp)
				if err != nil {
					return err
				}

				err = c.Write(ctx, websocket.MessageText, p)
				if err != nil {
					return err
				}

				encResult := subscriptionResultEnc{
					ID:     "0x5a395650bce324475634d746a831c227",
					Result: "New Keystone Available",
				}
				subNotif := jsonrpcSubscriptionNotification{
					Version: "2.0",
					Method:  "eth_subscription",
					Params:  encResult,
				}

				t.Log("Sending new keystone notification")
				err = c.Write(ctx, websocket.MessageText, p)
				if err != nil {
					return err
				}

				go func() {
					p, err := json.Marshal(subNotif)
					if err != nil {
						panic(err)
					}
					for {
						select {
						case <-ctx.Done():
							return
						case <-time.After(50 * time.Millisecond):
							t.Log("Sending new keystone notification")
							err = c.Write(ctx, websocket.MessageText, p)
							if err != nil {
								t.Error(err)
								return
							}
						}
					}
				}()
			case "kss_getLatestKeystones":
				var count []int
				err = json.Unmarshal(msg.Params, &count)
				if err != nil {
					panic(err)
				}

				kssResp := eth.L2KeystoneLatestResponse{
					L2Keystones: kssList[lastKeystone : lastKeystone+count[0]],
				}
				lastKeystone += count[0]

				subResp := jsonrpcMessage{
					Version: "2.0",
					ID:      msg.ID,
					Result:  kssResp,
				}

				p, err := json.Marshal(subResp)
				if err != nil {
					return err
				}

				err = c.Write(ctx, websocket.MessageText, p)
				if err != nil {
					return err
				}
			default:
				t.Errorf("unsupported message %v", msg.Method)
			}
		}
	}

	h := handler{handleFunc: hf, errCh: errCh, name: "mockOpgeth"}

	opgeth := httptest.NewServer(h)
	return opgeth
}
