// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

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
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"
	"github.com/phayes/freeport"

	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
)

// Opgeth RPC Messages structs

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

func createAddress() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(fmt.Errorf("find free port: %w", err))
	}
	return fmt.Sprintf("localhost:%d", port)
}

func TestBFG(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()

	msgCh := make(chan string, 10)
	errCh := make(chan error)

	const keystoneCount = 10

	// Create opgeth test server with the request handler.
	opgeth := mockOpgeth(ctx, t, msgCh, errCh)
	defer opgeth.Close()

	// Create tbc test server with the request handler.
	mtbc := mockTBC(ctx, t, msgCh, errCh)
	defer mtbc.Close()

	bfgCfg := NewDefaultConfig()
	bfgCfg.Network = "testnet3"
	bfgCfg.BitcoinSource = "tbc"
	bfgCfg.BitcoinURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
	bfgCfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
	bfgCfg.ListenAddress = createAddress()
	// bfgCfg.LogLevel = "bfg=Trace;"

	if err := loggo.ConfigureLoggers(bfgCfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(bfgCfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// messages we expect to receive
	expectedMsg := map[string]int{
		"kss_getKeystone": keystoneCount,
		tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest: keystoneCount * 2,
	}

	for !s.Connected() {
		time.Sleep(10 * time.Millisecond)
	}

	// send finality requests to bfg
	go func() {
		for range keystoneCount {
			kssHash := "99f3e3b9f72805f6992550ed870905cd45c832d78caa990b099b4c5873d06c59"
			u := fmt.Sprintf("http://%v/v%v/keystonefinality/%v",
				bfgCfg.ListenAddress, bfgapi.APIVersion, kssHash)
			resp, err := http.Get(u)
			if err != nil {
				panic(err)
			}

			fin := bfgapi.L2KeystoneBitcoinFinalityResponse{}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				panic(err)
			}
			// XXX add http status code test

			if err = json.Unmarshal(body, &fin); err != nil {
				panic(err)
			}
			if !*fin.SuperFinality {
				panic(fmt.Errorf("unexpected finality result: %v",
					spew.Sdump(fin)))
			}
			panic(spew.Sdump(fin)) // XXX antonio i think this test is broken when i look at BlockHeight: (uint) 10, and EffectiveConfirmations: (uint) 12,
		}
	}()

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

func mockTBC(ctx context.Context, t *testing.T, msgCh chan string, errCh chan error) *httptest.Server {
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
			case tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest:
				pl, ok := payload.(*tbcapi.BlockKeystoneByL2KeystoneAbrevHashRequest)
				if !ok {
					return fmt.Errorf("unexpected payload format: %v", payload)
				}

				expectedKeystone := hemi.L2Keystone{
					Version:            1,
					L1BlockNumber:      0xbadc0ffe,
					L2BlockNumber:      0xd3adb33f,
					ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
					PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
					StateRoot:          digest256([]byte("Hello, world!")),
					EPHash:             digest256([]byte{0xaa, 0x55}),
				}

				expectedAbrev := hemi.L2KeystoneAbbreviate(expectedKeystone)

				if pl.L2KeystoneAbrevHash != *expectedAbrev.Hash() {
					resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
						Error: protocol.Errorf("no clue who this is"),
					}
				} else {
					resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
						L2KeystoneAbrev:       expectedAbrev,
						L2KeystoneBlockHash:   &chainhash.Hash{0x0b, 0x0b},
						L2KeystoneBlockHeight: uint(10),
						BtcTipBlockHash:       &chainhash.Hash{0x0c, 0x0c},
						BtcTipBlockHeight:     uint(22),
					}
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

func mockOpgeth(ctx context.Context, t *testing.T, msgCh chan string, errCh chan error) *httptest.Server {
	hf := func(w http.ResponseWriter, r *http.Request) error {
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}

		defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

		t.Logf("mockOpgeth: connection from %v", r.RemoteAddr)

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
			case "kss_getKeystone":
				kssResp := bfgapi.L2KeystoneValidityResponse{
					L2Keystones: []hemi.L2Keystone{
						{
							Version:            1,
							L1BlockNumber:      0xbadc0ffe,
							L2BlockNumber:      0xd3adb33f,
							ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
							PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
							StateRoot:          digest256([]byte("Hello, world!")),
							EPHash:             digest256([]byte{0xaa, 0x55}),
						},
						{
							Version:            1,
							L1BlockNumber:      0xbadc0ffe,
							L2BlockNumber:      0xd3adb33f,
							ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
							PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
							StateRoot:          digest256([]byte("Goodbye, world!")),
							EPHash:             digest256([]byte{0xaa, 0x55}),
						},
					},
				}
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
