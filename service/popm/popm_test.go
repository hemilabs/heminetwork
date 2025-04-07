package popm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/coder/websocket"
	"github.com/go-test/deep"
	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/juju/loggo"
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

	msgCh := make(chan string, 10)
	errCh := make(chan error)

	const keystoneCount = 10

	// Create opgeth test server with the request handler.
	opgeth := mockOpgeth(ctx, t, keystoneCount, msgCh, errCh)
	defer opgeth.Close()

	// Create tbc test server with the request handler.
	mtbc := mockTBC(ctx, t, msgCh, errCh)
	defer mtbc.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.GozerType = "tbc"
	cfg.TBCURL = "ws" + strings.TrimPrefix(mtbc.URL, "http")
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
		"kss_subscribe":                  1,
		"keystone_request":               keystoneCount,
		tbcapi.CmdUTXOsByAddressRequest:  keystoneCount,
		tbcapi.CmdFeeEstimateRequest:     keystoneCount,
		tbcapi.CmdTxBroadcastRequest:     keystoneCount,
		tbcapi.CmdBlockHeaderBestRequest: keystoneCount,
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

// TestProcessReceivedKeystones ensures that we store the latest keystone
// correctly as well as data stored in slices within the struct
func TestProcessReceivedKeystones(t *testing.T) {
	firstBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
	}

	secondBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 6,
			EPHash:        []byte{6},
		},
		{
			L2BlockNumber: 5,
			EPHash:        []byte{5},
		},
		{
			L2BlockNumber: 4,
			EPHash:        []byte{4},
		},
	}

	miner := Server{
		l2Keystones: make(map[string]L2KeystoneProcessingContainer),
	}

	miner.processReceivedKeystones(context.Background(), firstBatchOfL2Keystones)
	diff := deep.Equal(*miner.lastKeystone, hemi.L2Keystone{
		L2BlockNumber: 3,
		EPHash:        []byte{3},
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff: %v", diff)
	}

	miner.processReceivedKeystones(context.Background(), secondBatchOfL2Keystones)
	diff = deep.Equal(*miner.lastKeystone, hemi.L2Keystone{
		L2BlockNumber: 6,
		EPHash:        []byte{6},
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff: %v", diff)
	}
}

// TestProcessReceivedKeystonesSameL2BlockNumber ensures that we process
// an l2 keystone with the same l2 block number that we saw before if it
// has changed and less than threshold
func TestProcessReceivedKeystonesSameL2BlockNumber(t *testing.T) {
	firstBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
		{
			L2BlockNumber: 6,
			EPHash:        []byte{6},
		},
		{
			L2BlockNumber: 5,
			EPHash:        []byte{5},
		},
		{
			L2BlockNumber: 4,
			EPHash:        []byte{4},
		},
	}

	secondBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{44},
		},
	}

	miner := Server{
		l2Keystones: make(map[string]L2KeystoneProcessingContainer),
		cfg:         NewDefaultConfig(),
	}
	miner.cfg.RetryMineThreshold = 1

	miner.processReceivedKeystones(context.Background(), firstBatchOfL2Keystones)
	miner.processReceivedKeystones(context.Background(), secondBatchOfL2Keystones)

	for _, v := range append(firstBatchOfL2Keystones, secondBatchOfL2Keystones...) {
		serialized := hemi.L2KeystoneAbbreviate(v).Serialize()
		key := hex.EncodeToString(serialized[:])
		if diff := deep.Equal(miner.l2Keystones[key].l2Keystone, v); len(diff) > 0 {
			t.Fatalf("unexpected diff: %s", diff)
		}

	}
}

// TestProcessReceivedKeystonesOverThreshold tests that we don't re-queue
// an l2 keystone that is beyond threshold config
func TestProcessReceivedKeystonesOverThreshold(t *testing.T) {
	firstBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 300,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 301,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 302,
			EPHash:        []byte{1},
		},
		{
			L2BlockNumber: 306,
			EPHash:        []byte{6},
		},
		{
			L2BlockNumber: 320,
			EPHash:        []byte{5},
		},
		{
			L2BlockNumber: 310,
			EPHash:        []byte{4},
		},
	}

	secondBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{44},
		},
	}

	miner := Server{
		l2Keystones: make(map[string]L2KeystoneProcessingContainer),
		cfg:         NewDefaultConfig(),
	}
	miner.cfg.RetryMineThreshold = 1

	miner.processReceivedKeystones(context.Background(), firstBatchOfL2Keystones)
	miner.processReceivedKeystones(context.Background(), secondBatchOfL2Keystones)

	for _, v := range firstBatchOfL2Keystones {
		serialized := hemi.L2KeystoneAbbreviate(v).Serialize()
		key := hex.EncodeToString(serialized[:])
		if diff := deep.Equal(miner.l2Keystones[key].l2Keystone, v); len(diff) > 0 {
			t.Fatalf("unexpected diff: %s", diff)
		}
	}

	for _, v := range secondBatchOfL2Keystones {
		serialized := hemi.L2KeystoneAbbreviate(v).Serialize()
		key := hex.EncodeToString(serialized[:])
		if _, ok := miner.l2Keystones[key]; ok {
			t.Fatalf("should not have queued keystone")
		}
	}
}

// TestProcessReceivedInAscOrder ensures that we sort and process the latest
// N (3) L2Keystones in ascending order to handle the oldest first
func TestProcessReceivedInAscOrder(t *testing.T) {
	firstBatchOfL2Keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
	}

	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	miner.processReceivedKeystones(context.Background(), firstBatchOfL2Keystones)
	receivedKeystones := miner.l2KeystonesForProcessing()

	slices.Reverse(receivedKeystones)
	diff := deep.Equal(firstBatchOfL2Keystones, receivedKeystones)
	if len(diff) != 0 {
		t.Fatalf("received unexpected diff: %s", diff)
	}
}

// TestProcessReceivedOnlyOnce ensures that we only process keystones once if
// no error
func TestProcessReceivedOnlyOnce(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
	}
	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}
	miner.processReceivedKeystones(context.Background(), keystones)

	processedKeystonesFirstTime := 0
	for range miner.l2KeystonesForProcessing() {
		processedKeystonesFirstTime++
	}
	if processedKeystonesFirstTime != 3 {
		t.Fatalf("should have processed 3 keystones, processed %d", processedKeystonesFirstTime)
	}

	processedKeystonesSecondTime := 0
	for range miner.l2KeystonesForProcessing() {
		processedKeystonesSecondTime++
	}

	if processedKeystonesSecondTime != 0 {
		t.Fatal("should have only processed the keystones once")
	}
}

// TestProcessReceivedUntilError ensures that we retry until no error
func TestProcessReceivedOnlyOnceWithError(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
	}

	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}
	miner.processReceivedKeystones(context.Background(), keystones)

	processedKeystonesFirstTime := 0
	for _, c := range miner.l2KeystonesForProcessing() {
		processedKeystonesFirstTime++
		serialized := hemi.L2KeystoneAbbreviate(c).Serialize()
		key := hex.EncodeToString(serialized[:])
		miner.mtx.Lock()
		if v, ok := miner.l2Keystones[key]; ok {
			v.requiresProcessing = true
			miner.l2Keystones[key] = v
		}
		miner.mtx.Unlock()
	}
	if processedKeystonesFirstTime != 3 {
		t.Fatalf("should have processed 3 keystones, processed %d", processedKeystonesFirstTime)
	}

	processedKeystonesSecondTime := 0
	for range miner.l2KeystonesForProcessing() {
		processedKeystonesSecondTime++
	}

	if processedKeystonesSecondTime != 3 {
		t.Fatalf("should have processed 3 keystones, processed %d", processedKeystonesSecondTime)
	}

	processedKeystonesThirdTime := 0
	for range miner.l2KeystonesForProcessing() {
		processedKeystonesThirdTime++
	}

	if processedKeystonesThirdTime != 0 {
		t.Fatal("keystones should have already been processed")
	}
}

// TestProcessReceivedNoDuplicates ensures that we don't queue a duplicate
func TestProcessReceivedNoDuplicates(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
	}

	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	miner.processReceivedKeystones(context.Background(), keystones)
	receivedKeystones := miner.l2KeystonesForProcessing()

	slices.Reverse(keystones)

	diff := deep.Equal([]hemi.L2Keystone{
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
	}, receivedKeystones)
	if len(diff) != 0 {
		t.Fatalf("received unexpected diff: %s", diff)
	}
}

// TestProcessReceivedInAscOrder ensures that if we queue more than 10 keystones
// for mining, that we override the oldest
func TestProcessReceivedInAscOrderOverride(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 4,
			EPHash:        []byte{4},
		},
		{
			L2BlockNumber: 5,
			EPHash:        []byte{5},
		},
		{
			L2BlockNumber: 6,
			EPHash:        []byte{6},
		},
		{
			L2BlockNumber: 7,
			EPHash:        []byte{7},
		},
		{
			L2BlockNumber: 8,
			EPHash:        []byte{8},
		},
		{
			L2BlockNumber: 9,
			EPHash:        []byte{9},
		},
		{
			L2BlockNumber: 10,
			EPHash:        []byte{10},
		},
		{
			L2BlockNumber: 11,
			EPHash:        []byte{11},
		},
	}

	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, keystone := range keystones {
		miner.processReceivedKeystones(context.Background(), []hemi.L2Keystone{keystone})
	}

	receivedKeystones := miner.l2KeystonesForProcessing()

	slices.Reverse(keystones)

	diff := deep.Equal(keystones[:10], receivedKeystones)
	if len(diff) != 0 {
		t.Fatalf("received unexpected diff: %s", diff)
	}
}

func TestProcessAllKeystonesIfAble(t *testing.T) {
	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	for i := uint32(1); i < 1000; i++ {
		keystone := hemi.L2Keystone{
			L2BlockNumber: i,
			EPHash:        []byte{byte(i)},
		}
		miner.processReceivedKeystones(context.Background(), []hemi.L2Keystone{keystone})
		for _, c := range miner.l2KeystonesForProcessing() {
			diff := deep.Equal(c, keystone)
			if len(diff) != 0 {
				t.Fatalf("unexpected diff: %s", diff)
			}
		}
	}
}

// TestProcessReceivedInAscOrderNoInsertIfTooOld ensures that if the queue
// is full, and we try to insert a keystone that is older than every other
// keystone, we don't insert it
func TestProcessReceivedInAscOrderNoInsertIfTooOld(t *testing.T) {
	keystones := []hemi.L2Keystone{
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
		{
			L2BlockNumber: 2,
			EPHash:        []byte{2},
		},
		{
			L2BlockNumber: 3,
			EPHash:        []byte{3},
		},
		{
			L2BlockNumber: 4,
			EPHash:        []byte{4},
		},
		{
			L2BlockNumber: 5,
			EPHash:        []byte{5},
		},
		{
			L2BlockNumber: 6,
			EPHash:        []byte{6},
		},
		{
			L2BlockNumber: 7,
			EPHash:        []byte{7},
		},
		{
			L2BlockNumber: 8,
			EPHash:        []byte{8},
		},
		{
			L2BlockNumber: 9,
			EPHash:        []byte{9},
		},
		{
			L2BlockNumber: 10,
			EPHash:        []byte{10},
		},
		{
			L2BlockNumber: 11,
			EPHash:        []byte{11},
		},
	}

	miner, err := NewServer(&Config{
		BitcoinSecret: "ebaaedce6af48a03bbfd25e8cd0364140ebaaedce6af48a03bbfd25e8cd03641",
		Network:       "testnet3",
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, keystone := range keystones {
		miner.processReceivedKeystones(context.Background(), []hemi.L2Keystone{keystone})
	}

	// this one should be dropped
	miner.processReceivedKeystones(context.Background(), []hemi.L2Keystone{
		{
			L2BlockNumber: 1,
			EPHash:        []byte{1},
		},
	})

	receivedKeystones := miner.l2KeystonesForProcessing()

	slices.Reverse(keystones)

	diff := deep.Equal(keystones[:10], receivedKeystones)
	if len(diff) != 0 {
		t.Fatalf("received unexpected diff: %s", diff)
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
						{TxId: chainhash.Hash{},
							Value:    1000000,
							OutIndex: 1},
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

	h := handler{handleFunc: hf, errCh: errCh, name: "mockTBC"}

	tbc := httptest.NewServer(h)
	return tbc
}

func mockOpgeth(ctx context.Context, t *testing.T, kssCount int, msgCh chan string, errCh chan error) *httptest.Server {

	hf := func(w http.ResponseWriter, r *http.Request) error {

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}

		defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

		t.Logf("mockOpgeth: connection from %v", r.RemoteAddr)

		for i := 0; i <= kssCount; i++ {

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
			case "keystone_request":
				l2Keystone := hemi.L2Keystone{
					Version:            1,
					L1BlockNumber:      0xbadc0ffe,
					L2BlockNumber:      uint32(i),
					ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
					PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
					StateRoot:          digest256([]byte("Hello, world!")),
					EPHash:             digest256([]byte{0xaa, 0x55}),
				}
				kssResp := popapi.L2KeystoneResponse{
					L2Keystones: []hemi.L2Keystone{l2Keystone},
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
		return nil
	}

	h := handler{handleFunc: hf, errCh: errCh, name: "mockOpgeth"}

	opgeth := httptest.NewServer(h)
	return opgeth
}
