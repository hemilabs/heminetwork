// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/database/tbcd/level"
)

// ordinalDBSeed holds the values seeded into the ordinal DB for test assertions.
type ordinalDBSeed struct {
	outpoint  tbcd.Outpoint
	txid      chainhash.Hash
	inscID    [36]byte
	satNumber uint64
	blockHash chainhash.Hash // genesis hash — header exists on server startup

	// Second inscription with all optional fields.
	txid2   chainhash.Hash
	inscID2 [36]byte
	sat2    uint64

	// Address for InscriptionsByAddress testing.
	address string
}

// createFullOrdinalDB opens a LevelDB at home, writes ordinal index
// entries covering all key types, and returns the seed values for test
// assertions. Mirrors createFullZKDB in zkindexer_test.go.
func createFullOrdinalDB(ctx context.Context, t *testing.T, home string) ordinalDBSeed {
	t.Helper()

	cfg, err := level.NewConfig("localnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}()

	seed := ordinalDBSeed{
		txid:      chainhash.Hash{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
		satNumber: 5_000_000_000,
	}
	seed.outpoint = tbcd.NewOutpoint(seed.txid, 0)

	// Use the regtest genesis hash so BlockHeaderByHash succeeds
	// (the server inserts genesis on startup).
	genesisHashBytes, _ := chainhash.NewHashFromStr(
		"0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")
	seed.blockHash = *genesisHashBytes

	// Build inscription ID: txid(32) + input_index(4 LE).
	copy(seed.inscID[:32], seed.txid[:])
	// input_index 0 → little-endian [0,0,0,0] (already zero)

	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)

	// Aux entries ('i', 'n', 'a') are carried on the outpoint they relate to.
	// Use seed.outpoint as the host for the first inscription's aux.
	entry1 := getEntry(cache, seed.outpoint)

	// 'i': inscription value (sat number + block hash + flags).
	entry1.Aux[ordinalInscriptionKey(seed.inscID)] = tbcd.OrdinalValue(encodeInscriptionValue(
		seed.satNumber, &seed.blockHash, false, &InscriptionEnvelope{
			ContentType: []byte("text/plain"),
			Content:     []byte("test inscription"),
		}))

	// 'n': block→inscription mapping (seq 0).
	entry1.Aux[ordinalBlockInscriptionKey(&seed.blockHash, 0)] = tbcd.OrdinalValue(seed.inscID[:])

	// --- Second inscription with parent, delegate, metaprotocol ---
	seed.txid2 = chainhash.Hash{0x11, 0x12, 0x13, 0x14}
	copy(seed.inscID2[:32], seed.txid2[:])
	seed.sat2 = 10_000_000_000

	parent := [36]byte{0xaa, 0xbb, 0xcc}   // parent inscription ID
	delegate := [36]byte{0xdd, 0xee, 0xff} // delegate inscription ID

	outpoint2 := tbcd.NewOutpoint(seed.txid2, 0)
	entry2 := getEntry(cache, outpoint2)

	entry2.Aux[ordinalInscriptionKey(seed.inscID2)] = tbcd.OrdinalValue(encodeInscriptionValue(
		seed.sat2, &seed.blockHash, true, &InscriptionEnvelope{
			ContentType:  []byte("application/json"),
			Content:      []byte(`{"p":"brc-20"}`),
			Parent:       &parent,
			Delegate:     &delegate,
			Metaprotocol: []byte("brc-20"),
		}))

	// 'o': outpoint ownership tracker for inscription at seed.outpoint.
	// InscriptionsByAddress scans 'o' entries at each UTXO outpoint.
	entry1.Inscriptions[0] = encodeOutpointValue(
		seed.inscID, srcKindReveal, 0, ordinalRevealSentinel, 0)

	// Second 'o' entry: inscID2 at a second outpoint (txid2:0).
	// Tests that InscriptionsByAddress accumulates across UTXOs.
	entry2.Inscriptions[0] = encodeOutpointValue(
		seed.inscID2, srcKindReveal, 0, ordinalRevealSentinel, 0)

	// 'a': sat→inscription mapping for InscriptionsBySat.
	entry1.Aux[ordinalSatInscriptionKey(seed.satNumber, seed.inscID)] = []byte{}

	cloned := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, len(cache))
	for k, v := range cache {
		cloned[k] = v
	}
	if err := db.BlockOrdinalUpdate(ctx, 1, cloned, nil, chainhash.Hash{}); err != nil {
		t.Fatal(err)
	}

	// Seed the UTXO index so InscriptionsByAddress can find inscriptions.
	privKeyBytes, _ := hex.DecodeString(privateKey)
	_, pub := btcec.PrivKeyFromBytes(privKeyBytes)
	p2pkhAddr, _ := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(pub.SerializeCompressed()),
		&chaincfg.RegressionNetParams)
	seed.address = p2pkhAddr.EncodeAddress()

	pkScript, _ := txscript.PayToAddrScript(p2pkhAddr)
	sh := tbcd.NewScriptHashFromScript(pkScript)
	co := tbcd.NewCacheOutput([32]byte(sh), 5_000_000_000, 0)
	co2 := tbcd.NewCacheOutput([32]byte(sh), 10_000_000_000, 0)

	utxoCache := map[tbcd.Outpoint]tbcd.CacheOutput{
		seed.outpoint: co,
		outpoint2:     co2,
	}
	if err := db.BlockUtxoUpdate(ctx, 1, utxoCache, chainhash.Hash{}); err != nil {
		t.Fatal(err)
	}

	return seed
}

// TestRpcOrdinal tests ordinal RPC handlers via websocket without
// bitcoind. Seeds LevelDB directly, starts TBC with OrdinalIndex,
// and exercises handlers through the dispatch layer. Mirrors TestRpcZK.
func TestRpcOrdinal(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
	defer cancel()

	home := t.TempDir()

	seed := createFullOrdinalDB(ctx, t, home)

	cfg := &Config{
		AutoIndex:         false,
		BlockCacheSize:    "10mb",
		HeaderCacheSize:   "1mb",
		BlockSanity:       false,
		OrdinalIndex:      true,
		LevelDBHome:       home,
		ListenAddress:     "127.0.0.1:0",
		MaxCachedTxs:      1000,
		MaxCachedOrdinals: 1000,
		Network:           networkLocalnet,
		RequestTimeout:    10,
		Seeds:             []string{"192.0.2.1:8333"},
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for HTTP server to start.
	var tbcAddr string
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(10 * time.Millisecond):
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcAddr = addr.String()
			break
		}
	}

	tbcUrl := fmt.Sprintf("http://%s%s", tbcAddr, tbcapi.RouteWebsocket)
	c, _, err := websocket.Dial(ctx, tbcUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)

	tws := &tbcWs{
		conn: protocol.NewWSConn(c),
	}

	type testTableItem struct {
		name          string
		skip          string // if set, skip with this reason
		req           any
		respHeader    protocol.Command
		handler       func(ctx context.Context, v protocol.Message) *protocol.Error
		expectedError *protocol.Error
	}

	fakeTxid := chainhash.Hash{0xde, 0xad, 0xbe, 0xef}
	fakeBlock := chainhash.Hash{0xff, 0xfe}

	tests := []testTableItem{
		{
			name: "SatRangesByOutpoint positive",
			skip: "ordinals2: on-demand computation needs real chain data",
			req: tbcapi.OrdinalSatRangesByOutpointRequest{
				TxID: *seed.outpoint.TxIdHash(),
				Vout: seed.outpoint.TxIndex(),
			},
			respHeader: tbcapi.CmdOrdinalSatRangesByOutpointResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalSatRangesByOutpointResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.SatRanges) != 1 {
					return protocol.Errorf("expected 1 sat range, got %d", len(r.SatRanges))
				}
				if r.SatRanges[0].Start != 5_000_000_000 || r.SatRanges[0].Count != 5_000_000_000 {
					return protocol.Errorf("sat range: got %v", r.SatRanges[0])
				}
				return nil
			},
		},
		{
			name: "SatRangesByOutpoint not found",
			skip: "ordinals2: on-demand computation needs real chain data",
			req: tbcapi.OrdinalSatRangesByOutpointRequest{
				TxID: fakeTxid,
				Vout: 99,
			},
			respHeader: tbcapi.CmdOrdinalSatRangesByOutpointResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalSatRangesByOutpointResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.NotFoundError("outpoint",
				fmt.Sprintf("%v:%d", fakeTxid, 99)),
		},
		{
			name: "InscriptionByID positive",
			req: tbcapi.OrdinalInscriptionByIDRequest{
				TxID:       seed.txid,
				InputIndex: 0,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionByIDResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionByIDResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if r.Inscription == nil {
					return protocol.Errorf("inscription is nil")
				}
				if r.Inscription.SatNumber != seed.satNumber {
					return protocol.Errorf("sat: got %d, want %d",
						r.Inscription.SatNumber, seed.satNumber)
				}
				if r.Inscription.TxID != seed.txid {
					return protocol.Errorf("txid mismatch")
				}
				return nil
			},
		},
		{
			name: "InscriptionByID not found",
			req: tbcapi.OrdinalInscriptionByIDRequest{
				TxID:       fakeTxid,
				InputIndex: 0,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionByIDResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionByIDResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.NotFoundError("inscription",
				fmt.Sprintf("%v:%d", fakeTxid, 0)),
		},
		{
			name: "InscriptionByID with parent+delegate+metaprotocol",
			req: tbcapi.OrdinalInscriptionByIDRequest{
				TxID:       seed.txid2,
				InputIndex: 0,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionByIDResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionByIDResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				i := r.Inscription
				if i == nil {
					return protocol.Errorf("inscription is nil")
				}
				if i.SatNumber != seed.sat2 {
					return protocol.Errorf("sat: got %d, want %d",
						i.SatNumber, seed.sat2)
				}
				if !i.Cursed {
					return protocol.Errorf("expected cursed")
				}
				if i.ParentTxID == nil {
					return protocol.Errorf("expected parent")
				}
				if i.DelegateTxID == nil {
					return protocol.Errorf("expected delegate")
				}
				if i.Metaprotocol == nil || *i.Metaprotocol != "brc-20" {
					return protocol.Errorf("metaprotocol: got %v",
						i.Metaprotocol)
				}
				return nil
			},
		},
		{
			name: "InscriptionsByBlock positive",
			req: tbcapi.OrdinalInscriptionsByBlockRequest{
				Hash: seed.blockHash,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByBlockResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByBlockResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 1 {
					return protocol.Errorf("expected 1 inscription, got %d",
						len(r.Inscriptions))
				}
				if r.Inscriptions[0].TxID != seed.txid {
					return protocol.Errorf("txid mismatch")
				}
				return nil
			},
		},
		{
			name: "InscriptionsByBlock empty",
			req: tbcapi.OrdinalInscriptionsByBlockRequest{
				Hash: fakeBlock,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByBlockResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByBlockResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 0 {
					return protocol.Errorf("expected 0 inscriptions, got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionsBySat positive",
			req: tbcapi.OrdinalInscriptionsBySatRequest{
				SatNumber: seed.satNumber,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsBySatResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsBySatResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 1 {
					return protocol.Errorf("expected 1 inscription, got %d",
						len(r.Inscriptions))
				}
				if r.Inscriptions[0].TxID != seed.txid {
					return protocol.Errorf("txid mismatch")
				}
				return nil
			},
		},
		{
			name: "InscriptionsBySat empty",
			req: tbcapi.OrdinalInscriptionsBySatRequest{
				SatNumber: 999_999_999,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsBySatResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsBySatResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 0 {
					return protocol.Errorf("expected 0 inscriptions, got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionContent not found",
			req: tbcapi.OrdinalInscriptionContentRequest{
				TxID:       fakeTxid,
				InputIndex: 0,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionContentResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionContentResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: protocol.NotFoundError("inscription content",
				fmt.Sprintf("%v:%d", fakeTxid, 0)),
		},
		{
			name: "InscriptionsByAddress positive",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: seed.address,
				Start:   0,
				Count:   10,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 2 {
					return protocol.Errorf("expected 2 inscriptions, got %d",
						len(r.Inscriptions))
				}
				// Both seed inscriptions must be present (order not guaranteed).
				found := map[chainhash.Hash]bool{}
				for _, insc := range r.Inscriptions {
					found[insc.TxID] = true
				}
				if !found[seed.txid] || !found[seed.txid2] {
					return protocol.Errorf("missing inscription: found %v", found)
				}
				return nil
			},
		},
		{
			name: "InscriptionsByAddress empty",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080",
				Start:   0,
				Count:   10,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 0 {
					return protocol.Errorf("expected 0 inscriptions, got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionsByAddress pagination skip",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: seed.address,
				Start:   1,
				Count:   1,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 1 {
					return protocol.Errorf("expected 1 inscription (skipped 1), got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionsByAddress pagination count limit",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: seed.address,
				Start:   0,
				Count:   1,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 1 {
					return protocol.Errorf("expected 1 inscription (count-limited from 2), got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionsByAddress pagination past end",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: seed.address,
				Start:   100,
				Count:   10,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				if r.Error != nil {
					return r.Error
				}
				if len(r.Inscriptions) != 0 {
					return protocol.Errorf("expected 0 inscriptions (past end), got %d",
						len(r.Inscriptions))
				}
				return nil
			},
		},
		{
			name: "InscriptionsByAddress bad address",
			req: tbcapi.OrdinalInscriptionsByAddressRequest{
				Address: "not-a-valid-address",
				Start:   0,
				Count:   10,
			},
			respHeader: tbcapi.CmdOrdinalInscriptionsByAddressResponse,
			handler: func(ctx context.Context, v protocol.Message) *protocol.Error {
				var r tbcapi.OrdinalInscriptionsByAddressResponse
				if err := json.Unmarshal(v.Payload, &r); err != nil {
					panic(err)
				}
				return r.Error
			},
			expectedError: &protocol.Error{
				Message: "internal error",
			},
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
			if tti.skip != "" {
				t.Skip(tti.skip)
			}
			if err := tbcapi.Write(ctx, tws.conn, tti.name, tti.req); err != nil {
				t.Fatal(err)
			}

			var v protocol.Message
			if err := wsjson.Read(ctx, c, &v); err != nil {
				t.Fatal(err)
			}

			if v.Header.Command != tti.respHeader {
				t.Fatalf("received unexpected command: %s", v.Header.Command)
			}

			resp := tti.handler(ctx, v)
			if tti.expectedError != nil {
				if resp == nil || resp.Message != tti.expectedError.Message {
					t.Fatalf("unexpected error: got %v, wanted %v",
						resp, tti.expectedError)
				}
			} else if resp != nil {
				t.Fatalf("unexpected error: %v", resp.Message)
			}
		})
	}
}

func TestPrometheusOrdinalMetric(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	home := t.TempDir()
	_ = createFullOrdinalDB(ctx, t, home)

	promAddr := "127.0.0.1:19123"
	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		HeaderCacheSize:         "1mb",
		BlockSanity:             false,
		OrdinalIndex:            true,
		LevelDBHome:             home,
		ListenAddress:           "127.0.0.1:0",
		MaxCachedTxs:            1000,
		MaxCachedOrdinals:       1000,
		Network:                 networkLocalnet,
		RequestTimeout:          10,
		PrometheusListenAddress: promAddr,
		Seeds:                   []string{"192.0.2.1:8333"},
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	// Wait for both HTTP and Prometheus to start.
	for {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(50 * time.Millisecond):
		}
		if s.HTTPAddress() != nil {
			break
		}
	}
	// Give prometheus listener time to bind.
	time.Sleep(200 * time.Millisecond)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		fmt.Sprintf("http://%s/metrics", promAddr), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics: status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	metrics := string(body)

	if !strings.Contains(metrics, "ordinal_sync_height") {
		t.Fatal("ordinal_sync_height metric not found in /metrics output")
	}
	t.Logf("ordinal_sync_height found in prometheus output")
}

// TestInputOutputValueUnknownTx verifies inputOutputValue returns a
// wrapped error when the txid is not in the database. This is the error
// path windBlock/unwindBlock rely on to fail loudly rather than silently
// mis-place an inscribed sat. The vout-out-of-range and tx-not-in-block
// paths require a fully mined block and are covered by the fork test's
// transfer scenarios.
func TestInputOutputValueUnknownTx(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	home := t.TempDir()
	cfg, err := level.NewConfig("localnet", home, "", "")
	if err != nil {
		t.Fatal(err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	})

	unknown := chainhash.Hash{0xde, 0xad}
	_, err = inputOutputValue(ctx, db, unknown, 0)
	if err == nil {
		t.Fatal("expected error for unknown txid, got nil")
	}
	if !errors.Is(err, database.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

// BenchmarkLocatedAtOutpoint measures the cache-overlay cost of the unwind
// lookup as the pending batch cache grows. The DB lookup returns nothing
// (unknown op), so this isolates the O(C) cache scan that dominates unwind
// of a batch. Run: go test -bench BenchmarkLocatedAtOutpoint -benchmem
//
// Establishes the number behind locatedAtOutpoint's documented O(D+C)
// bound so a future deep-reorg profile can be compared against it rather
// than guessed at.
func BenchmarkLocatedAtOutpoint(b *testing.B) {
	ctx, cancel := context.WithCancel(b.Context())
	defer cancel()

	home := b.TempDir()
	cfg, err := level.NewConfig("localnet", home, "", "")
	if err != nil {
		b.Fatal(err)
	}
	db, err := level.New(ctx, cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = db.Close() })

	oi := &ordinalIndexer{indexerCommon: indexerCommon{g: geometryParams{db: db}}}
	op := tbcd.NewOutpoint(chainhash.Hash{0xab}, 0)

	for _, cacheSize := range []int{100, 1000, 10000} {
		cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry, cacheSize)
		for n := 0; n < cacheSize; n++ {
			var txid chainhash.Hash
			binary.BigEndian.PutUint64(txid[:8], uint64(n))
			nop := tbcd.NewOutpoint(txid, 0)
			entry := getEntry(cache, nop)
			entry.Inscriptions[0] = encodeOutpointValue([36]byte{byte(n)}, srcKindReveal, 0, ordinalRevealSentinel, 0)
		}
		b.Run(fmt.Sprintf("cache=%d", cacheSize), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_, err := oi.locatedAtOutpoint(ctx, cache, op)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// TestOrdinalCacheLenCountsSubEntries verifies that OrdinalCache.Len()
// returns the total number of sub-entries (inscriptions + predecessors +
// aux) across all outpoints, not len(map). This is the core invariant
// of the cache redesign — flush decisions must reflect actual DB
// operation count.
func TestOrdinalCacheLenCountsSubEntries(t *testing.T) {
	cache := NewOrdinalCache(1000)

	if cache.Len() != 0 {
		t.Fatalf("empty cache: Len() = %d, want 0", cache.Len())
	}

	// One outpoint with 3 inscriptions, 2 predecessors, 1 aux entry = 6 writes.
	txid := chainhash.Hash{0x01}
	op := tbcd.NewOutpoint(txid, 0)
	cache.PutInscription(op, 0, []byte{0x01})
	cache.PutInscription(op, 100, []byte{0x02})
	cache.PutInscription(op, 200, nil) // tombstone — still a DB operation
	cache.PutPredecessor(op, 0, []byte{0x03})
	cache.PutPredecessor(op, 100, nil) // tombstone
	cache.PutAux(op, ordinalInscriptionKey([36]byte{0x01}), []byte{0x04})

	if got := cache.Len(); got != 6 {
		t.Fatalf("6 writes: Len() = %d, want 6", got)
	}

	// Second outpoint with 1 inscription = total 7.
	op2 := tbcd.NewOutpoint(chainhash.Hash{0x02}, 0)
	cache.PutInscription(op2, 0, []byte{0x05})

	if got := cache.Len(); got != 7 {
		t.Fatalf("7 writes: Len() = %d, want 7", got)
	}

	// Stats must reflect write count, not outpoint count.
	length, capacity, pct := cache.Stats()
	if length != 7 || capacity != 1000 {
		t.Fatalf("Stats: length=%d capacity=%d, want 7/1000", length, capacity)
	}
	if pct != 0 { // 7*100/1000 = 0 (integer division)
		t.Fatalf("Stats: pct=%d, want 0", pct)
	}

	// Clear resets everything.
	cache.Clear()
	if cache.Len() != 0 {
		t.Fatalf("after Clear: Len() = %d, want 0", cache.Len())
	}
	if len(cache.m) != 0 {
		t.Fatalf("after Clear: len(map) = %d, want 0", len(cache.m))
	}
}

// TestGetEntryCreateAndReuse verifies getEntry creates on miss and
// returns existing on hit without overwriting data.
func TestGetEntryCreateAndReuse(t *testing.T) {
	cache := make(map[tbcd.Outpoint]*tbcd.OrdinalCacheEntry)
	op := tbcd.NewOutpoint(chainhash.Hash{0x01}, 0)

	e1 := getEntry(cache, op)
	e1.Inscriptions[0] = []byte{0xaa}

	e2 := getEntry(cache, op)
	if e2 != e1 {
		t.Fatal("getEntry returned different pointer on hit")
	}
	if len(e2.Inscriptions) != 1 || e2.Inscriptions[0][0] != 0xaa {
		t.Fatal("getEntry overwrote existing entry data")
	}
}
