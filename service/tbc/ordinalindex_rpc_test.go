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
	"maps"
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

	cache := make(map[tbcd.OrdinalKey]tbcd.OrdinalValue)

	// 'r': sat range for outpoint.
	var rKey tbcd.OrdinalKey
	rKey[0] = 'r'
	copy(rKey[1:], seed.outpoint[:])
	cache[rKey] = tbcd.OrdinalValue(EncodeSatRanges([]SatRange{
		{Start: seed.satNumber, Count: 5_000_000_000},
	}))

	// 'i': inscription value (sat number + block hash + flags).
	var iKey tbcd.OrdinalKey
	iKey[0] = 'i'
	copy(iKey[1:], seed.inscID[:])
	cache[iKey] = tbcd.OrdinalValue(encodeInscriptionValue(
		seed.satNumber, &seed.blockHash, false, &InscriptionEnvelope{
			ContentType: []byte("text/plain"),
			Content:     []byte("test inscription"),
		}))

	// 's': sat → outpoint.
	var sKey tbcd.OrdinalKey
	sKey[0] = 's'
	binary.BigEndian.PutUint64(sKey[1:], seed.satNumber)
	cache[sKey] = tbcd.OrdinalValue(seed.outpoint[:])

	// 'a': sat→inscription mapping.
	var aKey tbcd.OrdinalKey
	aKey[0] = 'a'
	binary.BigEndian.PutUint64(aKey[1:], seed.satNumber)
	copy(aKey[9:], seed.inscID[:])
	cache[aKey] = tbcd.OrdinalValue(seed.inscID[:])

	// 'n': block→inscription mapping (seq 0).
	var nKey tbcd.OrdinalKey
	nKey[0] = 'n'
	copy(nKey[1:33], seed.blockHash[:])
	// seq 0 → bytes already zero
	cache[nKey] = tbcd.OrdinalValue(seed.inscID[:])

	// --- Second inscription with parent, delegate, metaprotocol ---
	seed.txid2 = chainhash.Hash{0x11, 0x12, 0x13, 0x14}
	copy(seed.inscID2[:32], seed.txid2[:])
	seed.sat2 = 10_000_000_000

	parent := [36]byte{0xaa, 0xbb, 0xcc}   // parent inscription ID
	delegate := [36]byte{0xdd, 0xee, 0xff} // delegate inscription ID
	var iKey2 tbcd.OrdinalKey
	iKey2[0] = 'i'
	copy(iKey2[1:], seed.inscID2[:])
	cache[iKey2] = tbcd.OrdinalValue(encodeInscriptionValue(
		seed.sat2, &seed.blockHash, true, &InscriptionEnvelope{
			ContentType:  []byte("application/json"),
			Content:      []byte(`{"p":"brc-20"}`),
			Parent:       &parent,
			Delegate:     &delegate,
			Metaprotocol: []byte("brc-20"),
		}))

	// 's' for sat2.
	var sKey2 tbcd.OrdinalKey
	sKey2[0] = 's'
	binary.BigEndian.PutUint64(sKey2[1:], seed.sat2)
	outpoint2 := tbcd.NewOutpoint(seed.txid2, 1)
	cache[sKey2] = tbcd.OrdinalValue(outpoint2[:])

	cloned := maps.Clone(cache)
	if err := db.BlockOrdinalUpdate(ctx, 1, cloned, chainhash.Hash{}); err != nil {
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

	utxoCache := map[tbcd.Outpoint]tbcd.CacheOutput{
		seed.outpoint: co,
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
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		OrdinalIndex:         true,
		LevelDBHome:          home,
		ListenAddress:        "127.0.0.1:0",
		MaxCachedTxs:         1000,
		MaxCachedOrdinals:    1000,
		Network:              networkLocalnet,
		Seeds:                []string{"192.0.2.1:8333"},
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
				// Empty or nil — both cover the handler.
				return nil
			},
		},
	}

	for _, tti := range tests {
		t.Run(tti.name, func(t *testing.T) {
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
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		OrdinalIndex:            true,
		LevelDBHome:             home,
		ListenAddress:           "127.0.0.1:0",
		MaxCachedTxs:            1000,
		MaxCachedOrdinals:       1000,
		Network:                 networkLocalnet,
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
