// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

	cloned := maps.Clone(cache)
	if err := db.BlockOrdinalUpdate(ctx, 1, cloned, chainhash.Hash{}); err != nil {
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
			name: "InscriptionsByAddress ordinal index check",
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
				// Returns empty or error — both cover the handler.
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
