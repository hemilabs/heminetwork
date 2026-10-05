// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

// counterValue returns the value of counter c, or of the series of a
// counter vector with the given label value.
func counterValue(t *testing.T, c prometheus.Collector, label string) float64 {
	t.Helper()

	reg := prometheus.NewPedanticRegistry()
	reg.MustRegister(c)
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			if label == "" {
				return m.GetCounter().GetValue()
			}
			for _, lp := range m.GetLabel() {
				if lp.GetValue() == label {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

// errIndexer is an Indexer whose position cannot be read.
type errIndexer struct{}

func (errIndexer) Enabled() bool                                     { return true }
func (errIndexer) Indexing() bool                                    { return false }
func (errIndexer) IndexToBest(context.Context) error                 { panic("stub") }
func (errIndexer) IndexToHash(context.Context, chainhash.Hash) error { panic("stub") }
func (errIndexer) IndexerAt(context.Context) (*tbcd.BlockHeader, error) {
	return nil, errors.New("database closed")
}

// TestLogIndexer checks that an indexer whose position cannot be read
// is logged, not dereferenced.
func TestLogIndexer(t *testing.T) {
	tests := []struct {
		name string
		i    Indexer
	}{
		{"position read", &stubIndexer{bh: &tbcd.BlockHeader{Height: 7}}},
		{"position error", errIndexer{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logIndexer(t.Context(), "test", tt.i) // must not panic
		})
	}
}

func TestBlockMetricsNil(t *testing.T) {
	var m *blockMetrics
	m.blockInserted()
	m.blockRequested()
	m.blockExpired(false)
	m.blockExpired(true)
}

func TestBlockMetricsRequested(t *testing.T) {
	tests := []struct {
		name     string
		headers  int
		inFlight int
		want     float64
	}{
		{"all missing requested", 10, 0, 10},
		{"window full", 200, defaultPendingBlocks, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newSyncServer(t, tt.headers)
			s.bm = newBlockMetrics("")
			getData := make(chan chainhash.Hash, 2*defaultPendingBlocks)
			p := addPipePeer(t, s, "peer", getData)
			for _, h := range chain[:tt.inFlight] {
				s.blocks.Put(t.Context(), time.Hour, h.BlockHash().String(),
					p, nil, nil)
			}

			s.syncBlocks(t.Context())
			collect(getData, int(tt.want), 2*time.Second)

			if got := counterValue(t, s.bm.requested, ""); got != tt.want {
				t.Fatalf("block_requests_total %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBlockMetricsExpired(t *testing.T) {
	tests := []struct {
		name      string
		fork      bool
		cancelled bool
		dropped   float64
		retried   float64
	}{
		{name: "fork block dropped", fork: true, dropped: 1},
		{name: "canonical block retried", retried: 1},
		{name: "expiry during shutdown", fork: true, cancelled: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, chain := newSyncServer(t, 10)
			s.bm = newBlockMetrics("")
			fork := makeChain(1, chaincfg.RegressionNetParams.GenesisBlock.Header,
				chaincfg.RegressionNetParams.PowLimitBits, 11*time.Minute)
			insertHeaders(t, s, fork)

			getData := make(chan chainhash.Hash, 2*defaultPendingBlocks)
			a := addPipePeer(t, s, "a", getData)
			addPipePeer(t, s, "b", getData)

			expired := chain[0].BlockHash()
			if tt.fork {
				expired = fork[0].BlockHash()
			}
			ctx := t.Context()
			if tt.cancelled {
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			s.blockExpired(ctx, expired.String(), a)

			dropped := counterValue(t, s.bm.expired, "dropped")
			retried := counterValue(t, s.bm.expired, "retried")
			if dropped != tt.dropped || retried != tt.retried {
				t.Fatalf("expired dropped %v retried %v, want %v %v",
					dropped, retried, tt.dropped, tt.retried)
			}
		})
	}
}

func TestBlockMetricsInserted(t *testing.T) {
	params := checkpointParams()
	payTo, err := btcutil.NewAddressPubKeyHash(make([]byte, 20), params)
	if err != nil {
		t.Fatal(err)
	}
	valid, err := newBlockTemplate(t, params, payTo, 1, params.GenesisHash,
		0, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Block timestamps have a precision of one second.
	hdr := &valid.MsgBlock().Header
	hdr.Timestamp = time.Unix(hdr.Timestamp.Unix(), 0)
	mineHeader(hdr)

	tests := []struct {
		name  string
		block *wire.MsgBlock
		want  float64
	}{
		{"valid block inserted", valid.MsgBlock(), 1},
		{"invalid block rejected", wire.NewMsgBlock(&wire.BlockHeader{}), 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newDifficultyTestServer(t, params)
			s.timeSource = blockchain.NewMedianTime()
			s.notifier = NewNotifier(false)
			s.bm = newBlockMetrics("")
			s.blocks, err = ttl.New(defaultPendingBlocks, true)
			if err != nil {
				t.Fatal(err)
			}
			s.pm, err = NewPeerManager(wire.TestNet, []string{}, 1)
			if err != nil {
				t.Fatal(err)
			}
			insertHeaders(t, s, []*wire.BlockHeader{hdr})

			err := s.handleBlock(t.Context(), nil, tt.block, nil)
			if (err == nil) != (tt.want == 1) {
				t.Fatalf("handleBlock: %v", err)
			}

			if got := counterValue(t, s.bm.inserted, ""); got != tt.want {
				t.Fatalf("blocks_inserted_total %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPromBlocksPending(t *testing.T) {
	var s Server
	if got := s.promBlocksPending(); got != 0 {
		t.Fatalf("no ttl: %v, want 0", got)
	}

	var err error
	s.blocks, err = ttl.New(defaultPendingBlocks, true)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		s.blocks.Put(t.Context(), time.Hour, i, nil, nil, nil)
	}
	if got := s.promBlocksPending(); got != 3 {
		t.Fatalf("blocks_pending %v, want 3", got)
	}
}
