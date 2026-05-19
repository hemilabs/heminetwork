// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// syncedDB embeds stubDB and overrides the two methods synced() needs.
type syncedDB struct {
	stubDB
	best    *tbcd.BlockHeader
	missing []tbcd.BlockIdentifier
}

func (d *syncedDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	return d.best, nil
}

func (d *syncedDB) BlocksMissing(context.Context, int) ([]tbcd.BlockIdentifier, error) {
	return d.missing, nil
}

// stubIndexer implements Indexer for synced() tests.
type stubIndexer struct {
	bh *tbcd.BlockHeader
}

func (si *stubIndexer) Enabled() bool                                        { return true }
func (si *stubIndexer) Indexing() bool                                       { return false }
func (si *stubIndexer) IndexToBest(context.Context) error                    { panic("stub") }
func (si *stubIndexer) IndexToHash(context.Context, chainhash.Hash) error    { panic("stub") }
func (si *stubIndexer) IndexerAt(context.Context) (*tbcd.BlockHeader, error) { return si.bh, nil }

func TestSynced(t *testing.T) {
	tipHash := chainhash.Hash{0x01} // non-zero
	staleHash := chainhash.Hash{0x02}

	tipBH := &tbcd.BlockHeader{Hash: tipHash, Height: 100}
	staleBH := &tbcd.BlockHeader{Hash: staleHash, Height: 99}

	tests := []struct {
		name      string
		hemiIndex bool
		zkIndex   bool
		keystone  *tbcd.BlockHeader
		zk        *tbcd.BlockHeader
		wantSync  bool
	}{
		{
			name:      "both indexes disabled",
			hemiIndex: false,
			zkIndex:   false,
			wantSync:  true,
		},
		{
			name:      "hemi enabled at tip",
			hemiIndex: true,
			zkIndex:   false,
			keystone:  tipBH,
			wantSync:  true,
		},
		{
			name:      "hemi enabled behind tip",
			hemiIndex: true,
			zkIndex:   false,
			keystone:  staleBH,
			wantSync:  false,
		},
		{
			name:      "zk enabled at tip",
			hemiIndex: false,
			zkIndex:   true,
			zk:        tipBH,
			wantSync:  true,
		},
		{
			name:      "zk enabled behind tip",
			hemiIndex: false,
			zkIndex:   true,
			zk:        staleBH,
			wantSync:  false,
		},
		{
			name:      "both enabled at tip",
			hemiIndex: true,
			zkIndex:   true,
			keystone:  tipBH,
			zk:        tipBH,
			wantSync:  true,
		},
		{
			name:      "both enabled hemi behind",
			hemiIndex: true,
			zkIndex:   true,
			keystone:  staleBH,
			zk:        tipBH,
			wantSync:  false,
		},
		{
			name:      "both enabled zk behind",
			hemiIndex: true,
			zkIndex:   true,
			keystone:  tipBH,
			zk:        staleBH,
			wantSync:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &syncedDB{
				best:    tipBH,
				missing: nil,
			}
			s := &Server{
				cfg: &Config{
					HemiIndex: tt.hemiIndex,
					ZKIndex:   tt.zkIndex,
				},
				g: geometryParams{db: db},
				// UTXO and TX indexers at tip.
				ui: &stubIndexer{bh: tipBH},
				ti: &stubIndexer{bh: tipBH},
			}
			if tt.keystone != nil {
				s.ki = &stubIndexer{bh: tt.keystone}
			}
			if tt.zk != nil {
				s.zki = &stubIndexer{bh: tt.zk}
			}

			si := s.synced(t.Context())
			if si.Synced != tt.wantSync {
				t.Errorf("synced() = %v, want %v", si.Synced, tt.wantSync)
			}
		})
	}
}
