// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

func mainnetIdentityServer(db *identityStubDB) *Server {
	return &Server{
		cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams,
		wireNet: wire.MainNet, db: db, checkpoints: mainnetCheckpoints, // as NewServer sets for mainnet
	}
}

// soakHeader returns a trivial-PoW header that cannot meet mainnet's PowLimit.
func soakHeader(tag byte, height uint64) *tbcd.BlockHeader {
	w := &wire.BlockHeader{
		Version: 1, PrevBlock: chainhash.Hash{tag},
		Bits: chaincfg.RegressionNetParams.PowLimitBits, Timestamp: time.Unix(1600000000, 0),
	}
	return bhFromWire(w, height)
}

// A datadir stamped for the configured params starts without re-checking the
// tip's proof of work, since a stamped node may later take a tip through the
// blind-trust op-geth header door. Unstamped datadirs are still checked and
// mismatched stamps are still refused.
func TestVerifyDatadirIdentityStampIsAuthoritative(t *testing.T) {
	genesisBH := bhFromWire(&chaincfg.MainNetParams.GenesisBlock.Header, 0)
	byGenesis := func() map[chainhash.Hash]*tbcd.BlockHeader {
		return map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH}
	}

	t.Run("stamped-matching datadir with a sub-PowLimit tip restarts", func(t *testing.T) {
		probe := mainnetIdentityServer(&identityStubDB{})
		db := &identityStubDB{
			best:   soakHeader(0x01, 900000), // arrived via the op-geth door
			byHash: byGenesis(),
			meta:   map[string][]byte{string(paramsIdentityKey): probe.paramsIdentity()},
		}
		if err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("a correctly stamped datadir was refused on restart: %v", err)
		}
	})

	t.Run("unstamped soak tip is still refused", func(t *testing.T) {
		db := &identityStubDB{best: soakHeader(0x02, 500000), byHash: byGenesis()}
		err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context())
		if err == nil || !strings.Contains(err.Error(), "proof-of-work") {
			t.Fatalf("unstamped soak tip = %v, want a proof-of-work refusal", err)
		}
		if _, ok := db.meta[string(paramsIdentityKey)]; ok {
			t.Fatal("a refused datadir was stamped")
		}
	})

	t.Run("mismatched stamp is still refused", func(t *testing.T) {
		testnet := (&Server{chainParams: &chaincfg.TestNet3Params, wireNet: wire.TestNet3}).paramsIdentity()
		db := &identityStubDB{
			best: genesisBH, byHash: byGenesis(),
			meta: map[string][]byte{string(paramsIdentityKey): testnet},
		}
		err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context())
		if err == nil || !strings.Contains(err.Error(), "stamped for a") {
			t.Fatalf("mismatched stamp = %v, want refusal", err)
		}
	})
}

// On an unstamped datadir with no stored checkpoint at or below them, the
// utxo, tx and keystone index heads must meet the configured PowLimit too. A
// soak datadir whose header chain was later extended
// with real-PoW headers passes the tip check but still has trivial-PoW index
// heads.
func TestVerifyDatadirIdentityChecksIndexedFrontier(t *testing.T) {
	genesisBH := bhFromWire(&chaincfg.MainNetParams.GenesisBlock.Header, 0)

	for _, which := range []string{"utxo", "tx", "keystone"} {
		t.Run("soak "+which+" frontier is refused", func(t *testing.T) {
			soak := soakHeader(0x03, 700000)
			db := &identityStubDB{
				best: genesisBH, // real PoW: passes the tip check
				byHash: map[chainhash.Hash]*tbcd.BlockHeader{
					*chaincfg.MainNetParams.GenesisHash: genesisBH,
					soak.Hash:                           soak,
				},
			}
			switch which {
			case "utxo":
				db.utxo = soak
			case "tx":
				db.tx = soak
			case "keystone":
				db.keystone = soak
			}
			err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context())
			if err == nil || !strings.Contains(err.Error(), "network mismatch") {
				t.Fatalf("soak %v frontier = %v, want a datadir-mismatch refusal", which, err)
			}
			if _, ok := db.meta[string(paramsIdentityKey)]; ok {
				t.Fatal("a refused datadir was stamped")
			}
		})
	}

	t.Run("legit legacy datadir is accepted and stamped", func(t *testing.T) {
		db := &identityStubDB{
			best:   genesisBH,
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH},
			utxo:   genesisBH, tx: genesisBH, // indexed to genesis
		}
		s := mainnetIdentityServer(db)
		if err := s.verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("legit legacy datadir refused: %v", err)
		}
		if _, ok := db.meta[string(paramsIdentityKey)]; !ok {
			t.Fatal("legit legacy datadir was not stamped")
		}
	})
}

// The stamp must change when only PowLimit (the big.Int the proof-of-work
// checks use) changes, even with PowLimitBits left alone.
func TestParamsIdentityCoversPowLimit(t *testing.T) {
	mainnet := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &chaincfg.MainNetParams, wireNet: wire.MainNet}
	p := chaincfg.MainNetParams
	p.PowLimit = chaincfg.RegressionNetParams.PowLimit // PowLimitBits unchanged
	variant := &Server{cfg: &Config{Network: "mainnet"}, chainParams: &p, wireNet: wire.MainNet}
	if string(mainnet.paramsIdentity()) == string(variant.paramsIdentity()) {
		t.Fatal("a params set differing only in PowLimit shares the mainnet stamp")
	}
}

// op-geth feeds TBC headers through a door that is not PoW-checked, so an L2
// gossip peer can plant a trivial-PoW tip in an otherwise correct datadir.
// Such an unstamped datadir must start, and be stamped, when a real checkpoint
// header is stored at or below the tip; the same holds for index heads inside
// the plant at any depth. A trivial-PoW chain with no stored checkpoint under
// it is refused, and the refusal must not tell the operator to wipe the datadir.
func TestVerifyDatadirIdentityGossipPlantedTip(t *testing.T) {
	genesisBH := bhFromWire(&chaincfg.MainNetParams.GenesisBlock.Header, 0)
	var cp checkpoint
	for _, c := range mainnetCheckpoints {
		if c.height == 850000 {
			cp = c
		}
	}
	if cp.height == 0 {
		t.Fatal("premise: checkpoint 850000 not found")
	}

	t.Run("planted tip over real history starts and is stamped", func(t *testing.T) {
		db := &identityStubDB{
			best: soakHeader(0x04, 900001), // planted through the gossip door
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{
				*chaincfg.MainNetParams.GenesisHash: genesisBH,
				cp.hash:                             {Hash: cp.hash, Height: cp.height},
			},
		}
		if err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("a correct datadir with a gossip-planted tip was refused: %v", err)
		}
		if _, ok := db.meta[string(paramsIdentityKey)]; !ok {
			t.Fatal("the accepted datadir was not stamped")
		}
	})

	// trivialOn builds n trivial-PoW headers on top of parent; the last is
	// the head.
	trivialOn := func(parent *tbcd.BlockHeader, n int, byHash map[chainhash.Hash]*tbcd.BlockHeader) *tbcd.BlockHeader {
		for i := range n {
			w := &wire.BlockHeader{
				Version: 1, PrevBlock: parent.Hash, Nonce: uint32(i),
				Bits: chaincfg.RegressionNetParams.PowLimitBits, Timestamp: time.Unix(1600000000, 0),
			}
			parent = bhFromWire(w, parent.Height+1)
			byHash[parent.Hash] = parent
		}
		return parent
	}

	// realBH stands in for a real-PoW header above the checkpoint (the mainnet
	// genesis header at a new height; only its proof of work matters here).
	realBH := *genesisBH
	realBH.Height = cp.height + 1000

	t.Run("indexed deep plant over real history starts and is stamped", func(t *testing.T) {
		byHash := map[chainhash.Hash]*tbcd.BlockHeader{
			*chaincfg.MainNetParams.GenesisHash: genesisBH,
			cp.hash:                             {Hash: cp.hash, Height: cp.height},
		}
		// The planter chooses the depth; one gossip message carries many
		// headers.
		plant := trivialOn(&realBH, 32, byHash)
		db := &identityStubDB{best: plant, byHash: byHash, utxo: plant, tx: plant, keystone: plant}
		if err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context()); err != nil {
			t.Fatalf("a correct datadir with an indexed gossip plant was refused: %v", err)
		}
		if _, ok := db.meta[string(paramsIdentityKey)]; !ok {
			t.Fatal("the accepted datadir was not stamped")
		}
	})

	t.Run("indexed trivial frontier without a checkpoint is refused", func(t *testing.T) {
		byHash := map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH}
		soak := trivialOn(&realBH, 1, byHash)
		db := &identityStubDB{best: &realBH, byHash: byHash, utxo: soak}
		err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context())
		if err == nil || !strings.Contains(err.Error(), "proof-of-work") {
			t.Fatalf("trivial frontier with no real history = %v, want a proof-of-work refusal", err)
		}
		if _, ok := db.meta[string(paramsIdentityKey)]; ok {
			t.Fatal("a refused datadir was stamped")
		}
	})

	t.Run("soak datadir is still refused, without advice to wipe", func(t *testing.T) {
		db := &identityStubDB{
			best:   soakHeader(0x05, 900001),
			byHash: map[chainhash.Hash]*tbcd.BlockHeader{*chaincfg.MainNetParams.GenesisHash: genesisBH},
		}
		err := mainnetIdentityServer(db).verifyDatadirIdentity(t.Context())
		if err == nil || !strings.Contains(err.Error(), "proof-of-work") {
			t.Fatalf("soak datadir = %v, want a proof-of-work refusal", err)
		}
		if strings.Contains(err.Error(), "wipe the datadir") {
			t.Fatalf("the refusal tells the operator to wipe the datadir: %v", err)
		}
	})
}
