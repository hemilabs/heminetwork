// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

// N2 mutation-sweep gap closures for service/tbc.
//
// Each test exists because a specific production mutation left the ENTIRE package green.

import (
	"errors"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

// TestN2RejectNilBlockElementsRefusesANilBlock closes a guard that had ZERO coverage.
//
// SURVIVING MUTANTS THIS KILLS: N22 (delete the `blk == nil` arm), N23 (return nil instead of the
// error -- a silent swallow), N24 (return a different sentinel). All three left the package green.
//
// The arm is not decoration. rejectNilBlockElements is the FIRST statement of Server.BlockInsert,
// which is the exported entry point op-geth's L2 gossip ingest writes through, and the very next
// thing the function does is `range blk.Transactions`. Deleting the arm turns Server.BlockInsert(ctx,
// nil) from a returned error into a nil-pointer dereference; heminetwork's block handlers run on
// bare goroutines with no recover, so that is process death rather than a failed request.
func TestN2RejectNilBlockElementsRefusesANilBlock(t *testing.T) {
	// Premise: without the arm, the next statement really is lethal. Assert it rather than claim it.
	panicked := func() (p bool) {
		defer func() {
			if r := recover(); r != nil {
				p = true
			}
		}()
		var blk *wire.MsgBlock
		for range blk.Transactions { // deliberately dereferencing nil
			break
		}
		return false
	}()
	if !panicked {
		t.Skip("ranging over a nil *wire.MsgBlock's Transactions no longer panics; re-derive this " +
			"guard rather than deleting it")
	}

	err := rejectNilBlockElements(nil)
	if err == nil {
		t.Fatal("rejectNilBlockElements(nil) returned no error. It is the first statement of " +
			"Server.BlockInsert, and the statement after it dereferences the block. A nil block " +
			"reaching an exported write path is a nil-pointer panic on a goroutine with no recover.")
	}
	if !errors.Is(err, ErrNilElement) {
		t.Fatalf("rejectNilBlockElements(nil) returned %v, which is not ErrNilElement. Callers "+
			"discriminate on that sentinel -- handleTxBroadcastRequest and handleBlockInsertRequest "+
			"both give it its own arm so a client error is not logged as a server error.", err)
	}

	// The reachable path, not just the helper: Server.BlockInsert must answer rather than die.
	// The guard is its first statement, so a zero-value Server never touches its store here.
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("Server.BlockInsert(ctx, nil) PANICKED (%v) instead of returning an error. "+
					"This is the exported write path op-geth's gossip ingest uses.", r)
			}
		}()
		if _, err := (&Server{}).BlockInsert(t.Context(), nil); err == nil {
			t.Fatal("Server.BlockInsert(ctx, nil) accepted a nil block")
		} else if !errors.Is(err, ErrNilElement) {
			t.Fatalf("Server.BlockInsert(ctx, nil) returned %v, want ErrNilElement", err)
		}
	}()
}

// TestN2AddressCapBoundaryIsInclusive pins the address cap's boundary on BOTH address-taking Server
// methods.
//
// SURVIVING MUTANTS THIS KILLS: N14 and N15 (`len(encodedAddress) > MaxAddressLength` -> `>=` at
// each of the two call sites).
//
// The cap is documented as "bounds the encoded Bitcoin address": a string of exactly
// MaxAddressLength is INSIDE the bound and must reach the decoder, where it fails on its own merits.
// The existing coverage only feeds the cap a 256 KiB string, which both the correct and the
// off-by-one form reject, so the boundary itself was free. op-geth pins the identical boundary on
// its side (TestAddressCapBoundaryIsInclusive); this closes the asymmetry.
func TestN2AddressCapBoundaryIsInclusive(t *testing.T) {
	s := &Server{cfg: &Config{}, chainParams: &chaincfg.RegressionNetParams}

	atCap := strings.Repeat("z", MaxAddressLength)
	overCap := strings.Repeat("z", MaxAddressLength+1)

	for _, tc := range []struct {
		name string
		call func(string) error
	}{
		{"BalanceByAddress", func(a string) error { _, err := s.BalanceByAddress(t.Context(), a); return err }},
		{"UtxosByAddress", func(a string) error {
			_, err := s.UtxosByAddress(t.Context(), false, a, 0, 10)
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.call(atCap)
			if err == nil {
				t.Fatalf("%s ACCEPTED a %d-character address; premise failure, it is not a decodable "+
					"Bitcoin address", tc.name, len(atCap))
			}
			if strings.Contains(err.Error(), "too long") {
				t.Fatalf("%s rejected an address of exactly MaxAddressLength (%d) as TOO LONG: %v.\n\n"+
					"The cap is inclusive by construction -- the constant is the largest accepted "+
					"length, not the smallest rejected one -- and an off-by-one here silently narrows "+
					"the accepted set on a consensus-adjacent read path while every existing test, "+
					"which only ever feeds it a 256 KiB string, stays green.",
					tc.name, MaxAddressLength, err)
			}

			err = tc.call(overCap)
			if err == nil || !strings.Contains(err.Error(), "too long") {
				t.Fatalf("%s did not refuse a %d-character address as too long: %v. The bound must "+
					"still fire one character past the cap, or it is not a bound at all.",
					tc.name, len(overCap), err)
			}
		})
	}
}
