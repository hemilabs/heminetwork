// Copyright (c) 2024-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// M3 test-robustness round, heminetwork side.
//
// Mutation matrix for MaxAddressLength against the four existing tests, each run individually:
//
//	value    killed  by
//	    90    2/4    TestMaxAddressLengthCannotRejectARealAddress, TestMaxAddressLengthConsensusFloor
//	   129    2/4    (same two)
//	   130    0/4
//	  1024    0/4
//	 1<<20    0/4    <-- NOTHING. There is no ceiling assertion anywhere on this side.
//
// Two gaps follow. Both are covered below.
//
//  1. TOO HIGH IS COMPLETELY UNGUARDED. MaxAddressLength's own doc comment says what it is for: the
//     address-taking Server methods are reached from the tbcapi websocket, which defaults to
//     localhost:8082, is unauthenticated, has no rate limiting, and spawns a goroutine per message.
//     A 1 MiB cap there restores exactly the O(n^2) CPU exhaustion the constant exists to stop, and
//     the package notices nothing.
//
//  2. TOO LOW IS GUARDED ONLY BY RESTATEMENTS OF THE CONSTANT. Both killers assert
//     `130 <= MaxAddressLength` -- one via a list entry, one directly. Neither ever calls
//     BalanceByAddress with a long valid address, so a change that lowers the constant AND edits the
//     guards (which is what a "tighten to the bech32 limit" PR looks like) passes.
package tbc

import (
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
)

// m3DecodableAddresses returns strings btcutil.DecodeAddress ACCEPTS for net, derived from btcutil's
// own constructors -- never from MaxAddressLength. That is what makes the tests below survive a
// change that edits the constant and its guards together.
func m3DecodableAddresses(t *testing.T, net *chaincfg.Params) []string {
	t.Helper()
	p20 := make([]byte, 20)
	p32 := make([]byte, 32)
	for i := range p20 {
		p20[i] = byte(i + 1)
	}
	for i := range p32 {
		p32[i] = byte(i + 1)
	}
	var cands []string
	if a, e := btcutil.NewAddressPubKeyHash(p20, net); e == nil {
		cands = append(cands, a.EncodeAddress())
	}
	if a, e := btcutil.NewAddressScriptHashFromHash(p20, net); e == nil {
		cands = append(cands, a.EncodeAddress())
	}
	if a, e := btcutil.NewAddressWitnessPubKeyHash(p20, net); e == nil {
		cands = append(cands, a.EncodeAddress())
	}
	if a, e := btcutil.NewAddressWitnessScriptHash(p32, net); e == nil {
		cands = append(cands, a.EncodeAddress())
	}
	if a, e := btcutil.NewAddressTaproot(p32, net); e == nil {
		cands = append(cands, a.EncodeAddress())
	}
	// The two hex-pubkey lengths btcutil gates on, as a real secp256k1 point so they truly decode.
	// The 130-character form is the longest string DecodeAddress accepts at all -- measured across
	// mainnet, testnet3, regtest, simnet and signet -- and is the first thing a lowered cap breaks.
	cands = append(cands,
		"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
		"0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"+
			"483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")

	var out []string
	for _, c := range cands {
		if _, err := btcutil.DecodeAddress(c, net); err == nil {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		t.Fatal("no decodable address forms could be constructed")
	}
	return out
}

// TestM3AddressCapNeverRejectsADecodableAddress is the BEHAVIOURAL floor guard.
//
// The existing floor guards assert `130 <= MaxAddressLength`. This one asserts the consequence
// instead, and mentions MaxAddressLength in no assertion: for every address btcutil decodes,
// BalanceByAddress and UtxosByAddress must not refuse it for being too long.
//
// Why this matters more here than the error text suggests: op-geth's 0x40 btcBalAddr maps ANY error
// from BalanceByAddress -- including "address too long" -- to (nil, nil), which is a CALL that
// SUCCEEDS with empty returndata. Solidity reads that as a balance of zero. So a too-low value in
// this file does not surface as an error anywhere; it surfaces as the wrong number, on every node,
// with nothing to disagree about.
//
// The server has no database, so an address that gets PAST the length check panics further down in
// BalanceByScriptHash. That panic is the SUCCESS signal here and is recovered; what is asserted is
// that no "too long" rejection is returned.
func TestM3AddressCapNeverRejectsADecodableAddress(t *testing.T) {
	net := &chaincfg.RegressionNetParams
	s := &Server{cfg: &Config{}, chainParams: net}

	for _, addr := range m3DecodableAddresses(t, net) {
		if _, err := btcutil.DecodeAddress(addr, net); err != nil {
			t.Fatalf("premise: %q must decode: %v", addr, err)
		}

		for _, tc := range []struct {
			name string
			call func() error
		}{
			{"BalanceByAddress", func() error {
				_, err := s.BalanceByAddress(t.Context(), addr)
				return err
			}},
			{"UtxosByAddress", func() error {
				_, err := s.UtxosByAddress(t.Context(), false, addr, 0, 10)
				return err
			}},
		} {
			err := m3RecoverErr(tc.call)
			if err != nil && strings.Contains(err.Error(), "too long") {
				t.Fatalf("%s REFUSED a %d-character address that btcutil decodes, for being too "+
					"long (MaxAddressLength = %d).\n\n"+
					"This is not a local tightening. op-geth's 0x40 precompile hands its raw "+
					"address string to this method and maps any error to a SUCCESSFUL EMPTY CALL, "+
					"which Solidity reads as BALANCE ZERO for an address that may hold funds. "+
					"Nothing reverts, nothing logs, and every node does it identically -- so there "+
					"is no disagreement for Holocene to surface. The chain agrees on the wrong "+
					"value.\n\nerror: %v",
					tc.name, len(addr), MaxAddressLength, err)
			}
		}
	}
}

// m3RecoverErr runs fn, converting a panic into a nil error. A panic means the call got past the
// length check and died in the absent database, which is exactly what this file wants to see.
func m3RecoverErr(fn func() error) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = nil
		}
	}()
	return fn()
}

// TestM3AddressCapBoundsDecodeCost is the CEILING guard, which did not exist.
//
// Nothing in this package fails when MaxAddressLength is raised -- verified at 1024 and at 1<<20,
// where all four existing tests pass. That is the whole DoS property going unguarded on the surface
// the constant's doc comment identifies as the reason it exists: an unauthenticated, unthrottled
// websocket on localhost:8082 that spawns a goroutine per message.
//
// This measures the real cost at the cap rather than asserting a number, so it scales with the
// constant and no value can hide from it. Measured against the pinned btcutil: 200 chars = ~3.5us,
// 32 KiB = ~5.5ms, 1 MiB = ~4.6s, with cost growing as n^2 (measured ratio 4.06 per doubling).
func TestM3AddressCapBoundsDecodeCost(t *testing.T) {
	// One request must not buy more than a millisecond of CPU on an unauthenticated socket. At the
	// shipped 200 this is ~3.5us, so there is ~280x headroom -- not flaky, but any value above
	// roughly 3.4k characters fails.
	const budgetPerRequest = time.Millisecond

	// Fail legibly rather than spending minutes measuring an absurd value.
	if MaxAddressLength > 1<<16 {
		t.Fatalf("MaxAddressLength is %d. base58 decoding is O(n^2); at this size a single "+
			"unauthenticated tbcapi request costs milliseconds of CPU and the listener has no rate "+
			"limit and spawns a goroutine per message.", MaxAddressLength)
	}

	worst := strings.Repeat("z", MaxAddressLength)
	net := &chaincfg.RegressionNetParams

	best := time.Duration(1<<62 - 1)
	for i := 0; i < 9; i++ {
		const reps = 200
		start := time.Now()
		for j := 0; j < reps; j++ {
			_, _ = btcutil.DecodeAddress(worst, net)
		}
		if d := time.Since(start) / reps; d < best {
			best = d
		}
	}

	t.Logf("M3: MaxAddressLength=%d -> %v of base58 decode per address-taking request",
		MaxAddressLength, best)

	if best >= budgetPerRequest {
		t.Fatalf("at MaxAddressLength = %d one address-taking request costs %v of base58 decoding, "+
			"over the %v budget. BalanceByAddress and UtxosByAddress are reachable from the tbcapi "+
			"websocket, which defaults to localhost:8082, is unauthenticated, has no rate limiting "+
			"and spawns a goroutine per message -- so this is CPU exhaustion, not a slow query.",
			MaxAddressLength, best, budgetPerRequest)
	}
}

// TestM3AddressCapRejectsBeforeDecoding pins that the over-length rejection is reported as such
// on BOTH methods.
//
// TestMaxAddressLengthBoundsTheDecoder already checks the "too long" text. What it does not check is
// that the rejection happens BEFORE the decoder -- which is the entire point, since a check placed
// after btcutil.DecodeAddress would return the same message having already paid the O(n^2) cost.
// This measures: a 256 KiB address must be refused in microseconds, not the ~290ms its decode costs.
func TestM3AddressCapRejectsBeforeDecoding(t *testing.T) {
	s := &Server{cfg: &Config{}, chainParams: &chaincfg.RegressionNetParams}
	huge := strings.Repeat("z", 256*1024)

	// A 256 KiB decode measures ~290ms against the pinned btcutil. Anything under 10ms proves the
	// string never reached the decoder; the two are three orders of magnitude apart, so this is a
	// decisive discriminator rather than a tight timing assertion.
	const bound = 10 * time.Millisecond

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"BalanceByAddress", func() error { _, err := s.BalanceByAddress(t.Context(), huge); return err }},
		{"UtxosByAddress", func() error {
			_, err := s.UtxosByAddress(t.Context(), false, huge, 0, 10)
			return err
		}},
	} {
		start := time.Now()
		err := tc.call()
		elapsed := time.Since(start)

		if err == nil || !strings.Contains(err.Error(), "too long") {
			t.Fatalf("%s did not refuse a %d-byte address as too long: %v", tc.name, len(huge), err)
		}
		if elapsed >= bound {
			t.Fatalf("%s took %v to refuse a %d-byte address. The bound must be applied BEFORE "+
				"btcutil.DecodeAddress: rejecting afterwards returns the same message having "+
				"already paid the O(n^2) decode, which is the cost this constant exists to avoid.",
				tc.name, elapsed, len(huge))
		}
	}
}
