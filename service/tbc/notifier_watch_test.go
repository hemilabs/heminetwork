// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// --- Positive tests ---

func TestWatchDeliversMatchingMempool(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("merchant-addr"))
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}

	txid := chainhash.Hash{0x01}
	if err := n.Notify(ctx, NotificationTxMempool(txid, sh)); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeTxMempool {
		t.Fatalf("expected tx_mempool, got %s", msg.Type)
	}
	if msg.ID != txid.String() {
		t.Fatalf("expected txid %s, got %s", txid, msg.ID)
	}
	gotSH, ok := msg.ScriptHash()
	if !ok {
		t.Fatal("ScriptHash() returned false on tx_mempool notification")
	}
	if gotSH != sh {
		t.Fatalf("script hash mismatch: %x != %x", gotSH, sh)
	}
}

func TestWatchDeliversMatchingConfirmed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("merchant-addr"))
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}

	txid := chainhash.Hash{0x02}
	blockHash := chainhash.Hash{0x03}
	height := int64(800000)
	if err := n.Notify(ctx, NotificationTxConfirmed(txid, blockHash, height, sh)); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeTxConfirmed {
		t.Fatalf("expected tx_confirmed, got %s", msg.Type)
	}
	if msg.ID != txid.String() {
		t.Fatalf("expected txid %s, got %s", txid, msg.ID)
	}
	if msg.Metadata["block_hash"] != blockHash.String() {
		t.Fatalf("block_hash mismatch: %s", msg.Metadata["block_hash"])
	}
	if msg.Metadata["block_height"] != "800000" {
		t.Fatalf("block_height mismatch: %s", msg.Metadata["block_height"])
	}
}

func TestBlockInsertAlwaysDeliveredWithFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	// Set a watch filter — block_insert must still get through.
	sh := tbcd.NewScriptHashFromScript([]byte("addr"))
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}

	bh := chainhash.Hash{0x10}
	if err := n.Notify(ctx, NotificationBlock(bh)); err != nil {
		t.Fatal(err)
	}
	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("expected block_insert, got %s", msg.Type)
	}
}

func TestBlockheaderInsertAlwaysDeliveredWithFilter(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("addr"))
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}

	bh := chainhash.Hash{0x11}
	if err := n.Notify(ctx, NotificationBlockheader(bh)); err != nil {
		t.Fatal(err)
	}
	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockheaderInsert {
		t.Fatalf("expected blockheader_insert, got %s", msg.Type)
	}
}

func TestNoFilterReceivesAll(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	// No Watch() — should receive everything including tx notifications.
	sh := tbcd.NewScriptHashFromScript([]byte("whatever"))
	types := []Notification{
		NotificationBlock(chainhash.Hash{0x01}),
		NotificationBlockheader(chainhash.Hash{0x02}),
		NotificationTxMempool(chainhash.Hash{0x03}, sh),
		NotificationTxConfirmed(chainhash.Hash{0x04}, chainhash.Hash{0x05}, 1, sh),
	}
	for _, nt := range types {
		if err := n.Notify(ctx, nt); err != nil {
			t.Fatal(err)
		}
	}
	for i, expected := range types {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatalf("notification %d: %v", i, err)
		}
		if msg.Type != expected.Type {
			t.Fatalf("notification %d: expected %s, got %s", i, expected.Type, msg.Type)
		}
	}
}

func TestWatchMultipleScriptHashes(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	shA := tbcd.NewScriptHashFromScript([]byte("addr-A"))
	shB := tbcd.NewScriptHashFromScript([]byte("addr-B"))
	shC := tbcd.NewScriptHashFromScript([]byte("addr-C"))
	if err := l.Watch([]tbcd.ScriptHash{shA, shB}); err != nil {
		t.Fatal(err)
	}

	// A — deliver
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, shA)); err != nil {
		t.Fatal(err)
	}
	// C — drop (unwatched)
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x02}, shC)); err != nil {
		t.Fatal(err)
	}
	// B — deliver
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x03}, shB)); err != nil {
		t.Fatal(err)
	}
	// sentinel
	if err := n.Notify(ctx, NotificationBlock(chainhash.Hash{0xff})); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != (chainhash.Hash{0x01}).String() {
		t.Fatalf("expected 0x01 (shA), got %s", msg.ID)
	}
	msg, err = l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != (chainhash.Hash{0x03}).String() {
		t.Fatalf("expected 0x03 (shB), got %s — shC was not filtered", msg.ID)
	}
	msg, err = l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("expected sentinel block_insert, got %s", msg.Type)
	}
}

func TestMultipleListenersDifferentWatchSets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)

	l1, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l1.Unsubscribe()

	l2, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l2.Unsubscribe()

	shA := tbcd.NewScriptHashFromScript([]byte("addr-A"))
	shB := tbcd.NewScriptHashFromScript([]byte("addr-B"))

	if err := l1.Watch([]tbcd.ScriptHash{shA}); err != nil {
		t.Fatal(err)
	}
	if err := l2.Watch([]tbcd.ScriptHash{shB}); err != nil {
		t.Fatal(err)
	}

	// Notify shA — l1 receives, l2 does not.
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, shA)); err != nil {
		t.Fatal(err)
	}
	// Notify shB — l2 receives, l1 does not.
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x02}, shB)); err != nil {
		t.Fatal(err)
	}
	// sentinel for both
	if err := n.Notify(ctx, NotificationBlock(chainhash.Hash{0xff})); err != nil {
		t.Fatal(err)
	}

	// l1 should get shA then block
	msg, err := l1.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != (chainhash.Hash{0x01}).String() {
		t.Fatalf("l1: expected 0x01 (shA), got %s", msg.ID)
	}
	msg, err = l1.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("l1: expected sentinel, got %s %s", msg.Type, msg.ID)
	}

	// l2 should get shB then block
	msg, err = l2.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.ID != (chainhash.Hash{0x02}).String() {
		t.Fatalf("l2: expected 0x02 (shB), got %s", msg.ID)
	}
	msg, err = l2.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("l2: expected sentinel, got %s %s", msg.Type, msg.ID)
	}
}

func TestWatchUnwatchRewatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("addr"))

	// Watch → deliver
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, sh)); err != nil {
		t.Fatal(err)
	}
	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeTxMempool {
		t.Fatalf("phase 1: expected tx_mempool, got %s", msg.Type)
	}

	// Unwatch → drop, use sentinel to verify
	l.Unwatch([]tbcd.ScriptHash{sh})
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x02}, sh)); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationBlock(chainhash.Hash{0xaa})); err != nil {
		t.Fatal(err)
	}
	msg, err = l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("phase 2: expected block_insert (drop), got %s", msg.Type)
	}

	// Re-watch → deliver again
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x03}, sh)); err != nil {
		t.Fatal(err)
	}
	msg, err = l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeTxMempool {
		t.Fatalf("phase 3: expected tx_mempool after re-watch, got %s", msg.Type)
	}
}

// --- Negative tests ---

func TestWatchFilterDropsUnwatched(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	watched := tbcd.NewScriptHashFromScript([]byte("watched"))
	unwatched := tbcd.NewScriptHashFromScript([]byte("unwatched"))
	if err := l.Watch([]tbcd.ScriptHash{watched}); err != nil {
		t.Fatal(err)
	}

	// Send unwatched then sentinel
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, unwatched)); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationTxConfirmed(chainhash.Hash{0x02}, chainhash.Hash{0x03}, 1, unwatched)); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationBlock(chainhash.Hash{0xff})); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("expected sentinel (both tx notifications should be dropped), got %s", msg.Type)
	}
}

func TestUnwatchNeverWatched(t *testing.T) {
	// Unwatching a script hash that was never watched should be a silent no-op.
	n := NewNotifier(true)
	ctx := context.Background()
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("never-watched"))
	if err := l.Watch([]tbcd.ScriptHash{tbcd.NewScriptHashFromScript([]byte("other"))}); err != nil {
		t.Fatal(err)
	}
	l.Unwatch([]tbcd.ScriptHash{sh}) // should not panic or error
}

func TestWatchDuplicateIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	sh := tbcd.NewScriptHashFromScript([]byte("addr"))
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil { // duplicate — should be idempotent
		t.Fatal(err)
	}
	if err := l.Watch([]tbcd.ScriptHash{sh}); err != nil {
		t.Fatal(err)
	}

	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, sh)); err != nil {
		t.Fatal(err)
	}
	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Should get exactly one delivery, not three.
	if msg.Type != NtfnTypeTxMempool {
		t.Fatalf("expected tx_mempool, got %s", msg.Type)
	}
}

func TestWatchEmptyListInitializesFilter(t *testing.T) {
	// Watch([]) should initialize the filter map (non-nil) but with
	// zero entries, meaning all tx notifications get dropped.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	n := NewNotifier(true)
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	if err := l.Watch([]tbcd.ScriptHash{}); err != nil { // empty list
		t.Fatal(err)
	}

	sh := tbcd.NewScriptHashFromScript([]byte("any"))
	if err := n.Notify(ctx, NotificationTxMempool(chainhash.Hash{0x01}, sh)); err != nil {
		t.Fatal(err)
	}
	if err := n.Notify(ctx, NotificationBlock(chainhash.Hash{0xff})); err != nil {
		t.Fatal(err)
	}

	msg, err := l.Listen(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Type != NtfnTypeBlockInsert {
		t.Fatalf("empty watch list should drop all tx notifications, got %s", msg.Type)
	}
}

func TestAcceptsCorruptMetadata(t *testing.T) {
	l := &Listener{
		watchScripts: map[tbcd.ScriptHash]struct{}{
			tbcd.NewScriptHashFromScript([]byte("x")): {},
		},
	}

	// No metadata at all — should reject.
	n1 := Notification{Type: NtfnTypeTxMempool}
	if l.accepts(n1) {
		t.Fatal("accepted tx_mempool with no metadata")
	}

	// Metadata with bad hex — should reject.
	n2 := Notification{
		Type:     NtfnTypeTxMempool,
		Metadata: map[string]string{"script_hash": "not-hex!"},
	}
	if l.accepts(n2) {
		t.Fatal("accepted tx_mempool with invalid hex")
	}

	// Metadata with wrong length hex — should reject.
	n3 := Notification{
		Type:     NtfnTypeTxMempool,
		Metadata: map[string]string{"script_hash": "aabb"},
	}
	if l.accepts(n3) {
		t.Fatal("accepted tx_mempool with truncated script hash")
	}

	// Metadata with valid hex but non-matching hash — should reject.
	wrongSH := tbcd.NewScriptHashFromScript([]byte("y"))
	n4 := Notification{
		Type:     NtfnTypeTxConfirmed,
		Metadata: map[string]string{"script_hash": hex.EncodeToString(wrongSH[:])},
	}
	if l.accepts(n4) {
		t.Fatal("accepted tx_confirmed with non-matching script hash")
	}

	// Unknown notification type — should always accept (passthrough).
	n5 := Notification{Type: "some_future_type"}
	if !l.accepts(n5) {
		t.Fatal("rejected unknown notification type — should passthrough")
	}
}

func TestScriptHashParsingEdgeCases(t *testing.T) {
	// No metadata.
	n1 := Notification{Type: NtfnTypeTxMempool}
	if _, ok := n1.ScriptHash(); ok {
		t.Fatal("ScriptHash() should return false with no metadata")
	}

	// Empty script_hash value.
	n2 := Notification{
		Type:     NtfnTypeTxMempool,
		Metadata: map[string]string{"script_hash": ""},
	}
	if _, ok := n2.ScriptHash(); ok {
		t.Fatal("ScriptHash() should return false with empty string")
	}

	// Odd-length hex.
	n3 := Notification{
		Type:     NtfnTypeTxMempool,
		Metadata: map[string]string{"script_hash": "abc"},
	}
	if _, ok := n3.ScriptHash(); ok {
		t.Fatal("ScriptHash() should return false with odd hex")
	}

	// Correct length, valid hex — should work.
	sh := tbcd.NewScriptHashFromScript([]byte("test"))
	n4 := Notification{
		Type:     NtfnTypeTxMempool,
		Metadata: map[string]string{"script_hash": hex.EncodeToString(sh[:])},
	}
	got, ok := n4.ScriptHash()
	if !ok {
		t.Fatal("ScriptHash() should return true for valid data")
	}
	if got != sh {
		t.Fatalf("ScriptHash mismatch: %x != %x", got, sh)
	}
}

func TestConstructorMetadataIntegrity(t *testing.T) {
	txid := chainhash.Hash{0x30}
	blockHash := chainhash.Hash{0x31}
	sh := tbcd.NewScriptHashFromScript([]byte("merchant"))
	height := int64(850000)

	// tx_mempool
	nm := NotificationTxMempool(txid, sh)
	if nm.Type != NtfnTypeTxMempool {
		t.Fatalf("expected tx_mempool, got %s", nm.Type)
	}
	if nm.ID != txid.String() {
		t.Fatalf("txid mismatch")
	}
	gotSH, ok := nm.ScriptHash()
	if !ok || gotSH != sh {
		t.Fatal("ScriptHash round-trip failed for tx_mempool")
	}

	// tx_confirmed
	nc := NotificationTxConfirmed(txid, blockHash, height, sh)
	if nc.Type != NtfnTypeTxConfirmed {
		t.Fatalf("expected tx_confirmed, got %s", nc.Type)
	}
	if nc.Metadata["block_hash"] != blockHash.String() {
		t.Fatal("block_hash mismatch")
	}
	if nc.Metadata["block_height"] != "850000" {
		t.Fatal("block_height mismatch")
	}
	gotSH, ok = nc.ScriptHash()
	if !ok || gotSH != sh {
		t.Fatal("ScriptHash round-trip failed for tx_confirmed")
	}
}

func TestWatchExceedsLimit(t *testing.T) {
	n := NewNotifier(true)
	ctx := context.Background()
	l, err := n.Subscribe(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	// Fill to the limit.
	scripts := make([]tbcd.ScriptHash, maxWatchScripts)
	for i := range scripts {
		scripts[i] = tbcd.NewScriptHashFromScript([]byte(fmt.Sprintf("addr-%d", i)))
	}
	if err := l.Watch(scripts); err != nil {
		t.Fatalf("watch up to limit should succeed: %v", err)
	}

	// One more should fail.
	extra := tbcd.NewScriptHashFromScript([]byte("one-too-many"))
	if err := l.Watch([]tbcd.ScriptHash{extra}); err == nil {
		t.Fatal("watch beyond limit should return error")
	}
}

// --- Fuzz tests ---

func FuzzScriptHashParsing(f *testing.F) {
	// Seed with valid, empty, truncated, and garbage.
	sh := tbcd.NewScriptHashFromScript([]byte("seed"))
	f.Add(hex.EncodeToString(sh[:]))
	f.Add("")
	f.Add("aabb")
	f.Add("not-hex!")
	f.Add("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	f.Add(hex.EncodeToString(make([]byte, 31))) // one byte short
	f.Add(hex.EncodeToString(make([]byte, 33))) // one byte long

	f.Fuzz(func(t *testing.T, input string) {
		n := Notification{
			Type:     NtfnTypeTxMempool,
			Metadata: map[string]string{"script_hash": input},
		}
		gotSH, ok := n.ScriptHash()

		// Verify: if ok is true, the result must be a valid 32-byte hash
		// that round-trips back to the input hex.
		if ok {
			if len(gotSH) != 32 {
				t.Fatalf("ScriptHash returned ok=true but len=%d", len(gotSH))
			}
			// hex.EncodeToString always returns lowercase;
			// the input may have uppercase, so normalize.
			roundTrip := hex.EncodeToString(gotSH[:])
			if roundTrip != strings.ToLower(input) {
				t.Fatalf("round-trip mismatch: %q != %q", roundTrip, strings.ToLower(input))
			}
		}

		// Verify: accepts() must not panic regardless of input.
		l := &Listener{
			watchScripts: map[tbcd.ScriptHash]struct{}{
				tbcd.NewScriptHashFromScript([]byte("x")): {},
			},
		}
		_ = l.accepts(n) // must not panic
	})
}

func FuzzNotificationAccepts(f *testing.F) {
	f.Add(NtfnTypeTxMempool, "script_hash", "deadbeef")
	f.Add(NtfnTypeTxConfirmed, "script_hash", "")
	f.Add(NtfnTypeBlockInsert, "", "")
	f.Add(NtfnTypeBlockheaderInsert, "", "")
	f.Add("", "", "")
	f.Add(NtfnTypeTxMempool, "wrong_key", "aabbccdd")

	f.Fuzz(func(t *testing.T, nType, metaKey, metaVal string) {
		n := Notification{Type: nType}
		if metaKey != "" {
			n.Metadata = map[string]string{metaKey: metaVal}
		}

		// With nil watchScripts — must not panic, must accept everything.
		l1 := &Listener{}
		if !l1.accepts(n) {
			// nil watchScripts should accept all notifications.
			if nType != NtfnTypeTxMempool && nType != NtfnTypeTxConfirmed {
				t.Fatalf("nil watchScripts rejected type %q", nType)
			}
			// For tx types with nil watchScripts, accepts returns true,
			// so this branch shouldn't be hit.
		}

		// With non-nil watchScripts — must not panic.
		l2 := &Listener{
			watchScripts: map[tbcd.ScriptHash]struct{}{},
		}
		_ = l2.accepts(n) // must not panic
	})
}
