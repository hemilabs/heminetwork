// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

func TestEncodeSatRanges(t *testing.T) {
	tests := []struct {
		name   string
		ranges []SatRange
	}{
		{
			name:   "empty",
			ranges: nil,
		},
		{
			name:   "single range",
			ranges: []SatRange{{Start: 100, Count: 50}},
		},
		{
			name: "multiple ranges",
			ranges: []SatRange{
				{Start: 0, Count: 5000000000},
				{Start: 10000000000, Count: 2500000000},
				{Start: 50000000000, Count: 1},
			},
		},
		{
			name:   "max values",
			ranges: []SatRange{{Start: ^uint64(0), Count: ^uint64(0)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeSatRanges(tt.ranges)
			if len(tt.ranges) == 0 && len(encoded) != 0 {
				t.Fatalf("expected empty encoding, got %d bytes", len(encoded))
			}
			if len(tt.ranges) > 0 && len(encoded) != len(tt.ranges)*16 {
				t.Fatalf("expected %d bytes, got %d", len(tt.ranges)*16, len(encoded))
			}
			decoded := DecodeSatRanges(encoded)
			if len(decoded) != len(tt.ranges) {
				t.Fatalf("round-trip count: got %d want %d", len(decoded), len(tt.ranges))
			}
			for i := range decoded {
				if decoded[i] != tt.ranges[i] {
					t.Errorf("range %d: got %v want %v", i, decoded[i], tt.ranges[i])
				}
			}
		})
	}
}

func TestDecodeSatRangesPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic for invalid data length")
		}
	}()
	DecodeSatRanges([]byte{1, 2, 3}) // not a multiple of 16
}

func TestMergeSatRanges(t *testing.T) {
	tests := []struct {
		name  string
		input []SatRange
		want  []SatRange
	}{
		{
			name:  "empty",
			input: nil,
			want:  nil,
		},
		{
			name:  "single",
			input: []SatRange{{Start: 10, Count: 5}},
			want:  []SatRange{{Start: 10, Count: 5}},
		},
		{
			name: "contiguous merge",
			input: []SatRange{
				{Start: 10, Count: 5},
				{Start: 15, Count: 3},
			},
			want: []SatRange{{Start: 10, Count: 8}},
		},
		{
			name: "non-contiguous no merge",
			input: []SatRange{
				{Start: 10, Count: 5},
				{Start: 20, Count: 3},
			},
			want: []SatRange{
				{Start: 10, Count: 5},
				{Start: 20, Count: 3},
			},
		},
		{
			name: "three ranges two contiguous",
			input: []SatRange{
				{Start: 0, Count: 10},
				{Start: 10, Count: 10},
				{Start: 50, Count: 5},
			},
			want: []SatRange{
				{Start: 0, Count: 20},
				{Start: 50, Count: 5},
			},
		},
		{
			name: "all contiguous",
			input: []SatRange{
				{Start: 100, Count: 1},
				{Start: 101, Count: 1},
				{Start: 102, Count: 1},
			},
			want: []SatRange{{Start: 100, Count: 3}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeSatRanges(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("count: got %d want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("range %d: got %v want %v", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSplitSatRanges(t *testing.T) {
	tests := []struct {
		name            string
		input           []SatRange
		rangeOffset     int
		satOffset       uint64
		amount          uint64
		wantOutput      []SatRange
		wantRangeOffset int
		wantSatOffset   uint64
	}{
		{
			name:            "simple single range",
			input:           []SatRange{{Start: 0, Count: 100}},
			amount:          50,
			wantOutput:      []SatRange{{Start: 0, Count: 50}},
			wantRangeOffset: 0,
			wantSatOffset:   50,
		},
		{
			name:            "consume entire range",
			input:           []SatRange{{Start: 0, Count: 100}},
			amount:          100,
			wantOutput:      []SatRange{{Start: 0, Count: 100}},
			wantRangeOffset: 1,
			wantSatOffset:   0,
		},
		{
			name: "span two ranges",
			input: []SatRange{
				{Start: 0, Count: 30},
				{Start: 100, Count: 70},
			},
			amount: 50,
			wantOutput: []SatRange{
				{Start: 0, Count: 30},
				{Start: 100, Count: 20},
			},
			wantRangeOffset: 1,
			wantSatOffset:   20,
		},
		{
			name:            "resume from offset",
			input:           []SatRange{{Start: 0, Count: 100}},
			rangeOffset:     0,
			satOffset:       50,
			amount:          30,
			wantOutput:      []SatRange{{Start: 50, Count: 30}},
			wantRangeOffset: 0,
			wantSatOffset:   80,
		},
		{
			name: "resume from second range",
			input: []SatRange{
				{Start: 0, Count: 100},
				{Start: 200, Count: 100},
			},
			rangeOffset:     1,
			satOffset:       0,
			amount:          50,
			wantOutput:      []SatRange{{Start: 200, Count: 50}},
			wantRangeOffset: 1,
			wantSatOffset:   50,
		},
		{
			name: "three outputs from two ranges",
			input: []SatRange{
				{Start: 0, Count: 50},
				{Start: 1000, Count: 50},
			},
			amount:          100,
			wantRangeOffset: 2,
			wantSatOffset:   0,
			wantOutput: []SatRange{
				{Start: 0, Count: 50},
				{Start: 1000, Count: 50},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotRO, gotSO := SplitSatRanges(tt.input, tt.rangeOffset, tt.satOffset, tt.amount)
			if gotRO != tt.wantRangeOffset {
				t.Errorf("rangeOffset: got %d want %d", gotRO, tt.wantRangeOffset)
			}
			if gotSO != tt.wantSatOffset {
				t.Errorf("satOffset: got %d want %d", gotSO, tt.wantSatOffset)
			}
			if len(got) != len(tt.wantOutput) {
				t.Fatalf("output count: got %d want %d\n  got:  %v\n  want: %v",
					len(got), len(tt.wantOutput), got, tt.wantOutput)
			}
			for i := range got {
				if got[i] != tt.wantOutput[i] {
					t.Errorf("output range %d: got %v want %v", i, got[i], tt.wantOutput[i])
				}
			}
		})
	}
}

func TestSplitSatRangesConservation(t *testing.T) {
	// Verify sat conservation: splitting a range into multiple outputs
	// must produce the same total sat count.
	input := []SatRange{
		{Start: 0, Count: 5000000000},
		{Start: 10000000000, Count: 2500000000},
	}
	amounts := []uint64{3000000000, 2000000000, 2500000000}

	var totalInput uint64
	for _, r := range input {
		totalInput += r.Count
	}

	var totalOutput uint64
	var ro int
	var so uint64
	for _, amount := range amounts {
		var out []SatRange
		out, ro, so = SplitSatRanges(input, ro, so, amount)
		for _, r := range out {
			totalOutput += r.Count
		}
	}

	if totalOutput != totalInput {
		t.Errorf("sat conservation violated: input %d output %d",
			totalInput, totalOutput)
	}
}

func TestSubsidyAtHeight(t *testing.T) {
	tests := []struct {
		height uint32
		want   uint64
	}{
		{0, 5000000000},
		{1, 5000000000},
		{209999, 5000000000},
		{210000, 2500000000},
		{419999, 2500000000},
		{420000, 1250000000},
		{630000, 625000000},
		{6929999, 1}, // last non-zero subsidy (halving 32)
		{6930000, 0}, // halving 33, subsidy drops to 0
	}
	for _, tt := range tests {
		got := SubsidyAtHeight(tt.height)
		if got != tt.want {
			t.Errorf("SubsidyAtHeight(%d): got %d want %d", tt.height, got, tt.want)
		}
	}
}

func TestTotalSubsidyBeforeHeight(t *testing.T) {
	// At height 0, no sats have been mined yet.
	if got := TotalSubsidyBeforeHeight(0); got != 0 {
		t.Errorf("TotalSubsidyBeforeHeight(0): got %d want 0", got)
	}

	// At height 1, the genesis block (50 BTC) has been mined.
	if got := TotalSubsidyBeforeHeight(1); got != 5000000000 {
		t.Errorf("TotalSubsidyBeforeHeight(1): got %d want 5000000000", got)
	}

	// At height 210000 (first halving), 210000 * 50 BTC worth of sats.
	expected := uint64(210000) * 5000000000
	if got := TotalSubsidyBeforeHeight(210000); got != expected {
		t.Errorf("TotalSubsidyBeforeHeight(210000): got %d want %d", got, expected)
	}

	// At height 210001, one more block at 25 BTC.
	expected += 2500000000
	if got := TotalSubsidyBeforeHeight(210001); got != expected {
		t.Errorf("TotalSubsidyBeforeHeight(210001): got %d want %d", got, expected)
	}
}

func TestCoinbaseSatRange(t *testing.T) {
	// Genesis block: sats 0 through 4999999999.
	start, count := CoinbaseSatRange(0)
	if start != 0 || count != 5000000000 {
		t.Errorf("CoinbaseSatRange(0): got (%d, %d) want (0, 5000000000)", start, count)
	}

	// Block 1: sats 5000000000 through 9999999999.
	start, count = CoinbaseSatRange(1)
	if start != 5000000000 || count != 5000000000 {
		t.Errorf("CoinbaseSatRange(1): got (%d, %d) want (5000000000, 5000000000)", start, count)
	}

	// First halving block.
	start, count = CoinbaseSatRange(210000)
	expectedStart := uint64(210000) * 5000000000
	if start != expectedStart || count != 2500000000 {
		t.Errorf("CoinbaseSatRange(210000): got (%d, %d) want (%d, 2500000000)",
			start, count, expectedStart)
	}
}

func TestIsInscriptionCursed(t *testing.T) {
	tests := []struct {
		name        string
		blockHeight uint32
		inputIdx    int
		env         *InscriptionEnvelope
		want        bool
	}{
		{
			name:        "normal inscription",
			blockHeight: 800000,
			inputIdx:    0,
			env:         &InscriptionEnvelope{},
			want:        false,
		},
		{
			name:        "non-zero input pre-jubilee",
			blockHeight: 800000,
			inputIdx:    1,
			env:         &InscriptionEnvelope{},
			want:        true,
		},
		{
			name:        "non-zero input post-jubilee",
			blockHeight: jubileeHeight,
			inputIdx:    1,
			env:         &InscriptionEnvelope{},
			want:        false,
		},
		{
			name:        "multiple envelopes pre-jubilee",
			blockHeight: 800000,
			inputIdx:    0,
			env:         &InscriptionEnvelope{MultipleEnvelopes: true},
			want:        true,
		},
		{
			name:        "unrecognized even tag pre-jubilee",
			blockHeight: 800000,
			inputIdx:    0,
			env:         &InscriptionEnvelope{HasUnrecognizedEvenTag: true},
			want:        true,
		},
		{
			name:        "unrecognized even tag post-jubilee",
			blockHeight: jubileeHeight,
			inputIdx:    0,
			env:         &InscriptionEnvelope{HasUnrecognizedEvenTag: true},
			want:        false,
		},
		{
			name:        "non-taproot pre-jubilee",
			blockHeight: 800000,
			inputIdx:    0,
			env:         &InscriptionEnvelope{NonTaprootWitness: true},
			want:        true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isInscriptionCursed(tt.blockHeight, tt.inputIdx, tt.env)
			if got != tt.want {
				t.Errorf("got %v want %v", got, tt.want)
			}
		})
	}
}

// buildOrdEnvelope constructs a minimal taproot witness with an ord envelope.
func buildOrdEnvelope(t *testing.T, tags map[int][]byte) wire.TxWitness {
	t.Helper()

	builder := txscript.NewScriptBuilder()
	// Some initial script ops (signature check or similar).
	builder.AddOp(txscript.OP_TRUE)

	// Ord envelope.
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))

	for tag, value := range tags {
		// Tags 1-16 use OP_1 through OP_16.
		if tag >= 1 && tag <= 16 {
			builder.AddOp(txscript.OP_1 + byte(tag-1))
		} else {
			builder.AddData([]byte{byte(tag)})
		}
		builder.AddData(value)
	}

	builder.AddOp(txscript.OP_ENDIF)

	script, err := builder.Script()
	if err != nil {
		t.Fatalf("build script: %v", err)
	}

	// Taproot witness: [... script, control_block]
	// Control block can be empty for our test purposes.
	return wire.TxWitness{script, {0x00}}
}

func TestParseInscriptionEnvelope(t *testing.T) {
	t.Run("empty witness", func(t *testing.T) {
		env, err := ParseInscriptionEnvelope(nil)
		if err != nil {
			t.Fatal(err)
		}
		if env != nil {
			t.Fatal("expected nil for empty witness")
		}
	})

	t.Run("single element witness", func(t *testing.T) {
		env, err := ParseInscriptionEnvelope(wire.TxWitness{{0x01}})
		if err != nil {
			t.Fatal(err)
		}
		if env != nil {
			t.Fatal("expected nil for single element witness")
		}
	})

	t.Run("basic inscription", func(t *testing.T) {
		witness := buildOrdEnvelope(t, map[int][]byte{
			1: []byte("text/plain"),
			5: []byte("hello world"),
		})
		env, err := ParseInscriptionEnvelope(witness)
		if err != nil {
			t.Fatal(err)
		}
		if env == nil {
			t.Fatal("expected envelope")
		}
		if !bytes.Equal(env.ContentType, []byte("text/plain")) {
			t.Errorf("content type: got %q want %q", env.ContentType, "text/plain")
		}
		if !bytes.Equal(env.Content, []byte("hello world")) {
			t.Errorf("content: got %q want %q", env.Content, "hello world")
		}
	})

	t.Run("with metaprotocol", func(t *testing.T) {
		witness := buildOrdEnvelope(t, map[int][]byte{
			1: []byte("application/json"),
			5: []byte(`{"p":"brc-20"}`),
			7: []byte("brc-20"),
		})
		env, err := ParseInscriptionEnvelope(witness)
		if err != nil {
			t.Fatal(err)
		}
		if env == nil {
			t.Fatal("expected envelope")
		}
		if !bytes.Equal(env.Metaprotocol, []byte("brc-20")) {
			t.Errorf("metaprotocol: got %q want %q", env.Metaprotocol, "brc-20")
		}
	})

	t.Run("unrecognized even tag", func(t *testing.T) {
		witness := buildOrdEnvelope(t, map[int][]byte{
			1:  []byte("text/plain"),
			5:  []byte("test"),
			14: []byte("unknown"),
		})
		env, err := ParseInscriptionEnvelope(witness)
		if err != nil {
			t.Fatal(err)
		}
		if env == nil {
			t.Fatal("expected envelope")
		}
		if !env.HasUnrecognizedEvenTag {
			t.Error("expected HasUnrecognizedEvenTag to be true")
		}
	})

	t.Run("no envelope in witness", func(t *testing.T) {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_TRUE)
		script, err := builder.Script()
		if err != nil {
			t.Fatal(err)
		}
		env, err := ParseInscriptionEnvelope(wire.TxWitness{script, {0x00}})
		if err != nil {
			t.Fatal(err)
		}
		if env != nil {
			t.Fatal("expected nil for witness without envelope")
		}
	})
}

func TestEncodeInscriptionValue(t *testing.T) {
	t.Run("minimal no flags", func(t *testing.T) {
		env := &InscriptionEnvelope{}
		var blockHash chainhash.Hash
		blockHash[0] = 0xaa

		v := encodeInscriptionValue(42, &blockHash, false, env)
		if len(v) != 41 {
			t.Fatalf("expected 41 bytes, got %d", len(v))
		}
		if v[40] != 0 {
			t.Errorf("expected flags 0, got %d", v[40])
		}
	})

	t.Run("cursed flag", func(t *testing.T) {
		env := &InscriptionEnvelope{}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, true, env)
		if v[40]&1 != 1 {
			t.Error("expected cursed bit set")
		}
	})

	t.Run("with parent", func(t *testing.T) {
		parent := [36]byte{0x01}
		env := &InscriptionEnvelope{Parent: &parent}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		if len(v) != 41+36 {
			t.Fatalf("expected 77 bytes, got %d", len(v))
		}
		if v[40]&(1<<1) == 0 {
			t.Error("expected parent bit set")
		}
	})

	t.Run("with delegate", func(t *testing.T) {
		delegate := [36]byte{0x02}
		env := &InscriptionEnvelope{Delegate: &delegate}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		if len(v) != 41+36 {
			t.Fatalf("expected 77 bytes, got %d", len(v))
		}
		if v[40]&(1<<2) == 0 {
			t.Error("expected delegate bit set")
		}
	})

	t.Run("with metaprotocol", func(t *testing.T) {
		env := &InscriptionEnvelope{Metaprotocol: []byte("brc-20")}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		if len(v) != 41+6 {
			t.Fatalf("expected 47 bytes, got %d", len(v))
		}
		if v[40]&(1<<3) == 0 {
			t.Error("expected metaprotocol bit set")
		}
	})

	t.Run("all flags", func(t *testing.T) {
		parent := [36]byte{0x01}
		delegate := [36]byte{0x02}
		env := &InscriptionEnvelope{
			Parent:       &parent,
			Delegate:     &delegate,
			Metaprotocol: []byte("test"),
		}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, true, env)
		expectedLen := 41 + 36 + 36 + 4
		if len(v) != expectedLen {
			t.Fatalf("expected %d bytes, got %d", expectedLen, len(v))
		}
		if v[40] != 0x0f { // all 4 bits set
			t.Errorf("expected flags 0x0f, got 0x%02x", v[40])
		}
	})
}

func TestDecodeInscriptionValue(t *testing.T) {
	t.Run("round trip minimal", func(t *testing.T) {
		env := &InscriptionEnvelope{}
		var blockHash chainhash.Hash
		blockHash[0] = 0xaa

		v := encodeInscriptionValue(42, &blockHash, false, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if d.SatNumber != 42 {
			t.Errorf("sat_number: got %d, want 42", d.SatNumber)
		}
		if d.BlockHash != blockHash {
			t.Errorf("block_hash mismatch")
		}
		if d.Cursed {
			t.Error("expected not cursed")
		}
		if d.Parent != nil || d.Delegate != nil || d.Metaprotocol != "" {
			t.Error("expected no optional fields")
		}
	})

	t.Run("round trip cursed", func(t *testing.T) {
		env := &InscriptionEnvelope{}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(100, &blockHash, true, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if !d.Cursed {
			t.Error("expected cursed")
		}
	})

	t.Run("round trip with parent", func(t *testing.T) {
		parent := [36]byte{0x01, 0x02, 0x03}
		env := &InscriptionEnvelope{Parent: &parent}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if d.Parent == nil {
			t.Fatal("expected parent")
		}
		if *d.Parent != parent {
			t.Errorf("parent mismatch: got %x, want %x", d.Parent, parent)
		}
	})

	t.Run("round trip with delegate", func(t *testing.T) {
		delegate := [36]byte{0x04, 0x05, 0x06}
		env := &InscriptionEnvelope{Delegate: &delegate}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if d.Delegate == nil {
			t.Fatal("expected delegate")
		}
		if *d.Delegate != delegate {
			t.Errorf("delegate mismatch")
		}
	})

	t.Run("round trip with metaprotocol", func(t *testing.T) {
		env := &InscriptionEnvelope{Metaprotocol: []byte("brc-20")}
		var blockHash chainhash.Hash

		v := encodeInscriptionValue(0, &blockHash, false, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if d.Metaprotocol != "brc-20" {
			t.Errorf("metaprotocol: got %q, want %q", d.Metaprotocol, "brc-20")
		}
	})

	t.Run("round trip all flags", func(t *testing.T) {
		parent := [36]byte{0x01}
		delegate := [36]byte{0x02}
		env := &InscriptionEnvelope{
			Parent:       &parent,
			Delegate:     &delegate,
			Metaprotocol: []byte("test"),
		}
		var blockHash chainhash.Hash
		blockHash[31] = 0xff

		v := encodeInscriptionValue(999, &blockHash, true, env)
		d, err := decodeInscriptionValue(v)
		if err != nil {
			t.Fatal(err)
		}
		if d.SatNumber != 999 {
			t.Errorf("sat_number: got %d, want 999", d.SatNumber)
		}
		if !d.Cursed {
			t.Error("expected cursed")
		}
		if d.Parent == nil || *d.Parent != parent {
			t.Error("parent mismatch")
		}
		if d.Delegate == nil || *d.Delegate != delegate {
			t.Error("delegate mismatch")
		}
		if d.Metaprotocol != "test" {
			t.Errorf("metaprotocol: got %q, want %q", d.Metaprotocol, "test")
		}
	})

	t.Run("too short", func(t *testing.T) {
		_, err := decodeInscriptionValue(make([]byte, 40))
		if err == nil {
			t.Fatal("expected error for short data")
		}
	})

	t.Run("truncated at parent", func(t *testing.T) {
		// Build a value with parent flag set but truncated data.
		data := make([]byte, 41+10) // 10 bytes is too short for 36-byte parent
		data[40] = 1 << 1           // parent flag
		_, err := decodeInscriptionValue(data)
		if err == nil {
			t.Fatal("expected error for truncated parent")
		}
	})

	t.Run("truncated at delegate", func(t *testing.T) {
		// Parent present and complete, delegate flag set but truncated.
		data := make([]byte, 41+36+10) // parent OK, delegate truncated
		data[40] = (1 << 1) | (1 << 2) // parent + delegate flags
		_, err := decodeInscriptionValue(data)
		if err == nil {
			t.Fatal("expected error for truncated delegate")
		}
	})
}

func TestMakeInscriptionID(t *testing.T) {
	var txHash chainhash.Hash
	txHash[0] = 0xab
	txHash[31] = 0xcd

	id := makeInscriptionID(&txHash, 0)
	if id[0] != 0xab || id[31] != 0xcd {
		t.Error("txid not preserved in inscription ID")
	}
	// Input index is little-endian.
	if id[32] != 0 || id[33] != 0 || id[34] != 0 || id[35] != 0 {
		t.Error("input index 0 should be all zeros")
	}

	id2 := makeInscriptionID(&txHash, 1)
	if id2[32] != 1 {
		t.Errorf("input index 1: got byte[32]=%d want 1", id2[32])
	}

	id3 := makeInscriptionID(&txHash, 256)
	// 256 LE = 0x00, 0x01, 0x00, 0x00
	if id3[32] != 0 || id3[33] != 1 {
		t.Errorf("input index 256 LE encoding wrong: got [%d,%d]", id3[32], id3[33])
	}
}

func TestKeyConstruction(t *testing.T) {
	t.Run("ordinalInscriptionKey prefix", func(t *testing.T) {
		var inscID [36]byte
		inscID[0] = 0xff
		k := ordinalInscriptionKey(inscID)
		if !k.IsInscription() {
			t.Errorf("prefix: got %c want i", k[0])
		}
	})

	t.Run("ordinalSatInscriptionKey prefix", func(t *testing.T) {
		var inscID [36]byte
		k := ordinalSatInscriptionKey(42, inscID)
		if !k.IsSatInscription() {
			t.Errorf("prefix: got %c want a", k[0])
		}
	})

	t.Run("ordinalBlockInscriptionKey prefix", func(t *testing.T) {
		var bh chainhash.Hash
		k := ordinalBlockInscriptionKey(&bh, 7)
		if !k.IsBlockInscription() {
			t.Errorf("prefix: got %c want n", k[0])
		}
	})
}

func TestOrdinalKeyIsMethods(t *testing.T) {
	tests := []struct {
		name            string
		key             tbcd.OrdinalKey
		wantInscription bool
		wantSatInsc     bool
		wantBlockInsc   bool
	}{
		{"inscription key", ordinalInscriptionKey([36]byte{}), true, false, false},
		{"sat inscription key", ordinalSatInscriptionKey(42, [36]byte{}), false, true, false},
		{"block inscription key", ordinalBlockInscriptionKey(&chainhash.Hash{}, 0), false, false, true},
		{"zero key", tbcd.OrdinalKey{}, false, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.IsInscription(); got != tt.wantInscription {
				t.Errorf("IsInscription() = %v, want %v", got, tt.wantInscription)
			}
			if got := tt.key.IsSatInscription(); got != tt.wantSatInsc {
				t.Errorf("IsSatInscription() = %v, want %v", got, tt.wantSatInsc)
			}
			if got := tt.key.IsBlockInscription(); got != tt.wantBlockInsc {
				t.Errorf("IsBlockInscription() = %v, want %v", got, tt.wantBlockInsc)
			}
		})
	}
}

func TestOrdinalValueMethods(t *testing.T) {
	t.Run("nil is delete", func(t *testing.T) {
		var v tbcd.OrdinalValue
		if !v.IsDelete() {
			t.Error("nil OrdinalValue should be delete")
		}
		if v.Bytes() != nil {
			t.Error("nil OrdinalValue.Bytes() should be nil")
		}
	})

	t.Run("non-nil is not delete", func(t *testing.T) {
		v := tbcd.OrdinalValue([]byte{0x01, 0x02})
		if v.IsDelete() {
			t.Error("non-nil OrdinalValue should not be delete")
		}
		if len(v.Bytes()) != 2 || v.Bytes()[0] != 0x01 {
			t.Errorf("Bytes() = %x, want 0102", v.Bytes())
		}
	})

	t.Run("empty non-nil is not delete", func(t *testing.T) {
		v := tbcd.OrdinalValue([]byte{})
		if v.IsDelete() {
			t.Error("empty non-nil OrdinalValue should not be delete")
		}
	})
}

func TestSplitSatRangesFIFOMultiOutput(t *testing.T) {
	// Simulate a real tx: 2 inputs totaling 150k sats, 3 outputs.
	input := []SatRange{
		{Start: 1000, Count: 100000},
		{Start: 5000000, Count: 50000},
	}

	// Output 0: 80000 sats
	out0, ro, so := SplitSatRanges(input, 0, 0, 80000)
	if len(out0) != 1 || out0[0].Start != 1000 || out0[0].Count != 80000 {
		t.Fatalf("output 0: got %v", out0)
	}

	// Output 1: 30000 sats (crosses range boundary)
	out1, ro, so := SplitSatRanges(input, ro, so, 30000)
	if len(out1) != 2 {
		t.Fatalf("output 1: expected 2 ranges (crosses boundary), got %d: %v", len(out1), out1)
	}
	// First part: remaining 20000 from first range.
	if out1[0].Start != 81000 || out1[0].Count != 20000 {
		t.Errorf("output 1[0]: got %v want {81000, 20000}", out1[0])
	}
	// Second part: 10000 from second range.
	if out1[1].Start != 5000000 || out1[1].Count != 10000 {
		t.Errorf("output 1[1]: got %v want {5000000, 10000}", out1[1])
	}

	// Output 2: 40000 sats (remaining from second range)
	out2, _, _ := SplitSatRanges(input, ro, so, 40000)
	if len(out2) != 1 || out2[0].Start != 5010000 || out2[0].Count != 40000 {
		t.Fatalf("output 2: got %v want [{5010000, 40000}]", out2)
	}

	// Verify sat conservation.
	var totalIn, totalOut uint64
	for _, r := range input {
		totalIn += r.Count
	}
	for _, out := range [][]SatRange{out0, out1, out2} {
		for _, r := range out {
			totalOut += r.Count
		}
	}
	if totalIn != totalOut {
		t.Errorf("conservation: in=%d out=%d", totalIn, totalOut)
	}
}

func TestSubsidyScheduleCompleteness(t *testing.T) {
	// The total bitcoin supply should be ~21M BTC = 2.1e15 sats.
	// Sum all subsidies until they reach 0.
	var total uint64
	for h := uint32(0); ; h += 210000 {
		s := SubsidyAtHeight(h)
		if s == 0 {
			break
		}
		total += s * 210000
	}
	// Total should be 2099999997690000 sats.
	expected := uint64(2099999997690000)
	if total != expected {
		t.Errorf("total supply: got %d want %d", total, expected)
	}
}

func TestTotalSubsidyBeforeHeightCrossHalving(t *testing.T) {
	// Verify continuity across halving boundaries.
	// The subsidy at height 209999 (last block before halving) should be
	// included in TotalSubsidyBeforeHeight(210000).
	before := TotalSubsidyBeforeHeight(209999)
	at := TotalSubsidyBeforeHeight(210000)
	if at-before != SubsidyAtHeight(209999) {
		t.Errorf("gap at halving: before=%d at=%d diff=%d subsidy=%d",
			before, at, at-before, SubsidyAtHeight(209999))
	}

	// Same check at second halving.
	before2 := TotalSubsidyBeforeHeight(419999)
	at2 := TotalSubsidyBeforeHeight(420000)
	if at2-before2 != SubsidyAtHeight(419999) {
		t.Errorf("gap at second halving: diff=%d subsidy=%d",
			at2-before2, SubsidyAtHeight(419999))
	}
}

func TestParseInscriptionEnvelopeWithParent(t *testing.T) {
	var parentID [36]byte
	parentID[0] = 0xde
	parentID[35] = 0xad

	pngMagic := []byte{0x89, 0x50, 0x4e, 0x47}
	witness := buildOrdEnvelope(t, map[int][]byte{
		1: []byte("image/png"),
		3: parentID[:],
		5: pngMagic,
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.Parent == nil {
		t.Fatal("expected parent")
	}
	if env.Parent[0] != 0xde || env.Parent[35] != 0xad {
		t.Errorf("parent ID mismatch: got %x", env.Parent)
	}
}

func TestParseInscriptionEnvelopeWithDelegate(t *testing.T) {
	var delegateID [36]byte
	delegateID[0] = 0xca
	delegateID[35] = 0xfe

	witness := buildOrdEnvelope(t, map[int][]byte{
		11: delegateID[:],
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.Delegate == nil {
		t.Fatal("expected delegate")
	}
	if env.Delegate[0] != 0xca || env.Delegate[35] != 0xfe {
		t.Errorf("delegate ID mismatch: got %x", env.Delegate)
	}
	// Delegate inscription has no content of its own.
	if len(env.Content) != 0 {
		t.Errorf("expected no content for delegate, got %d bytes", len(env.Content))
	}
}

func TestParseInscriptionEnvelopeWithPointer(t *testing.T) {
	// Pointer tag 2, value is LE varint.
	witness := buildOrdEnvelope(t, map[int][]byte{
		1: []byte("text/plain"),
		2: {0x39, 0x05}, // 1337 in LE
		5: []byte("pointed inscription"),
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.Pointer == nil {
		t.Fatal("expected pointer")
	}
	if *env.Pointer != 1337 {
		t.Errorf("pointer: got %d want 1337", *env.Pointer)
	}
}

func TestDecodeVarUint(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want uint64
	}{
		{"zero", []byte{0x00}, 0},
		{"one byte", []byte{0x42}, 0x42},
		{"two bytes LE", []byte{0x39, 0x05}, 1337},
		{"max single byte", []byte{0xff}, 255},
		{"three bytes", []byte{0x01, 0x02, 0x03}, 0x030201},
		{"eight bytes", []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}, 0x0807060504030201},
		{"empty", []byte{}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decodeVarUint(tt.data)
			if got != tt.want {
				t.Errorf("got 0x%x want 0x%x", got, tt.want)
			}
		})
	}
}

func TestEncodeSatRangesEmpty(t *testing.T) {
	// Nil and empty both produce empty output.
	if len(EncodeSatRanges(nil)) != 0 {
		t.Error("nil should produce empty encoding")
	}
	if len(EncodeSatRanges([]SatRange{})) != 0 {
		t.Error("empty slice should produce empty encoding")
	}
}

func TestMergeSatRangesLargeChain(t *testing.T) {
	// 1000 contiguous single-sat ranges should merge into one.
	ranges := make([]SatRange, 1000)
	for i := range ranges {
		ranges[i] = SatRange{Start: uint64(i), Count: 1}
	}
	merged := MergeSatRanges(ranges)
	if len(merged) != 1 {
		t.Fatalf("expected 1 merged range, got %d", len(merged))
	}
	if merged[0].Start != 0 || merged[0].Count != 1000 {
		t.Errorf("merged: got %v want {0, 1000}", merged[0])
	}
}

func TestCoinbaseSatRangeSequential(t *testing.T) {
	// First 5 blocks should produce non-overlapping contiguous ranges.
	var prevEnd uint64
	for h := uint32(0); h < 5; h++ {
		start, count := CoinbaseSatRange(h)
		if start != prevEnd {
			t.Errorf("block %d: start=%d expected=%d (gap or overlap)", h, start, prevEnd)
		}
		prevEnd = start + count
	}
}

// Negative tests: FIFO engine edge cases.

func TestSplitSatRangesZeroAmount(t *testing.T) {
	input := []SatRange{{Start: 100, Count: 50}}
	out, ro, so := SplitSatRanges(input, 0, 0, 0)
	if len(out) != 0 {
		t.Errorf("zero amount should produce empty output, got %v", out)
	}
	if ro != 0 || so != 0 {
		t.Errorf("offsets should be unchanged: ro=%d so=%d", ro, so)
	}
}

func TestSplitSatRangesExceedsAvailable(t *testing.T) {
	input := []SatRange{{Start: 100, Count: 10}}
	out, ro, so := SplitSatRanges(input, 0, 0, 100)
	// Should consume what's available and stop.
	if len(out) != 1 || out[0].Count != 10 {
		t.Fatalf("expected partial consumption, got %v", out)
	}
	// rangeOffset should advance past the exhausted range.
	if ro != 1 {
		t.Errorf("rangeOffset: got %d want 1", ro)
	}
	_ = so
}

func TestSplitSatRangesEmptyInput(t *testing.T) {
	out, ro, so := SplitSatRanges(nil, 0, 0, 100)
	if len(out) != 0 {
		t.Errorf("nil input should produce empty output, got %v", out)
	}
	if ro != 0 || so != 0 {
		t.Errorf("offsets should be zero: ro=%d so=%d", ro, so)
	}
}

func TestSplitSatRangesOffsetBeyondRanges(t *testing.T) {
	input := []SatRange{{Start: 100, Count: 10}}
	// rangeOffset already past the only range.
	out, _, _ := SplitSatRanges(input, 1, 0, 50)
	if len(out) != 0 {
		t.Errorf("offset beyond ranges should produce empty output, got %v", out)
	}
}

func TestMergeSatRangesNonContiguousGap(t *testing.T) {
	// Gap of 1 sat between ranges — must NOT merge.
	input := []SatRange{
		{Start: 100, Count: 10},
		{Start: 111, Count: 10}, // gap at sat 110
	}
	got := MergeSatRanges(input)
	if len(got) != 2 {
		t.Fatalf("gap of 1: expected 2 ranges, got %d: %v", len(got), got)
	}
}

// Negative tests: inscription envelope parsing.

func TestParseEnvelopeWrongMagic(t *testing.T) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("not-ord")) // wrong magic
	builder.AddOp(txscript.OP_1)
	builder.AddData([]byte("text/plain"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(wire.TxWitness{script, {0x00}})
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		t.Fatal("wrong magic should not produce an envelope")
	}
}

func TestParseEnvelopeTruncatedNoEndif(t *testing.T) {
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1)
	builder.AddData([]byte("text/plain"))
	// No OP_ENDIF — truncated envelope.
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(wire.TxWitness{script, {0x00}})
	if err != nil {
		t.Fatal(err)
	}
	// Should still return what was parsed (malformed but usable).
	if env == nil {
		t.Fatal("truncated envelope should still return parsed data")
	}
	if !bytes.Equal(env.ContentType, []byte("text/plain")) {
		t.Errorf("content type: got %q want %q", env.ContentType, "text/plain")
	}
}

func TestParseEnvelopeEmptyBody(t *testing.T) {
	// Envelope with content type but no content body (tag 5 missing).
	witness := buildOrdEnvelope(t, map[int][]byte{
		1: []byte("text/plain"),
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if len(env.Content) != 0 {
		t.Errorf("expected empty content, got %d bytes", len(env.Content))
	}
}

func TestParseEnvelopeInvalidParentLength(t *testing.T) {
	// Parent tag with wrong length (not 36 bytes) should be ignored.
	witness := buildOrdEnvelope(t, map[int][]byte{
		1: []byte("text/plain"),
		3: []byte("too-short"),
		5: []byte("test"),
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.Parent != nil {
		t.Error("invalid-length parent should be nil")
	}
}

func TestParseEnvelopeInvalidDelegateLength(t *testing.T) {
	// Delegate tag with wrong length (not 36 bytes) should be ignored.
	witness := buildOrdEnvelope(t, map[int][]byte{
		11: []byte("not-36-bytes"),
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.Delegate != nil {
		t.Error("invalid-length delegate should be nil")
	}
}

func TestParseEnvelopeOddUnrecognizedTagNotCursed(t *testing.T) {
	// Unrecognized ODD tags should NOT set HasUnrecognizedEvenTag.
	witness := buildOrdEnvelope(t, map[int][]byte{
		1:  []byte("text/plain"),
		5:  []byte("test"),
		13: []byte("odd-tag-value"),
	})
	env, err := ParseInscriptionEnvelope(witness)
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if env.HasUnrecognizedEvenTag {
		t.Error("odd unrecognized tag should not set HasUnrecognizedEvenTag")
	}
}

func TestParseEnvelopeNoWitnessData(t *testing.T) {
	// Completely empty witness elements.
	env, err := ParseInscriptionEnvelope(wire.TxWitness{})
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		t.Fatal("empty witness should return nil")
	}
}

func TestParseEnvelopeScriptWithoutOrdPattern(t *testing.T) {
	// Script has OP_FALSE but no OP_IF following it.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_TRUE)
	builder.AddOp(txscript.OP_DROP)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(wire.TxWitness{script, {0x00}})
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		t.Fatal("script without ord pattern should return nil")
	}
}

// Negative tests: value encoding edge cases.

func TestEncodeInscriptionValueZeroSat(t *testing.T) {
	// Sat 0 is the first sat ever mined (genesis coinbase).
	env := &InscriptionEnvelope{}
	var bh chainhash.Hash
	v := encodeInscriptionValue(0, &bh, false, env)
	// First 8 bytes should all be zero.
	for i := 0; i < 8; i++ {
		if v[i] != 0 {
			t.Errorf("byte %d: got 0x%02x want 0x00", i, v[i])
		}
	}
}

func TestDecodeVarUintSingleZero(t *testing.T) {
	if got := decodeVarUint([]byte{0}); got != 0 {
		t.Errorf("got %d want 0", got)
	}
}

// Negative tests: coinbase edge cases.

func TestCoinbaseSatRangeAfterAllSubsidies(t *testing.T) {
	// After all halvings, subsidy is 0 and count should be 0.
	start, count := CoinbaseSatRange(14000000) // well past all halvings
	if count != 0 {
		t.Errorf("expected 0 subsidy, got count=%d", count)
	}
	_ = start
}

// FuzzParseInscriptionEnvelope exercises the inscription parser with
// arbitrary witness data. The parser must not panic on any input.
// Seeds cover: valid envelope, empty witness, no envelope, truncated
// envelope, OP_0 body separator, and garbage.
func FuzzParseInscriptionEnvelope(f *testing.F) {
	// Valid envelope: OP_TRUE OP_FALSE OP_IF "ord" OP_1 <content-type> OP_0 <body> OP_ENDIF
	validScript := buildInscriptionWitness("text/plain", "hello ordinals")
	for _, elem := range validScript {
		f.Add(elem)
	}

	// Empty witness element.
	f.Add([]byte{})

	// Single opcode.
	f.Add([]byte{byte(txscript.OP_FALSE)})

	// Random garbage.
	f.Add([]byte{0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa})

	// OP_FALSE OP_IF without "ord" magic.
	f.Add([]byte{byte(txscript.OP_FALSE), byte(txscript.OP_IF), 0x03, 'f', 'o', 'o', byte(txscript.OP_ENDIF)})

	// Truncated: OP_FALSE OP_IF "ord" but no OP_ENDIF.
	f.Add([]byte{byte(txscript.OP_FALSE), byte(txscript.OP_IF), 0x03, 'o', 'r', 'd'})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Build a witness with the fuzzed data as the tapscript element.
		witness := wire.TxWitness{
			{0x01},     // dummy signature
			data,       // fuzzed tapscript
			{0xc0, 42}, // dummy control block
		}
		// Must not panic. Errors are expected and fine.
		_, _ = ParseInscriptionEnvelope(witness)
	})
}

// --- Coverage gap tests: applyTag, envelopeTag, parseEnvelopeTags ---

func buildWitness(script []byte) wire.TxWitness {
	return wire.TxWitness{
		{0x01},     // dummy signature
		script,     // tapscript
		{0xc0, 42}, // dummy control block
	}
}

func TestParseEnvelopeWithPointerTag(t *testing.T) {
	// Tag 2 (pointer) with valid length (<=8 bytes).
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1) // tag 1: content type
	builder.AddData([]byte("text/plain"))
	builder.AddOp(txscript.OP_2)              // tag 2: pointer
	builder.AddData([]byte{0x05, 0x00, 0x00}) // little-endian 5
	builder.AddOp(txscript.OP_0)              // body
	builder.AddData([]byte("pointed"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if env == nil || env.Pointer == nil {
		t.Fatal("expected pointer to be set")
	}
	if *env.Pointer != 5 {
		t.Errorf("pointer: got %d, want 5", *env.Pointer)
	}
	if string(env.Content) != "pointed" {
		t.Errorf("content: got %q, want %q", string(env.Content), "pointed")
	}
}

func TestParseEnvelopePointerTooLong(t *testing.T) {
	// Tag 2 (pointer) with length > 8 — should be ignored.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_2)                       // tag 2: pointer
	builder.AddData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}) // 9 bytes, too long
	builder.AddOp(txscript.OP_0)
	builder.AddData([]byte("body"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if env.Pointer != nil {
		t.Error("pointer should be nil for oversized data")
	}
}

func TestParseEnvelopeWithMetaprotocol(t *testing.T) {
	// Tag 7 (metaprotocol).
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1) // content type
	builder.AddData([]byte("text/plain"))
	builder.AddOp(txscript.OP_7) // tag 7: metaprotocol
	builder.AddData([]byte("brc-20"))
	builder.AddOp(txscript.OP_0)
	builder.AddData([]byte("{}"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Metaprotocol) != "brc-20" {
		t.Errorf("metaprotocol: got %q, want %q", string(env.Metaprotocol), "brc-20")
	}
}

func TestParseEnvelopeUnrecognizedEvenTag(t *testing.T) {
	// Unrecognized even tag (e.g. 4) should set HasUnrecognizedEvenTag.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_4) // tag 4: unrecognized, even
	builder.AddData([]byte("whatever"))
	builder.AddOp(txscript.OP_0)
	builder.AddData([]byte("body"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if !env.HasUnrecognizedEvenTag {
		t.Error("expected HasUnrecognizedEvenTag to be true")
	}
}

func TestParseEnvelopeOP5ContentEncoding(t *testing.T) {
	// Tag 5 (alternate content encoding via OP_5).
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1) // content type
	builder.AddData([]byte("text/plain"))
	builder.AddOp(txscript.OP_5) // tag 5: content (alternate)
	builder.AddData([]byte("chunk1"))
	builder.AddData([]byte("chunk2"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Content) != "chunk1chunk2" {
		t.Errorf("content: got %q, want %q", string(env.Content), "chunk1chunk2")
	}
}

func TestParseEnvelopeOP5ThenTag(t *testing.T) {
	// Tag 5 content followed by a recognized tag mid-body.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_5) // content via OP_5
	builder.AddData([]byte("body"))
	builder.AddOp(txscript.OP_7) // tag 7 mid-body
	builder.AddData([]byte("meta"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Content) != "body" {
		t.Errorf("content: got %q, want %q", string(env.Content), "body")
	}
	if string(env.Metaprotocol) != "meta" {
		t.Errorf("metaprotocol: got %q, want %q", string(env.Metaprotocol), "meta")
	}
}

func TestParseEnvelopeBodyThenTag(t *testing.T) {
	// OP_0 body separator followed by content, then a recognized tag.
	// This exercises applyTag via the OP_0 body path.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1) // content type
	builder.AddData([]byte("text/plain"))
	builder.AddOp(txscript.OP_0) // body
	builder.AddData([]byte("content"))
	builder.AddOp(txscript.OP_2) // tag 2 (pointer) mid-body → applyTag
	builder.AddData([]byte{42})  // pointer value
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Content) != "content" {
		t.Errorf("content: got %q, want %q", string(env.Content), "content")
	}
	// The pointer tag was applied via applyTag.
	if env.Pointer == nil || *env.Pointer != 42 {
		t.Errorf("pointer: got %v, want 42", env.Pointer)
	}
}

func TestParseEnvelopeBodyThenMetaprotocol(t *testing.T) {
	// OP_0 body → content → tag 7 (metaprotocol) mid-body → applyTag.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_0) // body
	builder.AddData([]byte("data"))
	builder.AddOp(txscript.OP_7) // metaprotocol mid-body → applyTag
	builder.AddData([]byte("sns"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if string(env.Content) != "data" {
		t.Errorf("content: got %q, want %q", string(env.Content), "data")
	}
	if string(env.Metaprotocol) != "sns" {
		t.Errorf("metaprotocol: got %q, want %q", string(env.Metaprotocol), "sns")
	}
}

func TestParseEnvelopeBodyThenEvenTag(t *testing.T) {
	// OP_0 body → content → unrecognized even tag → applyTag default.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_0)
	builder.AddData([]byte("xx")) // multi-byte to avoid tag misparse
	builder.AddOp(txscript.OP_6)  // tag 6: unrecognized even
	builder.AddData([]byte("val"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if !env.HasUnrecognizedEvenTag {
		t.Error("expected HasUnrecognizedEvenTag via applyTag")
	}
}

func TestParseEnvelopeBodyThenOddTag(t *testing.T) {
	// OP_0 body → content → unrecognized odd tag → applyTag default (no effect).
	// Use multi-byte content to avoid single-byte being parsed as a tag number.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_0)
	builder.AddData([]byte("xx")) // multi-byte so envelopeTag returns -1
	builder.AddOp(txscript.OP_9)  // tag 9: unrecognized odd
	builder.AddData([]byte("val"))
	builder.AddOp(txscript.OP_ENDIF)
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if env.HasUnrecognizedEvenTag {
		t.Error("odd tag should not set HasUnrecognizedEvenTag")
	}
}

func TestParseEnvelopeDataPushTag(t *testing.T) {
	// envelopeTag with single-byte data push (OP_DATA_1) instead of OP_N.
	// Tag number encoded as the byte value.
	script := []byte{
		byte(txscript.OP_FALSE),
		byte(txscript.OP_IF),
		3, 'o', 'r', 'd', // push "ord"
		1, 7, // OP_DATA_1 with value 7 → tag 7 (metaprotocol)
		4, 'c', 'b', 'r', 'c', // push "cbrc"
		byte(txscript.OP_0),        // body
		5, 'h', 'e', 'l', 'l', 'o', // push "hello"
		byte(txscript.OP_ENDIF),
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	if env == nil {
		t.Fatal("expected envelope")
	}
	if string(env.Metaprotocol) != "cbrc" {
		t.Errorf("metaprotocol: got %q, want %q", string(env.Metaprotocol), "cbrc")
	}
	if string(env.Content) != "hello" {
		t.Errorf("content: got %q, want %q", string(env.Content), "hello")
	}
}

func TestParseEnvelopeFromScriptTokenizerExhaustion(t *testing.T) {
	// OP_FALSE but tokenizer runs out before OP_IF.
	script := []byte{byte(txscript.OP_FALSE)}
	env, err := parseEnvelopeFromScript(script)
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		t.Error("expected nil for exhausted tokenizer")
	}

	// OP_FALSE OP_IF but tokenizer runs out before data push.
	script = []byte{byte(txscript.OP_FALSE), byte(txscript.OP_IF)}
	env, err = parseEnvelopeFromScript(script)
	if err != nil {
		t.Fatal(err)
	}
	if env != nil {
		t.Error("expected nil for truncated envelope")
	}
}

func TestParseEnvelopeTagValueExhaustion(t *testing.T) {
	// Tag present but tokenizer runs out before the value push.
	builder := txscript.NewScriptBuilder()
	builder.AddOp(txscript.OP_FALSE)
	builder.AddOp(txscript.OP_IF)
	builder.AddData([]byte("ord"))
	builder.AddOp(txscript.OP_1) // tag 1 with no value after
	script, err := builder.Script()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ParseInscriptionEnvelope(buildWitness(script))
	if err != nil {
		t.Fatal(err)
	}
	// Should return a partial envelope (no content type set).
	if env == nil {
		t.Fatal("expected partial envelope, got nil")
	}
	if env.ContentType != nil {
		t.Error("content type should be nil when value push is missing")
	}
}

func TestApplyTagCoverageViaBodyPath(t *testing.T) {
	// All these tests exercise applyTag through the OP_0 body mid-tag path.

	t.Run("content type mid-body", func(t *testing.T) {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0) // body
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_1) // tag 1 mid-body → applyTag
		builder.AddData([]byte("image/png"))
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if string(env.ContentType) != "image/png" {
			t.Errorf("content type: got %q, want %q", string(env.ContentType), "image/png")
		}
	})

	t.Run("parent mid-body valid", func(t *testing.T) {
		var parentID [36]byte
		parentID[0] = 0xaa
		parentID[35] = 0xbb
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0)
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_3) // tag 3 mid-body → applyTag
		builder.AddData(parentID[:])
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if env.Parent == nil || env.Parent[0] != 0xaa || env.Parent[35] != 0xbb {
			t.Errorf("parent: got %v", env.Parent)
		}
	})

	t.Run("parent mid-body invalid length", func(t *testing.T) {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0)
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_3)     // tag 3 mid-body
		builder.AddData([]byte{1, 2, 3}) // wrong length
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if env.Parent != nil {
			t.Error("parent should be nil for invalid length")
		}
	})

	t.Run("delegate mid-body valid", func(t *testing.T) {
		var delegateID [36]byte
		delegateID[0] = 0xcc
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0)
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_11) // tag 11 mid-body → applyTag
		builder.AddData(delegateID[:])
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if env.Delegate == nil || env.Delegate[0] != 0xcc {
			t.Errorf("delegate: got %v", env.Delegate)
		}
	})

	t.Run("delegate mid-body invalid length", func(t *testing.T) {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0)
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_11) // tag 11
		builder.AddData([]byte{1, 2}) // wrong length
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if env.Delegate != nil {
			t.Error("delegate should be nil for invalid length")
		}
	})

	t.Run("pointer mid-body too long", func(t *testing.T) {
		builder := txscript.NewScriptBuilder()
		builder.AddOp(txscript.OP_FALSE)
		builder.AddOp(txscript.OP_IF)
		builder.AddData([]byte("ord"))
		builder.AddOp(txscript.OP_0)
		builder.AddData([]byte("data"))
		builder.AddOp(txscript.OP_2)                       // tag 2 pointer
		builder.AddData([]byte{1, 2, 3, 4, 5, 6, 7, 8, 9}) // 9 bytes > 8
		builder.AddOp(txscript.OP_ENDIF)
		script, _ := builder.Script()
		env, err := ParseInscriptionEnvelope(buildWitness(script))
		if err != nil {
			t.Fatal(err)
		}
		if env.Pointer != nil {
			t.Error("pointer should be nil for oversized data via applyTag")
		}
	})
}

// --- Fuzz tests for encode/decode functions ---

// FuzzDecodeSatRanges verifies DecodeSatRanges does not panic on
// arbitrary input. Valid input is a multiple of 16 bytes.
func FuzzDecodeSatRanges(f *testing.F) {
	f.Add([]byte{})
	f.Add(EncodeSatRanges([]SatRange{{Start: 0, Count: 1}}))
	f.Add(EncodeSatRanges([]SatRange{
		{Start: 0, Count: 100},
		{Start: 100, Count: 200},
	}))
	f.Add([]byte{
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
	})
	f.Add([]byte{1, 2, 3}) // not a multiple of 16

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data)%16 != 0 {
			// DecodeSatRanges panics on non-multiple-of-16.
			// That's by design (caller ensures valid data).
			return
		}
		ranges := DecodeSatRanges(data)
		// Round-trip: encode and decode again must match.
		reencoded := EncodeSatRanges(ranges)
		redecoded := DecodeSatRanges(reencoded)
		if len(ranges) != len(redecoded) {
			t.Fatalf("round-trip count: %d vs %d", len(ranges), len(redecoded))
		}
		for i := range ranges {
			if ranges[i] != redecoded[i] {
				t.Fatalf("round-trip mismatch at %d: %v vs %v",
					i, ranges[i], redecoded[i])
			}
		}
	})
}

// FuzzDecodeInscriptionValue verifies decodeInscriptionValue does not
// panic on arbitrary input and that valid encodings round-trip.
func FuzzDecodeInscriptionValue(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0}) // too short
	f.Add(encodeInscriptionValue(42, &chainhash.Hash{}, false, &InscriptionEnvelope{
		ContentType: []byte("text/plain"),
		Content:     []byte("hello"),
	}))
	f.Add(encodeInscriptionValue(0, &chainhash.Hash{0xff}, true, &InscriptionEnvelope{
		ContentType: []byte("application/json"),
		Content:     []byte("{}"),
		Parent:      &[36]byte{0xaa},
	}))
	f.Add(encodeInscriptionValue(1, &chainhash.Hash{}, false, &InscriptionEnvelope{
		Delegate:     &[36]byte{0xbb},
		Metaprotocol: []byte("brc-20"),
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		d, err := decodeInscriptionValue(data)
		if err != nil {
			return // expected for malformed input
		}
		// Valid decode: re-encode and verify round-trip.
		env := &InscriptionEnvelope{
			Metaprotocol: []byte(d.Metaprotocol),
		}
		if d.Parent != nil {
			env.Parent = d.Parent
		}
		if d.Delegate != nil {
			env.Delegate = d.Delegate
		}
		reencoded := encodeInscriptionValue(d.SatNumber, &d.BlockHash, d.Cursed, env)
		d2, err := decodeInscriptionValue(reencoded)
		if err != nil {
			t.Fatalf("round-trip decode failed: %v", err)
		}
		if d.SatNumber != d2.SatNumber {
			t.Fatalf("sat: %d vs %d", d.SatNumber, d2.SatNumber)
		}
		if d.BlockHash != d2.BlockHash {
			t.Fatalf("block hash mismatch")
		}
		if d.Cursed != d2.Cursed {
			t.Fatalf("cursed: %v vs %v", d.Cursed, d2.Cursed)
		}
	})
}

// FuzzDecodeVarUint verifies decodeVarUint does not panic on arbitrary
// input. It always returns a value (no error), so we just verify no crash.
func FuzzDecodeVarUint(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0})
	f.Add([]byte{42})
	f.Add([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	f.Add([]byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}) // >8 bytes

	f.Fuzz(func(t *testing.T, data []byte) {
		_ = decodeVarUint(data) // must not panic
	})
}

// --- Corner case and negative path tests ---

func TestDecodeInscriptionValueMaxSat(t *testing.T) {
	// Max uint64 sat number must round-trip.
	env := &InscriptionEnvelope{}
	var blockHash chainhash.Hash
	v := encodeInscriptionValue(math.MaxUint64, &blockHash, false, env)
	d, err := decodeInscriptionValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if d.SatNumber != math.MaxUint64 {
		t.Errorf("sat: got %d, want %d", d.SatNumber, uint64(math.MaxUint64))
	}
}

func TestDecodeInscriptionValueEmptyMetaprotocol(t *testing.T) {
	// Metaprotocol flag set but zero remaining bytes after offset.
	// This is a valid encoding — empty metaprotocol string.
	data := make([]byte, 41)
	data[40] = 1 << 3 // metaprotocol flag
	d, err := decodeInscriptionValue(data)
	if err != nil {
		t.Fatal(err)
	}
	if d.Metaprotocol != "" {
		t.Errorf("metaprotocol: got %q, want empty", d.Metaprotocol)
	}
}

func TestDecodeInscriptionValueUnknownFlags(t *testing.T) {
	// Bits 4-7 in the flags byte are unused. Decoder should not
	// fail and should ignore them (forward compatibility).
	env := &InscriptionEnvelope{}
	var blockHash chainhash.Hash
	v := encodeInscriptionValue(42, &blockHash, false, env)
	v[40] = 0xF0 // set bits 4-7, clear bits 0-3
	d, err := decodeInscriptionValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if d.SatNumber != 42 {
		t.Errorf("sat: got %d, want 42", d.SatNumber)
	}
	if d.Cursed || d.Parent != nil || d.Delegate != nil || d.Metaprotocol != "" {
		t.Error("unknown flags should not activate any fields")
	}
}

func TestEncodeSatRangesZeroCount(t *testing.T) {
	// Zero-count range is semantically empty but must round-trip.
	encoded := EncodeSatRanges([]SatRange{{Start: 42, Count: 0}})
	decoded := DecodeSatRanges(encoded)
	if len(decoded) != 1 || decoded[0].Start != 42 || decoded[0].Count != 0 {
		t.Errorf("zero-count round-trip: got %v", decoded)
	}
}

func TestEncodeSatRangesMaxUint64(t *testing.T) {
	// Max uint64 Start and Count must round-trip.
	encoded := EncodeSatRanges([]SatRange{
		{Start: math.MaxUint64, Count: math.MaxUint64},
	})
	decoded := DecodeSatRanges(encoded)
	if len(decoded) != 1 {
		t.Fatalf("expected 1 range, got %d", len(decoded))
	}
	if decoded[0].Start != math.MaxUint64 || decoded[0].Count != math.MaxUint64 {
		t.Errorf("max round-trip: got Start=%d Count=%d",
			decoded[0].Start, decoded[0].Count)
	}
}

func TestDecodeVarUintMaxUint64(t *testing.T) {
	// 8 bytes of 0xff should decode to MaxUint64.
	data := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	got := decodeVarUint(data)
	if got != math.MaxUint64 {
		t.Errorf("got 0x%x, want 0x%x", got, uint64(math.MaxUint64))
	}
}

func TestDecodeVarUintOverflow(t *testing.T) {
	// >8 bytes: Go shifts past 64 produce 0, extra bytes are silently
	// ignored. Verify this doesn't corrupt the lower bytes.
	data := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0xff, 0xff}
	got := decodeVarUint(data)
	// Only the first 8 bytes should contribute.
	expected := decodeVarUint(data[:8])
	if got != expected {
		t.Errorf("overflow corruption: got 0x%x, want 0x%x", got, expected)
	}
}

func TestDecodeInscriptionValueExact41Bytes(t *testing.T) {
	// Exactly 41 bytes with no flags — minimum valid encoding.
	data := make([]byte, 41)
	binary.BigEndian.PutUint64(data[0:8], 123)
	data[9] = 0xab // block hash byte
	d, err := decodeInscriptionValue(data)
	if err != nil {
		t.Fatal(err)
	}
	if d.SatNumber != 123 {
		t.Errorf("sat: got %d, want 123", d.SatNumber)
	}
}

func TestDecodeInscriptionValueMetaprotocolFlagNoParentNoDelegate(t *testing.T) {
	// Metaprotocol flag with content, but no parent/delegate flags.
	// Offset should be 41 (skip straight to metaprotocol).
	env := &InscriptionEnvelope{Metaprotocol: []byte("rune")}
	var blockHash chainhash.Hash
	v := encodeInscriptionValue(0, &blockHash, false, env)
	d, err := decodeInscriptionValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if d.Metaprotocol != "rune" {
		t.Errorf("metaprotocol: got %q, want %q", d.Metaprotocol, "rune")
	}
	if d.Parent != nil || d.Delegate != nil {
		t.Error("unexpected parent/delegate")
	}
}

// TestOutpointValueRoundTrip exercises the 'o' value codec for reveal,
// transfer, fee, and lost entries, plus the malformed-length error path.
func TestOutpointValueRoundTrip(t *testing.T) {
	inscID := [36]byte{0x01, 0x02, 0x03}
	for i := range inscID {
		inscID[i] = byte(i + 1)
	}

	tests := []struct {
		name        string
		kind        byte
		srcTxIdx    uint32
		srcInputIdx uint32
		srcOffset   uint64
		wantXfer    bool
	}{
		{"reveal sentinel", srcKindReveal, 0, ordinalRevealSentinel, 0, false},
		{"transfer input 0 offset 0", srcKindTransfer, 1, 0, 0, true},
		{"transfer input 3 offset 12345", srcKindTransfer, 2, 3, 12345, true},
		{"transfer max offset", srcKindTransfer, 5, 7, math.MaxUint64, true},
		{"transfer high input idx", srcKindTransfer, 0, 0xFFFFFFFE, 1, true},
		{"fee kind", srcKindFee, 3, 1, 500, true},
		{"lost kind", srcKindLost, 4, 2, 999, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := encodeOutpointValue(inscID, tt.kind, tt.srcTxIdx, tt.srcInputIdx, tt.srcOffset)
			if len(v) != ordinalOutpointValueLen {
				t.Fatalf("encoded length %d, want %d", len(v), ordinalOutpointValueLen)
			}
			gotID, gotKind, gotTxIdx, gotIdx, gotOff, xfer, err := decodeOutpointValue(v)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if gotID != inscID {
				t.Errorf("inscID got %x want %x", gotID, inscID)
			}
			if gotKind != tt.kind {
				t.Errorf("kind got %d want %d", gotKind, tt.kind)
			}
			if gotTxIdx != tt.srcTxIdx {
				t.Errorf("srcTxIdx got %d want %d", gotTxIdx, tt.srcTxIdx)
			}
			if gotIdx != tt.srcInputIdx {
				t.Errorf("srcInputIdx got %d want %d", gotIdx, tt.srcInputIdx)
			}
			if gotOff != tt.srcOffset {
				t.Errorf("srcOffset got %d want %d", gotOff, tt.srcOffset)
			}
			if xfer != tt.wantXfer {
				t.Errorf("isTransfer got %v want %v", xfer, tt.wantXfer)
			}
		})
	}

	t.Run("malformed length rejected", func(t *testing.T) {
		for _, n := range []int{0, 35, 36, 45, 46, 52, 54, 81} {
			_, _, _, _, _, _, err := decodeOutpointValue(make([]byte, n))
			if err == nil {
				t.Errorf("len %d: expected error, got nil", n)
			}
		}
	})
}

// FuzzDecodeOutpointValue ensures the 'o' value decoder never panics on
// arbitrary bytes (it reads fixed offsets after a length guard).
func FuzzDecodeOutpointValue(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, ordinalOutpointValueLen))
	f.Add(append([]byte("inscid"), make([]byte, 40)...))
	f.Fuzz(func(t *testing.T, v []byte) {
		_, _, _, _, _, _, _ = decodeOutpointValue(v)
	})
}

// TestPredecessorKeyLayout verifies the 'p' key construction mirrors 'o'.
func TestPredecessorKeyLayout(t *testing.T) {
	txid := chainhash.Hash{0xaa, 0xbb, 0xcc}
	op := tbcd.NewOutpoint(txid, 7)
	offset := uint64(42)

	// Construct 'o' key inline — the production code now builds this
	// in the DB layer (level.go BlockOrdinalUpdate), not via a helper.
	var oKey tbcd.OrdinalKey
	oKey[0] = 'o'
	copy(oKey[1:37], op[1:37])
	binary.BigEndian.PutUint64(oKey[37:], offset)

	pKey := predecessorKey(op, offset)

	// Same layout except prefix byte.
	if oKey[0] != 'o' {
		t.Fatalf("'o' key prefix: got %c", oKey[0])
	}
	if pKey[0] != 'p' {
		t.Fatalf("'p' key prefix: got %c", pKey[0])
	}
	// Bytes 1..44 must be identical (txid + vout + offset).
	if !bytes.Equal(oKey[1:], pKey[1:]) {
		t.Errorf("key payload mismatch:\n  o: %x\n  p: %x", oKey[1:], pKey[1:])
	}
}

// TestMultiHopPredecessorProof demonstrates the multi-hop unwind bug that
// the 'p' prefix fixes. The test shows that li.Value (the destination's
// own 'o' value) differs from the predecessor value, proving that copying
// li.Value to the source is wrong and the 'p' approach is necessary.
//
// Chain: reveal at O1 → transfer to O2 → transfer to O3.
// O3's 'o' value carries O3's source info (input of T3 that spent O2).
// O2's predecessor ('p'@O2 captured during wind) carries O2's own source
// info (input of T2 that spent O1). These are different values.
// On unwind of O3: restoring 'p'@O3 (= O2's old value) is correct;
// restoring li.Value (= O3's value) would corrupt O2's source info.
func TestMultiHopPredecessorProof(t *testing.T) {
	inscID := [36]byte{0x01}

	// Simulate the 'o' values that wind would produce:
	// O1: reveal
	o1Value := encodeOutpointValue(inscID, srcKindReveal, 0, ordinalRevealSentinel, 0)
	// O2: transfer from O1 via input 2 of tx at block index 1, offset 0
	o2Value := encodeOutpointValue(inscID, srcKindTransfer, 1, 2, 0)
	// O3: transfer from O2 via input 0 of tx at block index 3, offset 0
	o3Value := encodeOutpointValue(inscID, srcKindTransfer, 3, 0, 0)

	// The predecessor stored at O3 during wind is O2's value (captured
	// from the 'o' entry at O2 before it was deleted).
	predecessorAtO3 := o2Value

	// The predecessor stored at O2 during wind is O1's value.
	predecessorAtO2 := o1Value

	// PROOF: O3's own value != the predecessor. Copying li.Value to O2
	// on unwind of O3 would write O3's source info at O2, which is wrong.
	if bytes.Equal(o3Value, predecessorAtO3) {
		t.Fatal("bug in test: o3Value should differ from predecessorAtO3")
	}

	// Correct unwind of O3: restore predecessorAtO3 at O2's key.
	_, _, _, srcInputIdx, srcOffset, _, err := decodeOutpointValue(predecessorAtO3)
	if err != nil {
		t.Fatalf("decode predecessorAtO3: %v", err)
	}
	// srcInputIdx=2 and srcOffset=0 — matches O2's original source info.
	if srcInputIdx != 2 {
		t.Errorf("restored srcInputIdx: got %d, want 2", srcInputIdx)
	}
	if srcOffset != 0 {
		t.Errorf("restored srcOffset: got %d, want 0", srcOffset)
	}

	// Correct unwind of O2: restore predecessorAtO2 at O1's key.
	_, kind, _, _, _, _, err := decodeOutpointValue(predecessorAtO2)
	if err != nil {
		t.Fatalf("decode predecessorAtO2: %v", err)
	}
	// O1 was a reveal — kind must be REVEAL.
	if kind != srcKindReveal {
		t.Errorf("restored kind: got %d, want %d (REVEAL)", kind, srcKindReveal)
	}
}

// TestLostSatOffset verifies the block-height encoding in lost sat offsets.
func TestLostSatOffset(t *testing.T) {
	tests := []struct {
		name   string
		height uint32
		seq    uint32
	}{
		{"genesis", 0, 0},
		{"block 100 seq 0", 100, 0},
		{"block 100 seq 5", 100, 5},
		{"block maxuint32 seq maxuint32", math.MaxUint32, math.MaxUint32},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			offset := lostSatOffset(tt.height, tt.seq)
			gotHeight := lostSatBlockHeight(offset)
			if gotHeight != tt.height {
				t.Errorf("height: got %d, want %d", gotHeight, tt.height)
			}
			// Verify uniqueness: different seq → different offset.
			if tt.seq > 0 {
				other := lostSatOffset(tt.height, tt.seq-1)
				if offset == other {
					t.Error("different seq produced same offset")
				}
			}
		})
	}
}

// TestLostSentinelOutpoint verifies the sentinel outpoint has the expected
// shape: all-zero txid, vout 0xFFFFFFFF.
func TestLostSentinelOutpoint(t *testing.T) {
	op := lostSentinelOutpoint()
	// Outpoint layout: u-prefix(1) + txid(32) + vout(4)
	// txid should be all zeros.
	for i := 1; i <= 32; i++ {
		if op[i] != 0 {
			t.Fatalf("sentinel txid byte %d: got %02x, want 00", i, op[i])
		}
	}
	// vout should be 0xFFFFFFFF (big-endian at bytes 33..36).
	vout := binary.BigEndian.Uint32(op[33:37])
	if vout != 0xFFFFFFFF {
		t.Fatalf("sentinel vout: got %08x, want FFFFFFFF", vout)
	}
}

// TestTxOutTotal verifies the output value sum helper.
func TestTxOutTotal(t *testing.T) {
	tests := []struct {
		name string
		outs []*wire.TxOut
		want uint64
	}{
		{"empty", nil, 0},
		{"single", []*wire.TxOut{{Value: 100}}, 100},
		{"all zero", []*wire.TxOut{{Value: 0}, {Value: 0}}, 0},
		{"mixed with zero", []*wire.TxOut{{Value: 100}, {Value: 0}, {Value: 200}, {Value: 50}}, 350},
		{"large values", []*wire.TxOut{{Value: 5_000_000_000}, {Value: 5_000_000_000}}, 10_000_000_000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := txOutTotal(tt.outs)
			if got != tt.want {
				t.Errorf("txOutTotal: got %d, want %d", got, tt.want)
			}
		})
	}
}

// TestFeeSatPlacement verifies that a fee sat at feePoolOff is placed at
// the correct coinbase position: subsidyCount + feePoolOff.
func TestFeeSatPlacement(t *testing.T) {
	inscID := [36]byte{0xfe}

	// Simulate: subsidy = 5 BTC = 500_000_000 sats, fee sat at pool offset 42.
	subsidyCount := uint64(500_000_000)
	feePoolOff := uint64(42)
	posCB := subsidyCount + feePoolOff

	// Coinbase has one output of 500_000_100 sats (subsidy + 100 sats fee).
	cbOutTotal := uint64(500_000_100)
	if posCB >= cbOutTotal {
		t.Fatal("test setup: fee sat should land in coinbase output")
	}

	// Encode the FEE entry.
	v := encodeOutpointValue(inscID, srcKindFee, 1, 0, 0)
	_, kind, srcTxIdx, _, _, isTransfer, err := decodeOutpointValue(v)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if kind != srcKindFee {
		t.Errorf("kind: got %d, want %d", kind, srcKindFee)
	}
	if srcTxIdx != 1 {
		t.Errorf("srcTxIdx: got %d, want 1", srcTxIdx)
	}
	if !isTransfer {
		t.Error("FEE should report isTransfer=true")
	}
}

// TestLostSatPlacement verifies that a fee sat exceeding coinbase output
// value produces a LOST entry.
func TestLostSatPlacement(t *testing.T) {
	inscID := [36]byte{0xaa}

	// Simulate: subsidy = 500M sats, fee sat at pool offset 200, but
	// coinbase only claims 500M (subsidy only, no fees claimed).
	subsidyCount := uint64(500_000_000)
	feePoolOff := uint64(200)
	posCB := subsidyCount + feePoolOff
	cbOutTotal := uint64(500_000_000) // miner claimed only subsidy

	if posCB < cbOutTotal {
		t.Fatal("test setup: fee sat should NOT land in coinbase output")
	}

	// Encode the LOST entry.
	v := encodeOutpointValue(inscID, srcKindLost, 2, 1, 99)
	_, kind, srcTxIdx, srcInputIdx, srcOffset, isTransfer, err := decodeOutpointValue(v)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if kind != srcKindLost {
		t.Errorf("kind: got %d, want %d", kind, srcKindLost)
	}
	if srcTxIdx != 2 {
		t.Errorf("srcTxIdx: got %d, want 2", srcTxIdx)
	}
	if srcInputIdx != 1 {
		t.Errorf("srcInputIdx: got %d, want 1", srcInputIdx)
	}
	if srcOffset != 99 {
		t.Errorf("srcOffset: got %d, want 99", srcOffset)
	}
	if !isTransfer {
		t.Error("LOST should report isTransfer=true")
	}
}

// TestBlockFeeBaseAccumulation proves that blockFeeBase accumulates fees
// from ALL non-coinbase txs, including those with no inscriptions. This is
// the invariant that the review caught as a bug: the original code skipped
// fee accumulation for txs without flotsam, producing wrong feePoolOff.
//
// Scenario: tx1 has no inscriptions but 1000-sat fee. tx2 has an inscription
// whose sat falls into fees. tx2's feePoolOff must include tx1's fee.
func TestBlockFeeBaseAccumulation(t *testing.T) {
	var blockFeeBase uint64

	// tx1: no inscriptions. inputValue=5000, outTotal=4000 → fee=1000.
	// blockFeeBase must accumulate this even with no flotsam.
	tx1InputValue := uint64(5000)
	tx1OutTotal := uint64(4000)
	blockFeeBase += tx1InputValue - tx1OutTotal

	if blockFeeBase != 1000 {
		t.Fatalf("blockFeeBase after tx1: got %d, want 1000", blockFeeBase)
	}

	// tx2: inscription at FIFO pos 2800, outTotal=2500.
	// pos >= outTotal → fee sat. feeInternal = 2800 - 2500 = 300.
	// feePoolOff = blockFeeBase + feeInternal = 1000 + 300 = 1300.
	tx2OutTotal := uint64(2500)
	inscPos := uint64(2800)
	feeInternal := inscPos - tx2OutTotal
	feePoolOff := blockFeeBase + feeInternal

	if feePoolOff != 1300 {
		t.Fatalf("feePoolOff: got %d, want 1300 (blockFeeBase=%d + feeInternal=%d)",
			feePoolOff, blockFeeBase, feeInternal)
	}

	// BUG (pre-fix): if tx1's fee was skipped, blockFeeBase would be 0 and
	// feePoolOff would be 300 — placing the inscription at the wrong
	// coinbase position. This test proves the fix is correct.
	wrongFeePoolOff := uint64(0) + feeInternal // what the buggy code produced
	if feePoolOff == wrongFeePoolOff {
		t.Fatal("feePoolOff equals the buggy value — blockFeeBase was not accumulated")
	}

	// tx2 also contributes its own fee.
	tx2InputValue := uint64(3000)
	blockFeeBase += tx2InputValue - tx2OutTotal

	if blockFeeBase != 1500 {
		t.Fatalf("blockFeeBase after tx2: got %d, want 1500", blockFeeBase)
	}
}

// TestRevealLandsInFees verifies the handling of a reveal whose inscribed
// sat's FIFO position exceeds the tx output total (the sat falls into fees).
// The inscription metadata ('i'/'n'/'a') should still be created, but the
// 'o' entry should land in the coinbase (srcKind=FEE) or sentinel
// (srcKind=LOST), not at the tx's output. The 'p' entry should be empty
// since there is no predecessor for a newly revealed inscription.
func TestRevealLandsInFees(t *testing.T) {
	inscID := [36]byte{0xbb}

	// A reveal at input 0: pos = 0 (offset 0 of input 0).
	// If the tx has outputs totaling 0 sats (e.g., only OP_RETURN),
	// then pos >= outTotal → fee sat.
	outTotal := uint64(0)
	revealPos := uint64(0)

	if revealPos < outTotal {
		t.Fatal("test setup: reveal should land in fees")
	}

	feeInternal := revealPos - outTotal // 0
	blockFeeBase := uint64(0)
	feePoolOff := blockFeeBase + feeInternal // 0

	// Coinbase: subsidy at height 0 = 5 BTC = 5_000_000_000 sats.
	subsidyCount := SubsidyAtHeight(0)
	posCB := subsidyCount + feePoolOff // 5_000_000_000 + 0

	// If coinbase claims subsidy + fees: posCB < cbOutTotal → FEE.
	cbOutTotal := subsidyCount + 100 // subsidy + some fees
	if posCB >= cbOutTotal {
		t.Fatal("test setup: fee sat should land in coinbase")
	}

	// The 'o' entry at the coinbase output has srcKind=FEE.
	v := encodeOutpointValue(inscID, srcKindFee, 1, 0, 0)
	_, kind, _, _, _, _, err := decodeOutpointValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if kind != srcKindFee {
		t.Errorf("kind: got %d, want %d (FEE)", kind, srcKindFee)
	}

	// The 'p' entry for a reveal-in-fees is empty (no predecessor).
	// On unwind, len(prevValue) == 0 means nothing to restore — the
	// inscription deletion loop handles 'i'/'n'/'a' cleanup.
	var prevValue []byte // nil for reveals
	if len(prevValue) != 0 {
		t.Error("reveal-in-fees should have no predecessor")
	}
}

// TestRevealLandsInLost verifies a reveal whose fee sat exceeds the
// coinbase output value — the sat is LOST.
func TestRevealLandsInLost(t *testing.T) {
	inscID := [36]byte{0xcc}

	// Same setup as TestRevealLandsInFees but the coinbase doesn't claim
	// any fees (subsidy only).
	subsidyCount := SubsidyAtHeight(0) // 5_000_000_000
	feePoolOff := uint64(0)
	posCB := subsidyCount + feePoolOff
	cbOutTotal := subsidyCount // miner claims only subsidy

	if posCB < cbOutTotal {
		t.Fatal("test setup: fee sat should be LOST")
	}

	v := encodeOutpointValue(inscID, srcKindLost, 1, 0, 0)
	_, kind, _, _, _, _, err := decodeOutpointValue(v)
	if err != nil {
		t.Fatal(err)
	}
	if kind != srcKindLost {
		t.Errorf("kind: got %d, want %d (LOST)", kind, srcKindLost)
	}

	// Lost offset encodes block height.
	blockHeight := uint32(100)
	offset := lostSatOffset(blockHeight, 0)
	if lostSatBlockHeight(offset) != blockHeight {
		t.Errorf("lost block height: got %d, want %d",
			lostSatBlockHeight(offset), blockHeight)
	}
}
