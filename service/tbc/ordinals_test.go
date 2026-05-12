// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
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

func TestSatAtOutputOffset(t *testing.T) {
	tests := []struct {
		name         string
		outputRanges map[uint32][]SatRange
		txOuts       []*wire.TxOut
		offset       uint64
		want         uint64
	}{
		{
			name: "first sat of first output",
			outputRanges: map[uint32][]SatRange{
				0: {{Start: 100, Count: 50}},
			},
			txOuts: []*wire.TxOut{{Value: 50}},
			offset: 0,
			want:   100,
		},
		{
			name: "middle of first output",
			outputRanges: map[uint32][]SatRange{
				0: {{Start: 100, Count: 50}},
			},
			txOuts: []*wire.TxOut{{Value: 50}},
			offset: 25,
			want:   125,
		},
		{
			name: "into second output",
			outputRanges: map[uint32][]SatRange{
				0: {{Start: 100, Count: 30}},
				1: {{Start: 500, Count: 20}},
			},
			txOuts: []*wire.TxOut{{Value: 30}, {Value: 20}},
			offset: 35,
			want:   505,
		},
		{
			name: "multi-range output",
			outputRanges: map[uint32][]SatRange{
				0: {
					{Start: 100, Count: 10},
					{Start: 200, Count: 10},
				},
			},
			txOuts: []*wire.TxOut{{Value: 20}},
			offset: 15,
			want:   205,
		},
		{
			name: "offset beyond total falls back",
			outputRanges: map[uint32][]SatRange{
				0: {{Start: 100, Count: 10}},
			},
			txOuts: []*wire.TxOut{{Value: 10}},
			offset: 999,
			want:   100, // fallback to first sat
		},
		{
			name:         "empty outputs falls back to zero",
			outputRanges: map[uint32][]SatRange{},
			txOuts:       []*wire.TxOut{},
			offset:       0,
			want:         0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := satAtOutputOffset(tt.outputRanges, tt.txOuts, tt.offset)
			if got != tt.want {
				t.Errorf("got %d want %d", got, tt.want)
			}
		})
	}
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
	t.Run("ordinalRangeKey prefix", func(t *testing.T) {
		op := tbcd.NewOutpoint(chainhash.Hash{0x01}, 42)
		k := ordinalRangeKey(op)
		if k[0] != 'r' {
			t.Errorf("prefix: got %c want r", k[0])
		}
		if len(k) != 38 { // 1 prefix + 37 outpoint
			t.Errorf("length: got %d want 38", len(k))
		}
		// Outpoint bytes should follow directly.
		for i := range op {
			if k[1+i] != op[i] {
				t.Errorf("outpoint byte %d mismatch", i)
				break
			}
		}
	})

	t.Run("ordinalSatKey prefix and encoding", func(t *testing.T) {
		k := ordinalSatKey(0x0102030405060708)
		if k[0] != 's' {
			t.Errorf("prefix: got %c want s", k[0])
		}
		if len(k) != 9 {
			t.Errorf("length: got %d want 9", len(k))
		}
		// Big-endian encoding.
		expected := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
		for i, b := range expected {
			if k[1+i] != b {
				t.Errorf("byte %d: got 0x%02x want 0x%02x", i, k[1+i], b)
			}
		}
	})

	t.Run("ordinalInscriptionKey prefix", func(t *testing.T) {
		var inscID [36]byte
		inscID[0] = 0xff
		k := ordinalInscriptionKey(inscID)
		if k[0] != 'i' {
			t.Errorf("prefix: got %c want i", k[0])
		}
		if len(k) != 37 {
			t.Errorf("length: got %d want 37", len(k))
		}
	})

	t.Run("ordinalSatInscriptionKey prefix", func(t *testing.T) {
		var inscID [36]byte
		k := ordinalSatInscriptionKey(42, inscID)
		if k[0] != 'a' {
			t.Errorf("prefix: got %c want a", k[0])
		}
		if len(k) != 45 { // 1 + 8 + 36
			t.Errorf("length: got %d want 45", len(k))
		}
	})

	t.Run("ordinalBlockInscriptionKey prefix", func(t *testing.T) {
		var bh chainhash.Hash
		k := ordinalBlockInscriptionKey(&bh, 7)
		if k[0] != 'n' {
			t.Errorf("prefix: got %c want n", k[0])
		}
		if len(k) != 37 { // 1 + 32 + 4
			t.Errorf("length: got %d want 37", len(k))
		}
	})
}

func TestInscribedSatsFromCache(t *testing.T) {
	cache := make(map[tbcd.OrdinalKey][]byte)

	// Insert some 's' entries.
	cache[ordinalSatKey(100)] = []byte{0x01} // inscribed
	cache[ordinalSatKey(200)] = []byte{0x02} // inscribed
	cache[ordinalSatKey(300)] = nil          // deleted
	cache[ordinalSatKey(500)] = []byte{0x03} // inscribed, out of range

	// Also insert non-'s' entries to verify filtering.
	var rKey [38]byte
	rKey[0] = 'r'
	cache[tbcd.OrdinalKey(rKey[:])] = []byte{0xff}

	t.Run("range covering two entries", func(t *testing.T) {
		got := inscribedSatsFromCache(cache, 50, 250)
		if len(got) != 2 {
			t.Fatalf("expected 2 sats, got %d: %v", len(got), got)
		}
		found100, found200 := false, false
		for _, s := range got {
			if s == 100 {
				found100 = true
			}
			if s == 200 {
				found200 = true
			}
		}
		if !found100 || !found200 {
			t.Errorf("expected sats 100 and 200, got %v", got)
		}
	})

	t.Run("deleted entry excluded", func(t *testing.T) {
		got := inscribedSatsFromCache(cache, 250, 350)
		if len(got) != 0 {
			t.Errorf("expected 0 sats (deleted), got %d: %v", len(got), got)
		}
	})

	t.Run("empty range", func(t *testing.T) {
		got := inscribedSatsFromCache(cache, 400, 450)
		if len(got) != 0 {
			t.Errorf("expected 0 sats, got %d", len(got))
		}
	})

	t.Run("out of range excluded", func(t *testing.T) {
		got := inscribedSatsFromCache(cache, 50, 499)
		// Should find 100 and 200 but not 500 (exclusive upper bound).
		for _, s := range got {
			if s == 500 {
				t.Error("sat 500 should be excluded (end is exclusive)")
			}
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
