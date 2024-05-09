// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"slices"
	"testing"
)

func TestNewOutpoint(t *testing.T) {
	tests := []struct {
		txid  [32]byte
		index uint32
		want  []byte
	}{
		{
			txid:  [32]byte{},
			index: 0,
			want: []byte{
				// Prefix - 1 byte
				'u',
				// txid - 32 bytes
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				// index (big endian) - 4 bytes
				0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			txid:  decodeTxId("369346b9912c5a7ce6986cc7761941eceb7c8c9e7756e4bae045677daa6c0862"),
			index: 1,
			want: []byte{
				// Prefix - 1 byte
				'u',
				// txid - 32 bytes
				0x62, 0x8, 0x6c, 0xaa, 0x7d, 0x67, 0x45, 0xe0,
				0xba, 0xe4, 0x56, 0x77, 0x9e, 0x8c, 0x7c, 0xeb,
				0xec, 0x41, 0x19, 0x76, 0xc7, 0x6c, 0x98, 0xe6,
				0x7c, 0x5a, 0x2c, 0x91, 0xb9, 0x46, 0x93, 0x36,
				// index (big endian) - 4 bytes
				0x00, 0x00, 0x00, 0x01,
			},
		},
		{
			txid:  decodeTxId("1fce5b19d295e03289dcfa18b0e554d25a7396dbe8e7d83533463d957525bf6d"),
			index: 43111,
			want: []byte{
				// Prefix - 1 byte
				'u',
				// txid - 32 bytes
				0x6d, 0xbf, 0x25, 0x75, 0x95, 0x3d, 0x46, 0x33,
				0x35, 0xd8, 0xe7, 0xe8, 0xdb, 0x96, 0x73, 0x5a,
				0xd2, 0x54, 0xe5, 0xb0, 0x18, 0xfa, 0xdc, 0x89,
				0x32, 0xe0, 0x95, 0xd2, 0x19, 0x5b, 0xce, 0x1f,
				// index (big endian) - 4 bytes
				0x00, 0x00, 0xA8, 0x67,
			},
		},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%x/%d", tt.txid, tt.index), func(t *testing.T) {
			op := NewOutpoint(tt.txid, tt.index)
			if !bytes.Equal(op[:], tt.want) {
				t.Errorf("NewOutpoint() = %x, want %x", op[:], tt.want)
			}
		})
	}
}

func decodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func decodeTxId(s string) [32]byte {
	b := decodeHex(s)
	if len(b) != 32 {
		panic(fmt.Errorf("invalid txid: %s", s))
	}

	// Convert from display order to natural order
	slices.Reverse(b)
	return [32]byte(b)
}
