// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"reflect"
	"testing"
)

func TestFillBytes(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		n      int
		want   []byte
	}{
		{
			name: "empty",
			n:    0,
			want: []byte{},
		},
		{
			name: "empty prefix",
			n:    32,
			want: []byte("________________________________"),
		},
		{
			name: "empty prefix long",
			n:    64,
			want: []byte("________________________________________________________________"),
		},
		{
			name:   "with prefix",
			prefix: "test",
			n:      32,
			want:   []byte("test____________________________"),
		},
		{
			name:   "odd length",
			prefix: "test",
			n:      15,
			want:   []byte("test___________"),
		},
		{
			name:   "prefix longer than n",
			prefix: "test",
			n:      3,
			want:   []byte("tes"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FillBytes(tt.prefix, tt.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FillBytes() = %v (len %d), want %v (len %d)",
					got, len(got), tt.want, len(tt.want))
			}
		})
	}
}

func TestFillBytesZero(t *testing.T) {
	tests := []struct {
		name   string
		prefix string
		n      int
		want   []byte
	}{
		{
			name: "empty",
			n:    0,
			want: []byte{},
		},
		{
			name: "empty prefix",
			n:    32,
			want: []byte{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:   "with prefix",
			prefix: "test",
			n:      32,
			want: []byte{
				0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:   "odd length",
			prefix: "test",
			n:      15,
			want: []byte{
				0x74, 0x65, 0x73, 0x74, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name:   "prefix longer than n",
			prefix: "test",
			n:      3,
			want:   []byte("tes"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := FillBytesZero(tt.prefix, tt.n); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FillBytesZero() = %v (len %d), want %v (len %d)",
					got, len(got), tt.want, len(tt.want))
			}
		})
	}
}
