// Copyright (c) 2025-2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package testutil

import (
	"bytes"
	"context"
	"errors"
	"reflect"
	"testing"
	"testing/synctest"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
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

func TestMessageListener(t *testing.T) {
	tests := []struct {
		name    string
		send    map[string]int
		want    map[string]int
		sentErr error
		wantErr error
		timeout bool
	}{
		{
			name: "valid",
			send: map[string]int{
				"a": 3, "b": 3, "c": 3,
			},
			want: map[string]int{
				"c": 3,
			},
		},
		{
			name: "timeout",
			send: map[string]int{
				"a": 3, "b": 3,
			},
			want: map[string]int{
				"a": 3, "b": 3, "c": 3,
			},
			wantErr: context.DeadlineExceeded,
			timeout: true,
		},
		{
			name: "receive err",
			send: map[string]int{
				"a": 3, "b": 3,
			},
			want: map[string]int{
				"a": 3, "b": 3, "c": 3,
			},
			sentErr: bytes.ErrTooLarge,
			wantErr: bytes.ErrTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				errCh := make(chan error, 1)
				if tt.sentErr != nil {
					errCh <- tt.sentErr
				}

				if tt.timeout {
					ctx, cancel := context.WithTimeout(t.Context(), 1*time.Minute)
					context.AfterFunc(ctx, func() {
						errCh <- context.DeadlineExceeded
					})
					defer cancel()
				}

				msgCh := make(chan string, 10)
				for k, v := range tt.send {
					for range v {
						msgCh <- k
					}
				}

				err := MessageListener(t, tt.want, errCh, msgCh)
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("expected error %v, got %v", tt.wantErr, err)
				}
			})
		})
	}
}

func TestRandomBytes(t *testing.T) {
	for i := range 1024 {
		b := RandomBytes(i)
		if len(b) != i {
			t.Fatalf("expected len %d, go %d", i, len(b))
		}
	}
}

func TestRandomHash(t *testing.T) {
	for range 100 {
		//nolint:staticcheck // b is used to check len
		b := RandomHash()
		if len(b) != len(chainhash.Hash{}) {
			t.Fatalf("expected len %d, go %d", len(chainhash.Hash{}), len(b))
		}
	}
}

func TestString2Hash(t *testing.T) {
	tests := []struct {
		name string
		str  string
		fail bool
		want chainhash.Hash
	}{
		{
			name: "empty",
			str:  "",
			want: chainhash.Hash{
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "underflow",
			str:  "1000000050f",
			want: chainhash.Hash{
				0x0f, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			},
		},
		{
			name: "overflow",
			str:  "1000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931eextra",
			fail: true,
		},
		{
			name: "invalid",
			str:  "xdty000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e",
			fail: true,
		},
		{
			name: "valid",
			str:  "1000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e",
			want: chainhash.Hash{
				0x1e, 0x93, 0xaa, 0x99, 0xc8, 0xff, 0x97, 0x49,
				0x03, 0x7d, 0x74, 0xa2, 0x20, 0x7f, 0x29, 0x95,
				0x02, 0xfa, 0x81, 0xd5, 0x6a, 0x4e, 0xa2, 0xad,
				0x53, 0x30, 0xff, 0x50, 0x00, 0x00, 0x00, 0x10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil && tt.fail {
					t.Errorf("expected panic")
				} else if r != nil && !tt.fail {
					t.Errorf("unexpected panic")
				}
			}()
			sh := String2Hash(tt.str)
			if !sh.IsEqual(&tt.want) {
				t.Errorf("expected %x, got %s", tt.want, sh.String())
			}
		})
	}
}

func TestBytes2Hash(t *testing.T) {
	tests := []struct {
		name string
		val  []byte
		fail bool
		want chainhash.Hash
	}{
		{
			name: "empty",
			val:  nil,
			fail: true,
		},
		{
			name: "underflow",
			val: []byte{
				0x1e, 0x93, 0xaa, 0x99, 0xc8, 0xff, 0x97, 0x49,
			},
			fail: true,
		},
		{
			name: "overflow",
			val: []byte{
				0x1e, 0x93, 0xaa, 0x99, 0xc8, 0xff, 0x97, 0x49,
				0x03, 0x7d, 0x74, 0xa2, 0x20, 0x7f, 0x29, 0x95,
				0x02, 0xfa, 0x81, 0xd5, 0x6a, 0x4e, 0xa2, 0xad,
				0x53, 0x30, 0xff, 0x50, 0x00, 0x00, 0x00, 0x10,
				0x53, 0x30, 0xff, 0x50, 0x00, 0x00, 0x00, 0x10,
			},
			fail: true,
		},
		{
			name: "valid",
			val: []byte{
				0x1e, 0x93, 0xaa, 0x99, 0xc8, 0xff, 0x97, 0x49,
				0x03, 0x7d, 0x74, 0xa2, 0x20, 0x7f, 0x29, 0x95,
				0x02, 0xfa, 0x81, 0xd5, 0x6a, 0x4e, 0xa2, 0xad,
				0x53, 0x30, 0xff, 0x50, 0x00, 0x00, 0x00, 0x10,
			},
			want: chainhash.Hash{
				0x1e, 0x93, 0xaa, 0x99, 0xc8, 0xff, 0x97, 0x49,
				0x03, 0x7d, 0x74, 0xa2, 0x20, 0x7f, 0x29, 0x95,
				0x02, 0xfa, 0x81, 0xd5, 0x6a, 0x4e, 0xa2, 0xad,
				0x53, 0x30, 0xff, 0x50, 0x00, 0x00, 0x00, 0x10,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil && tt.fail {
					t.Errorf("expected panic")
				} else if r != nil && !tt.fail {
					t.Errorf("unexpected panic %v", r)
				}
			}()
			sh := Bytes2Hash(tt.val)
			if !sh.IsEqual(&tt.want) {
				t.Errorf("expected %x, got %s", tt.want, sh.String())
			}
		})
	}
}

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		name string
		str  string
		fail bool
		want []byte
	}{
		{
			name: "empty",
			str:  "",
		},
		{
			name: "invalid",
			str:  "xdtyzewr80232390",
			fail: true,
		},
		{
			name: "valid",
			str:  "1000000050ff3053ada24e6ad581fa0295297f20a2747d034997ffc899aa931e",
			want: []byte{
				0x10, 0x00, 0x00, 0x00, 0x50, 0xff, 0x30, 0x53,
				0xad, 0xa2, 0x4e, 0x6a, 0xd5, 0x81, 0xfa, 0x02,
				0x95, 0x29, 0x7f, 0x20, 0xa2, 0x74, 0x7d, 0x03,
				0x49, 0x97, 0xff, 0xc8, 0x99, 0xaa, 0x93, 0x1e,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil && tt.fail {
					t.Errorf("expected panic")
				} else if r != nil && !tt.fail {
					t.Errorf("unexpected panic")
				}
			}()
			b := DecodeHex(tt.str)
			if !bytes.Equal(b, tt.want) {
				t.Errorf("expected %x, got %x", tt.want, b)
			}
		})
	}
}

func TestErrorIsOneOf(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		errors []error
		is     bool
	}{
		{
			name: "empty",
		},
		{
			name:   "invalid nil",
			errors: []error{chainhash.ErrHashStrSize},
		},
		{
			name:   "valid nil",
			errors: []error{chainhash.ErrHashStrSize, nil},
			is:     true,
		},
		{
			name:   "is not",
			err:    bytes.ErrTooLarge,
			errors: []error{chainhash.ErrHashStrSize},
			is:     false,
		},
		{
			name:   "is first",
			err:    chainhash.ErrHashStrSize,
			errors: []error{chainhash.ErrHashStrSize, bytes.ErrTooLarge},
			is:     true,
		},
		{
			name:   "is last",
			err:    bytes.ErrTooLarge,
			errors: []error{chainhash.ErrHashStrSize, bytes.ErrTooLarge},
			is:     true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if ErrorIsOneOf(tt.err, tt.errors) != tt.is {
				t.Errorf("expected %v", tt.is)
			}
		})
	}
}
