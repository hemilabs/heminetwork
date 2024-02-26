// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package auth

import (
	"bytes"
	"testing"
)

func TestAuthenticateMessage(t *testing.T) {
	tests := []struct {
		name   string
		am     *AuthenticateMessage
		fuzzer func(*AuthenticateMessage)
		want   bool
	}{
		{
			name: "with text",
			am: &AuthenticateMessage{
				Nonce:   [nonceLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Message: "Hello, World!",
			},
			want: true,
		},
		{
			name: "with random nonce",
			am:   MustNewAuthenticateMessage("Hello, World!"),
			want: true,
		},
		{
			name: "no text",
			am: &AuthenticateMessage{
				Nonce:   [nonceLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Message: "",
			},
			want: true,
		},
		{
			name: "nonce fuzzed",
			am: &AuthenticateMessage{
				Nonce:   [nonceLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Message: "",
			},
			fuzzer: func(am *AuthenticateMessage) {
				am.Nonce[0]++
			},
			want: false,
		},
		{
			name: "message fuzzed",
			am: &AuthenticateMessage{
				Nonce:   [nonceLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Message: "",
			},
			fuzzer: func(am *AuthenticateMessage) {
				am.Message = "hi"
			},
			want: false,
		},
		{
			name: "message fuzzed 2",
			am: &AuthenticateMessage{
				Nonce:   [nonceLength]byte{1, 2, 3, 4, 5, 6, 7, 8},
				Message: "hI",
			},
			fuzzer: func(am *AuthenticateMessage) {
				am.Message = "hi"
			},
			want: false,
		},
	}

	for i, test := range tests {
		am, err := NewAuthenticateFromBytes(test.am.Serialize())
		if err != nil {
			t.Fatalf("test %v (%v) %v", i, test.name, err)
		}
		if test.fuzzer != nil {
			test.fuzzer(test.am)
		}
		want := bytes.Equal(am.Hash(), test.am.Hash())
		if want != test.want {
			t.Fatalf("test %v (%v) want != test.want (%v != %v)",
				i, test.name, want, test.want)
		}
	}
}
