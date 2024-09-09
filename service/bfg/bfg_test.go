// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package bfg

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"testing"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btcwire "github.com/btcsuite/btcd/wire"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/bitcoin"
	"github.com/hemilabs/heminetwork/hemi"
)

// BitcoinFinality used to be in production code, it has been removed but
// we want to keep tests around its structure, so define it here
type BitcoinFinality struct {
	HEMIHeader          *hemi.Header    `json:"hemi_header"`
	BTCFinalityHeight   uint64          `json:"btc_finality_height"`
	BTCHeight           uint64          `json:"btc_height"`
	BTCRawBlockHeader   api.ByteSlice   `json:"btc_raw_block_header"`
	BTCRawTransaction   api.ByteSlice   `json:"btc_raw_transaction"`
	BTCTransactionIndex uint32          `json:"btc_transaction_index"`
	BTCMerkleHashes     []api.ByteSlice `json:"btc_merkle_hashes"`
	POPMinerPublicKey   api.ByteSlice   `json:"pop_miner_public_key"`
}

func checkBitcoinFinality(bf *BitcoinFinality) error {
	// Parse BTC block header and transaction.
	btcHeader := &btcwire.BlockHeader{}
	if err := btcHeader.Deserialize(bytes.NewReader(bf.BTCRawBlockHeader)); err != nil {
		return fmt.Errorf("deserialize BTC header: %w", err)
	}
	btcTransaction := &btcwire.MsgTx{}
	if err := btcTransaction.Deserialize(bytes.NewReader(bf.BTCRawTransaction)); err != nil {
		return fmt.Errorf("deserialize BTC transaction: %w", err)
	}
	btcTxHash := btcchainhash.DoubleHashB(bf.BTCRawTransaction)

	// Verify transaction to block header.
	var merkleHashes [][]byte
	for _, merkleHash := range bf.BTCMerkleHashes {
		merkleHashes = append(merkleHashes, merkleHash)
	}
	if err := bitcoin.CheckMerkleChain(btcTxHash, bf.BTCTransactionIndex, merkleHashes, btcHeader.MerkleRoot[:]); err != nil {
		return fmt.Errorf("verify merkle path for transaction: %w", err)
	}

	// XXX - verify HEMI keystone header and PoP miner public key.

	return nil
}

func testBitcoinFinality() *BitcoinFinality {
	return &BitcoinFinality{
		BTCHeight: 2530685,
		BTCMerkleHashes: []api.ByteSlice{
			[]byte{
				0x69, 0x9d, 0x14, 0xb7, 0xbb, 0xe6, 0x87, 0x7a,
				0x6c, 0x30, 0x1e, 0xdd, 0x60, 0xa5, 0x0d, 0x63,
				0x6c, 0xae, 0xe4, 0xdb, 0x4a, 0xce, 0x82, 0xbf,
				0x62, 0xc0, 0xc8, 0xf1, 0xdd, 0x89, 0x98, 0xa3,
			},
			[]byte{
				0x18, 0xf5, 0xbd, 0x44, 0xf1, 0xea, 0x94, 0x43,
				0x7e, 0x15, 0xe7, 0xa3, 0x98, 0xd2, 0x5e, 0xb0,
				0x68, 0x0a, 0x0b, 0xdd, 0xf5, 0x08, 0xd7, 0xbb,
				0xc8, 0xa0, 0x90, 0x35, 0x3e, 0x3a, 0x28, 0x1e,
			},
			[]byte{
				0xa5, 0xee, 0xe1, 0x40, 0x78, 0x15, 0xca, 0x16,
				0xa8, 0x95, 0xab, 0x3a, 0xe9, 0xe6, 0xa6, 0x85,
				0x81, 0x79, 0x90, 0x10, 0xfd, 0x99, 0x89, 0x29,
				0x0b, 0xdf, 0xbe, 0xf0, 0xf6, 0x0a, 0x97, 0x57,
			},
			[]byte{
				0x94, 0xd0, 0xb0, 0x0a, 0x81, 0x59, 0x3e, 0xc3,
				0xfe, 0xb8, 0xba, 0x26, 0xf4, 0x0b, 0x9e, 0x6d,
				0x1a, 0x90, 0xdc, 0xac, 0x8e, 0x8d, 0xdc, 0x97,
				0xf4, 0x7e, 0xff, 0xcb, 0x4d, 0xb7, 0x5c, 0xb7,
			},
			[]byte{
				0x21, 0x9d, 0xa2, 0xe3, 0x06, 0x0d, 0x64, 0xfe,
				0x95, 0xe5, 0x24, 0xc6, 0x39, 0x4f, 0x21, 0xd2,
				0xa1, 0x78, 0x30, 0x34, 0x23, 0xbc, 0x8a, 0x74,
				0xa2, 0xf7, 0x71, 0x1d, 0x9f, 0xb1, 0x0f, 0x58,
			},
		},
		BTCRawBlockHeader: []byte{
			0x00, 0x00, 0xc0, 0x20, 0x3c, 0x43, 0x87, 0x05,
			0xaf, 0x3b, 0x7f, 0x28, 0x4f, 0x8b, 0x79, 0xf3,
			0xf4, 0x94, 0xa0, 0x8f, 0x75, 0x70, 0x32, 0x58,
			0x69, 0x2d, 0x58, 0xe5, 0x03, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x6a, 0x00, 0xac, 0xda,
			0xdd, 0x1b, 0xff, 0xb8, 0xe5, 0xb8, 0x05, 0x41,
			0x33, 0xbd, 0x52, 0xa2, 0x25, 0xfb, 0x3f, 0x9e,
			0xcb, 0x0f, 0x41, 0x11, 0xd5, 0x21, 0xdc, 0xef,
			0xd3, 0x5d, 0xe8, 0xf6, 0xc5, 0x36, 0x20, 0x65,
			0x8c, 0xec, 0x00, 0x1a, 0x02, 0xb2, 0x9c, 0xab,
		},
		BTCRawTransaction: []byte{
			0x02, 0x00, 0x00, 0x00, 0x01, 0x2e, 0x2c, 0x5c,
			0xd1, 0x3e, 0x0f, 0x26, 0x04, 0xc9, 0x67, 0x90,
			0xaa, 0xc2, 0x04, 0x42, 0xc4, 0xac, 0x71, 0x8e,
			0xfc, 0x9e, 0x9c, 0xe7, 0xb7, 0x37, 0xfc, 0xfe,
			0x4c, 0x4f, 0xd6, 0x3f, 0x09, 0x01, 0x00, 0x00,
			0x00, 0x6a, 0x47, 0x30, 0x44, 0x02, 0x20, 0x7c,
			0x88, 0x78, 0xcf, 0x03, 0x66, 0x64, 0xdf, 0xbf,
			0x63, 0x8e, 0xd0, 0x76, 0x0a, 0x1d, 0x00, 0x18,
			0xe3, 0xd1, 0xba, 0xe6, 0xee, 0xeb, 0x1f, 0x41,
			0xed, 0x77, 0x72, 0x57, 0xfa, 0xbd, 0x1b, 0x02,
			0x20, 0x4d, 0x2e, 0x48, 0x43, 0x11, 0x48, 0x68,
			0xe9, 0x15, 0x5c, 0x96, 0xdc, 0xe0, 0xed, 0x10,
			0x2c, 0xd2, 0xb6, 0x79, 0x5c, 0xac, 0x5e, 0x91,
			0x2a, 0xc6, 0x25, 0xb1, 0x51, 0xbf, 0x67, 0x9d,
			0x11, 0x01, 0x21, 0x03, 0x9d, 0x3b, 0x17, 0x47,
			0x09, 0x36, 0x48, 0xca, 0x02, 0x13, 0xd3, 0xea,
			0x41, 0x8d, 0x7e, 0x1a, 0x5e, 0x37, 0xb7, 0x98,
			0xf6, 0xf6, 0xdf, 0x4f, 0xc9, 0xa1, 0x7a, 0x6e,
			0x90, 0xde, 0xaa, 0x12, 0xff, 0xff, 0xff, 0xff,
			0x02, 0xbf, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x19, 0x76, 0xa9, 0x14, 0xdc, 0x11, 0xbb,
			0xaf, 0xe2, 0x3f, 0xdd, 0xca, 0x0e, 0xaf, 0xd5,
			0xf7, 0xb3, 0x2c, 0x9d, 0x67, 0x54, 0xca, 0x73,
			0x4e, 0x88, 0xac, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x46, 0x6a, 0x44, 0x78, 0x79,
			0x7a, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x15, 0xfe, 0x01, 0xd8,
			0x46, 0xd9, 0xf5, 0x15, 0x0f, 0x40, 0x7e, 0x86,
			0xc1, 0x1f, 0x80, 0xc2, 0x69, 0x5f, 0x93, 0xd3,
			0x2e, 0x3b, 0x08, 0x3c, 0x4b, 0xf9, 0xdf, 0x97,
			0xf3, 0xa2, 0xa2, 0xa2, 0x5a, 0x73, 0x13, 0x75,
			0xcc, 0xb9, 0x7c, 0x9d, 0x26, 0x00,
		},
		BTCTransactionIndex: 19,
	}
}

func TestCheckBitcoinFinality(t *testing.T) {
	bf := testBitcoinFinality()
	if err := checkBitcoinFinality(bf); err != nil {
		t.Errorf("Bitcoin finality check failed: %v", err)
	}

	// Truncate raw bitcoin header.
	bf = testBitcoinFinality()
	bf.BTCRawBlockHeader = bf.BTCRawBlockHeader[:len(bf.BTCRawBlockHeader)-1]
	if err := checkBitcoinFinality(bf); err == nil {
		t.Error("Bitcoin finality succeeded, should have failed")
	}

	// Change TX hash, causing the merkle chain verification to fail.
	bf = testBitcoinFinality()
	bf.BTCRawTransaction[0] = 0x03
	if err := checkBitcoinFinality(bf); err == nil {
		t.Error("Bitcoin finality succeeded, should have failed")
	}

	// Change the transaction index, causing the merkle chain verification to fail.
	bf = testBitcoinFinality()
	bf.BTCTransactionIndex = 20
	if err := checkBitcoinFinality(bf); err == nil {
		t.Error("Bitcoin finality succeeded, should have failed")
	}
}

func TestServerRemoteIP(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		remoteIPHeaders []string
		trustedProxies  []*net.IPNet
		req             *http.Request
		want            string
	}{
		{
			name: "localhost-no-headers",
			req: &http.Request{
				RemoteAddr: "127.0.0.1:54864",
			},
			want: "127.0.0.1",
		},
		{
			name: "localhost-spoofed-xforwardedfor",
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4"},
				},
				RemoteAddr: "127.0.0.1:49488",
			},
			want: "127.0.0.1",
		},
		{
			name: "more-realistic",
			remoteIPHeaders: []string{
				"X-Forwarded-For",
			},
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4"},
				},
				RemoteAddr: "10.4.0.1:41587",
			},
			want: "1.2.3.4", // Value of X-Forwarded-For header.
		},
		{
			name: "multiple-trusted",
			remoteIPHeaders: []string{
				"X-Forwarded-For",
			},
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4, 10.1.0.1, 10.1.1.2"},
				},
				RemoteAddr: "10.1.2.3:44792",
			},
			want: "1.2.3.4",
		},
		{
			name: "multiple-untrusted",
			remoteIPHeaders: []string{
				"X-Forwarded-For",
			},
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4, 2.3.4.5"},
				},
				RemoteAddr: "10.1.2.3:43111",
			},
			want: "2.3.4.5", // First untrusted IP address must be used.
		},
		{
			name: "header-untrusted-remoteaddr",
			remoteIPHeaders: []string{
				"X-Forwarded-For",
			},
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{"1.2.3.4, 2.3.4.5, 10.0.1.2"},
				},
				RemoteAddr: "4.3.2.1:43111",
			},
			want: "4.3.2.1",
		},
		{
			name: "multiple-header-values",
			remoteIPHeaders: []string{
				"X-Forwarded-For",
			},
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			req: &http.Request{
				Header: http.Header{
					"X-Forwarded-For": []string{
						"1.2.3.4, 2.3.4.5, 10.1.1.1",
						"10.2.2.2, 10.3.3.3",
					},
				},
				RemoteAddr: "10.3.4.1:43111",
			},
			want: "2.3.4.5",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				remoteIPHeaders: tt.remoteIPHeaders,
				trustedProxies:  tt.trustedProxies,
			}

			if got := s.remoteIP(tt.req); got != tt.want {
				t.Errorf("remoteIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestServerParseForwardedHeader(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		trustedProxies []*net.IPNet
		input          []string
		want           string
		ok             bool
	}{
		{
			name: "empty",
			ok:   false,
		},
		{
			name: "localhost",
			input: []string{
				"127.0.0.1",
			},
			want: "127.0.0.1",
			ok:   true,
		},
		{
			name: "localhost-ipv6",
			input: []string{
				"::1",
			},
			want: "::1",
			ok:   true,
		},
		{
			name: "client-ip",
			input: []string{
				"1.2.3.4",
			},
			want: "1.2.3.4",
			ok:   true,
		},
		{
			name: "one-trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.2.3.4, 10.1.4.1",
			},
			want: "1.2.3.4",
			ok:   true,
		},
		{
			name: "multiple-trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.2.3.4, 10.1.4.1, 10.2.2.1",
			},
			want: "1.2.3.4",
			ok:   true,
		},
		{
			name: "multiple-untrusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.2.3.4, 2.3.4.5, 10.1.1.1, 10.2.2.2",
			},
			want: "2.3.4.5", // The first untrusted IP must be returned.
			ok:   true,
		},
		{
			name: "all-trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"10.1.1.1, 10.1.2.1, 10.1.3.1, 10.1.4.1",
			},
			want: "10.1.1.1", // If they are all trusted, return the first IP.
			ok:   true,
		},
		{
			name: "all-untrusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.0.0.1, 1.0.0.2, 1.0.0.3, 1.0.0.4",
			},
			want: "1.0.0.4", // The first untrusted IP must be returned.
			ok:   true,
		},
		{
			name: "multiple-header-values",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.2.3.4, 10.1.1.1, 10.2.2.1",
				"10.3.3.1, 10.4.4.4",
			},
			want: "1.2.3.4",
			ok:   true,
		},
		{
			name: "multiple-header-values-two-untrusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"1.2.4.5, 10.1.1.1, 10.2.2.1",
				"10.3.3.1, 1.2.3.4, 10.4.4.4",
			},
			want: "1.2.3.4", // The first untrusted IP must be returned.
			ok:   true,
		},
		{
			name: "ipv6",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("2001:db8:a1:b2::/64"),
			},
			input: []string{
				"2001:ffff::1, 2001:db8:a1:b2::1",
			},
			want: "2001:ffff::1",
			ok:   true,
		},
		{
			name: "ipv6-ipv4",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: []string{
				"2001:ffff::1, 10.1.1.1",
			},
			want: "2001:ffff::1",
			ok:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				trustedProxies: tt.trustedProxies,
			}

			got, ok := s.parseForwardedHeader(tt.input)
			if got != tt.want {
				t.Errorf("parseForwardedHeader(%q) value = %v, want %v",
					tt.input, got, tt.want)
			}
			if ok != tt.ok {
				t.Errorf("parseForwardedHeader(%q) ok = %v, want %v",
					tt.input, ok, tt.ok)
			}
		})
	}
}

func TestServerIsTrustedProxy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		trustedProxies []*net.IPNet
		input          string
		want           bool
	}{
		{
			name: "empty",
			want: false,
		},
		{
			name:  "localhost",
			input: "127.0.0.1",
			want:  false,
		},
		{
			name:  "localhost-ipv6",
			input: "::1",
			want:  false,
		},
		{
			name: "localhost-trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("127.0.0.0/8"),
			},
			input: "127.0.0.1",
			want:  true,
		},
		{
			name: "localhost-ipv6-trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("::1/128"),
			},
			input: "::1",
			want:  true,
		},
		{
			name: "trusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: "10.1.2.3",
			want:  true,
		},
		{
			name: "untrusted",
			trustedProxies: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
			},
			input: "1.2.3.4",
			want:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				trustedProxies: tt.trustedProxies,
			}

			if ok := s.isTrustedProxy(net.ParseIP(tt.input)); ok != tt.want {
				t.Errorf("isTrustedProxy(%q) = %v, want %v",
					tt.input, ok, tt.want)
			}
		})
	}
}

func TestParseTrustedProxies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   []string
		want    []*net.IPNet
		wantErr bool
	}{
		{
			name:  "nil",
			input: nil,
			want:  nil,
		},
		{
			name:  "empty",
			input: []string{},
			want:  nil,
		},
		{
			name: "ipv4",
			input: []string{
				"127.0.0.1",
			},
			want: []*net.IPNet{
				mustParseCIDR("127.0.0.1/32"),
			},
		},
		{
			name: "ipv6",
			input: []string{
				"2001:db8::1",
			},
			want: []*net.IPNet{
				mustParseCIDR("2001:db8::1/128"),
			},
		},
		{
			name: "cidr",
			input: []string{
				"192.0.2.0/24",
			},
			want: []*net.IPNet{
				mustParseCIDR("192.0.2.0/24"),
			},
		},
		{
			name: "ipv4-ipv6",
			input: []string{
				"10.0.0.0/8",
				"2001:db8::/32",
			},
			want: []*net.IPNet{
				mustParseCIDR("10.0.0.0/8"),
				mustParseCIDR("2001:db8::/32"),
			},
		},
		{
			name: "invalid",
			input: []string{
				"hello world",
			},
			wantErr: true,
		},
		{
			name: "invalid-ipv4-cidr",
			input: []string{
				"10.0.0.0/256",
			},
			wantErr: true,
		},
		{
			name: "invalid-ipv6-cidr",
			input: []string{
				"2001:db8::/256",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTrustedProxies(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseTrustedProxies(%q) error = %v, wantErr %v",
					tt.input, err, tt.wantErr)
				return
			}

			if diff := deep.Equal(got, tt.want); len(diff) > 0 {
				t.Errorf("parseTrustedProxies(%q):\n%s", tt.input, diff)
			}
		})
	}
}

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Errorf("parse CIDR %s: %w", s, err))
	}
	return ipNet
}

func TestSingleCIDR(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input   string
		want    string
		wantErr bool
	}{
		{
			input: "127.0.0.1",
			want:  "127.0.0.1/32",
		},
		{
			input: "1.2.3.4",
			want:  "1.2.3.4/32",
		},
		{
			input: "192.168.0.1",
			want:  "192.168.0.1/32",
		},
		{
			input: "2001:db8:3333:4444:5555:6666:7777:8888",
			want:  "2001:db8:3333:4444:5555:6666:7777:8888/128",
		},
		{
			input: "2001:db8::1234:5678",
			want:  "2001:db8::1234:5678/128",
		},
		{
			input: "2001:db8:1::ab9:C0A8:102",
			want:  "2001:db8:1::ab9:C0A8:102/128",
		},
		{
			input: "2001:0db8:0001:0000:0000:0ab9:C0A8:0102",
			want:  "2001:0db8:0001:0000:0000:0ab9:C0A8:0102/128",
		},
		{
			input:   "",
			wantErr: true,
		},
		{
			input:   "::1/128",
			wantErr: true,
		},
		{
			input:   "127.0.0.1/32",
			wantErr: true,
		},
		{
			input:   "1.2",
			wantErr: true,
		},
		{
			input:   "hello world",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := singleCIDR(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("singleCIDR(%q) error = %v, wantErr %v",
					tt.input, err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("singleCIDR(%q) got = %v, want %v",
					tt.input, got, tt.want)
			}
		})
	}
}
