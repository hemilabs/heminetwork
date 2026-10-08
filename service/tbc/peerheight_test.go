// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
	"github.com/hemilabs/heminetwork/v2/ttl"
)

// TestPeerBehind checks the peer-accept predicate against the best
// header height.
func TestPeerBehind(t *testing.T) {
	const best = 969978 // best header: the network tip during IBD

	tests := []struct {
		name      string
		best      uint64
		lastBlock int32
		want      bool // true == rejected (behind best header)
	}{
		{"peer at tip", best, best, false},
		{"peer one above best", best, best + 1, false},
		{"peer one behind best", best, best - 1, true},
		{"peer far behind during IBD", best, 91128, true},
		{"negative height", best, -1, true},
		{"negative height, fresh node", 0, -1, true},
		{"fresh node accepts anyone", 0, 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peerBehind(tt.lastBlock, tt.best)
			if got != tt.want {
				t.Fatalf("peerBehind(last=%d, best=%d) = %v, want %v",
					tt.lastBlock, tt.best, got, tt.want)
			}
		})
	}
}

// fakeVersionPeer accepts one connection, completes the version
// handshake advertising lastBlock, and reports whether tbc sent it a
// getheaders before the connection closed.
func fakeVersionPeer(t *testing.T, lastBlock int32) (string, <-chan bool) {
	t.Helper()

	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	gotHeaders := make(chan bool, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			gotHeaders <- false
			return
		}
		defer conn.Close()

		read := func() (wire.Message, error) {
			_, msg, _, err := wire.ReadMessageWithEncodingN(conn,
				wire.AddrV2Version, wire.MainNet, wire.LatestEncoding)
			return msg, err
		}
		write := func(msg wire.Message) error {
			_, err := wire.WriteMessageWithEncodingN(conn, msg,
				wire.AddrV2Version, wire.MainNet, wire.LatestEncoding)
			return err
		}

		// tbc sends its version first.
		if _, err := read(); err != nil {
			gotHeaders <- false
			return
		}
		v := wire.NewMsgVersion(&wire.NetAddress{}, &wire.NetAddress{},
			1, lastBlock)
		v.ProtocolVersion = int32(wire.AddrV2Version)
		if err := write(v); err != nil {
			gotHeaders <- false
			return
		}
		if err := write(wire.NewMsgVerAck()); err != nil {
			gotHeaders <- false
			return
		}

		for {
			msg, err := read()
			if errors.Is(err, wire.ErrUnknownMessage) {
				continue
			} else if err != nil {
				gotHeaders <- false
				return
			}
			if _, ok := msg.(*wire.MsgGetHeaders); ok {
				gotHeaders <- true
				return
			}
		}
	}()

	return ln.Addr().String(), gotHeaders
}

// TestHandlePeerGateDuringIBD is the regression test for the IBD stall
// where the peer gate keyed on the indexer height.
//
// During IBD the headers are at the network tip while the indexers sit
// at genesis, because they only run once every block is downloaded.  A
// gate on the indexer height admits every peer, including peers that
// lack the blocks we ask for; those requests expire and the blocks are
// dropped from blocks missing.  handlePeer must reject a peer that is
// behind our best header, and accept one at the tip.
func TestHandlePeerGateDuringIBD(t *testing.T) {
	const tip = 20 // best header height

	tests := []struct {
		name      string
		lastBlock int32
		accepted  bool
	}{
		{"peer behind best header", tip / 2, false},
		{"peer at best header", tip, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newDifficultyTestServer(t, &chaincfg.MainNetParams)

			// Headers to the tip, no blocks, indexers at genesis.
			chain := makeChain(tip, chaincfg.MainNetParams.GenesisBlock.Header,
				chaincfg.MainNetParams.PowLimitBits, 10*time.Minute)
			insertHeaders(t, s, chain)
			s.ui = &stubIndexer{bh: &tbcd.BlockHeader{
				Hash:   *chaincfg.MainNetParams.GenesisHash,
				Height: 0,
			}}

			var err error
			s.blocks, err = ttl.New(defaultPendingBlocks, true)
			if err != nil {
				t.Fatal(err)
			}
			s.pings, err = ttl.New(1, true)
			if err != nil {
				t.Fatal(err)
			}
			s.pm, err = NewPeerManager(wire.MainNet, []string{}, 1)
			if err != nil {
				t.Fatal(err)
			}

			addr, gotHeaders := fakeVersionPeer(t, tt.lastBlock)
			p, err := rawpeer.New(wire.MainNet, 0, addr)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Connect(t.Context()); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { p.Close() })

			// An accepted peer stays in the read loop until the fake
			// peer closes the connection after the getheaders.  A
			// rejected peer returns at once; close it, as the
			// caller in Run does, so the fake peer sees EOF.
			done := make(chan error, 1)
			go func() { done <- s.handlePeer(t.Context(), p) }()

			var herr error
			select {
			case herr = <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("timeout waiting for handlePeer")
			}
			p.Close()

			var sent bool
			select {
			case sent = <-gotHeaders:
			case <-time.After(10 * time.Second):
				t.Fatal("timeout waiting for fake peer")
			}

			if sent != tt.accepted {
				t.Fatalf("getheaders sent = %v, want %v (handlePeer: %v)",
					sent, tt.accepted, herr)
			}
			if !tt.accepted {
				want := fmt.Sprintf("remote peer height %v below ours %v",
					tt.lastBlock, tip)
				if herr == nil || herr.Error() != want {
					t.Fatalf("handlePeer = %v, want peer height reject", herr)
				}
			}
		})
	}
}
