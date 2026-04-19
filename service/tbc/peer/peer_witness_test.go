// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package peer

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
)

// newLoopbackPeer builds a Peer whose transport is the client end
// of a net.Pipe.  The server end is returned so the caller can
// read/write wire messages directly.  readLoop is started; callers
// must cancel ctx to tear down.
func newLoopbackPeer(t *testing.T, ctx context.Context) (*Peer, *rawpeer.RawPeer) {
	t.Helper()
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
	})

	clientRP, err := rawpeer.NewFromConn(clientConn, wire.TestNet3, wire.AddrV2Version, 0)
	if err != nil {
		t.Fatal(err)
	}
	serverRP, err := rawpeer.NewFromConn(serverConn, wire.TestNet3, wire.AddrV2Version, 0)
	if err != nil {
		t.Fatal(err)
	}

	p := &Peer{
		wg:          new(sync.WaitGroup),
		p:           clientRP,
		chainParams: &chaincfg.TestNet3Params,
		handlers:    make(map[string]func(context.Context, wire.Message) error, 16),
		pending:     make(map[string]chan wire.Message, 64),
	}
	// Wire up the same default handlers New() installs.
	p.setHandler(wire.CmdBlock, p.onBlockHandler)
	p.setHandler(wire.CmdTx, p.onTxHandler)
	p.setHandler(wire.CmdInv, p.onInvHandler)
	p.setHandler(wire.CmdNotFound, p.onNotFoundHandler)

	p.wg.Add(1)
	go p.readLoop(ctx)

	return p, serverRP
}

// TestGetDataWitnessBlock verifies that GetData with
// InvTypeWitnessBlock (a) sends the witness InvType on the wire
// and (b) correctly pairs the reply via the base-form pending
// key so onBlockHandler can deliver it.
func TestGetDataWitnessBlock(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	p, srv := newLoopbackPeer(t, ctx)

	// Build block first, derive its hash, then request that hash.
	prev := chainhash.DoubleHashH([]byte("prev"))
	bh := wire.NewBlockHeader(0, &prev, &chainhash.Hash{}, 0, 0)
	bh.Timestamp = time.Unix(0, 0)
	block := wire.NewMsgBlock(bh)
	blockHash := block.Header.BlockHash()

	type result struct {
		msg any
		err error
	}
	resultC := make(chan result, 1)
	go func() {
		msg, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeWitnessBlock, &blockHash))
		resultC <- result{msg, err}
	}()

	// Server side: read the outbound MsgGetData.
	msg, _, err := srv.Read(2 * time.Second)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	gd, ok := msg.(*wire.MsgGetData)
	if !ok {
		t.Fatalf("expected MsgGetData, got %T", msg)
	}
	if len(gd.InvList) != 1 {
		t.Fatalf("expected 1 inv, got %d", len(gd.InvList))
	}
	// The wire must carry the witness type — this is the fix.
	if gd.InvList[0].Type != wire.InvTypeWitnessBlock {
		t.Fatalf("expected InvTypeWitnessBlock on wire, got %v", gd.InvList[0].Type)
	}

	// Reply with the block.
	if err := srv.Write(2*time.Second, block); err != nil {
		t.Fatalf("server write block: %v", err)
	}

	r := <-resultC
	if r.err != nil {
		t.Fatalf("GetData: %v", r.err)
	}
	if _, ok := r.msg.(*wire.MsgBlock); !ok {
		t.Fatalf("expected *wire.MsgBlock, got %T", r.msg)
	}
}

// TestGetDataWitnessTx does the same for InvTypeWitnessTx.
func TestGetDataWitnessTx(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	p, srv := newLoopbackPeer(t, ctx)

	// Build tx first, derive its hash, then request that hash.
	tx := wire.NewMsgTx(2)
	prevHash := chainhash.DoubleHashH([]byte("prev-outpoint"))
	tx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: prevHash, Index: 0},
	})
	tx.AddTxOut(&wire.TxOut{Value: 1000, PkScript: []byte{0x6a}})
	txHash := tx.TxHash()

	type result struct {
		msg any
		err error
	}
	resultC := make(chan result, 1)
	go func() {
		msg, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeWitnessTx, &txHash))
		resultC <- result{msg, err}
	}()

	// Read the outbound MsgGetData.
	msg, _, err := srv.Read(2 * time.Second)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	gd, ok := msg.(*wire.MsgGetData)
	if !ok {
		t.Fatalf("expected MsgGetData, got %T", msg)
	}
	if gd.InvList[0].Type != wire.InvTypeWitnessTx {
		t.Fatalf("expected InvTypeWitnessTx on wire, got %v", gd.InvList[0].Type)
	}

	// Reply with the tx.
	if err := srv.Write(2*time.Second, tx); err != nil {
		t.Fatalf("server write tx: %v", err)
	}

	r := <-resultC
	if r.err != nil {
		t.Fatalf("GetData: %v", r.err)
	}
	if _, ok := r.msg.(*wire.MsgTx); !ok {
		t.Fatalf("expected *wire.MsgTx, got %T", r.msg)
	}
}

// TestGetDataBaseBlockStillWorks confirms the base (non-witness)
// InvType still pairs correctly — the strip is a no-op for
// non-witness requests.
func TestGetDataBaseBlockStillWorks(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	p, srv := newLoopbackPeer(t, ctx)

	prev := chainhash.DoubleHashH([]byte("base-prev"))
	bh := wire.NewBlockHeader(0, &prev, &chainhash.Hash{}, 0, 0)
	bh.Timestamp = time.Unix(0, 0)
	block := wire.NewMsgBlock(bh)
	blockHash := block.Header.BlockHash()

	type result struct {
		msg any
		err error
	}
	resultC := make(chan result, 1)
	go func() {
		msg, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeBlock, &blockHash))
		resultC <- result{msg, err}
	}()

	msg, _, err := srv.Read(2 * time.Second)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	gd := msg.(*wire.MsgGetData)
	if gd.InvList[0].Type != wire.InvTypeBlock {
		t.Fatalf("expected InvTypeBlock on wire, got %v", gd.InvList[0].Type)
	}

	if err := srv.Write(2*time.Second, block); err != nil {
		t.Fatalf("server write: %v", err)
	}

	r := <-resultC
	if r.err != nil {
		t.Fatalf("GetData: %v", r.err)
	}
}

// TestGetDataNotFound confirms MsgNotFound replies are delivered
// through the pending map correctly for witness-variant requests.
func TestGetDataNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	p, srv := newLoopbackPeer(t, ctx)

	hash := chainhash.DoubleHashH([]byte("missing-block"))

	type result struct {
		msg any
		err error
	}
	resultC := make(chan result, 1)
	go func() {
		msg, err := p.GetData(ctx, wire.NewInvVect(wire.InvTypeWitnessBlock, &hash))
		resultC <- result{msg, err}
	}()

	// Read the outbound getdata.
	if _, _, err := srv.Read(2 * time.Second); err != nil {
		t.Fatal(err)
	}

	// Reply with NotFound.
	nf := wire.NewMsgNotFound()
	if err := nf.AddInvVect(wire.NewInvVect(wire.InvTypeBlock, &hash)); err != nil {
		t.Fatal(err)
	}
	if err := srv.Write(2*time.Second, nf); err != nil {
		t.Fatalf("server write notfound: %v", err)
	}

	r := <-resultC
	if r.err != nil {
		t.Fatalf("GetData: %v", r.err)
	}
	if _, ok := r.msg.(*wire.MsgNotFound); !ok {
		t.Fatalf("expected *wire.MsgNotFound, got %T", r.msg)
	}
}
