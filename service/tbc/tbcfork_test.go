// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api/tbcapi"
)

type btcNode struct {
	mtx            sync.RWMutex
	t              *testing.T
	port           string
	chain          map[string]*btcutil.Block
	blocksAtHeight map[int32][]*btcutil.Block
	height         int
	best           []*chainhash.Hash
	params         *chaincfg.Params
}

func newFakeNode(t *testing.T, port string) (*btcNode, error) {
	node := &btcNode{
		t:              t,
		port:           port,
		chain:          make(map[string]*btcutil.Block, 10),
		blocksAtHeight: make(map[int32][]*btcutil.Block, 10),
		height:         0,
		params:         &chaincfg.RegressionNetParams,
		best:           []*chainhash.Hash{chaincfg.RegressionNetParams.GenesisHash},
	}
	genesis := btcutil.NewBlock(chaincfg.RegressionNetParams.GenesisBlock)
	genesis.SetHeight(0)
	node.chain[chaincfg.RegressionNetParams.GenesisHash.String()] = genesis

	return node, nil
}

func (b *btcNode) handleGetHeaders(m *wire.MsgGetHeaders) (*wire.MsgHeaders, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	if len(m.BlockLocatorHashes) != 1 {
		return nil, fmt.Errorf("get headers: invalid count got %v wanted %v",
			len(m.BlockLocatorHashes), 1)
	}
	locator := m.BlockLocatorHashes[0]
	from, ok := b.chain[locator.String()]
	if !ok {
		return nil, fmt.Errorf("get headers: locator not found %v", locator)
	}

	b.t.Logf("start from %v", from.Height())
	nmh := wire.NewMsgHeaders()
	height := from.Height() + 1
	for i := int32(0); i < 2000; i++ {
		bs, ok := b.blocksAtHeight[height]
		if !ok {
			b.t.Logf("no more blocks at: %v", height)
			return nmh, nil
		}
		if len(bs) != 1 {
			return nil, fmt.Errorf("fork at height: %v", height)
		}
		err := nmh.AddBlockHeader(&bs[0].MsgBlock().Header)
		if err != nil {
			return nil, fmt.Errorf("add header: %v", err)
		}

		b.t.Logf("%v: %v", height, bs[0].MsgBlock().Header.BlockHash())
		height++
	}

	return nmh, nil
}

func (b *btcNode) handleGetData(m *wire.MsgGetData) (*wire.MsgBlock, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	// b.t.Logf("get data: %v", spew.Sdump(m))
	if len(m.InvList) != 1 {
		return nil, fmt.Errorf("not supported multi invlist requests")
	}
	for _, v := range m.InvList {
		if v.Type != wire.InvTypeBlock {
			return nil, fmt.Errorf("unsuported data type: %v", v.Type)
		}
		block, ok := b.chain[v.Hash.String()]
		if !ok {
			return nil, fmt.Errorf("block not found: %v", v.Hash)
		}
		return block.MsgBlock(), nil
	}

	return nil, errors.New("not reached")
}

func (b *btcNode) handleRPC(ctx context.Context, conn net.Conn) {
	b.t.Logf("got conn %v", conn.RemoteAddr())
	defer b.t.Logf("exit conn %v", conn.RemoteAddr())

	p := &peer{
		conn:            conn,
		connected:       time.Now(),
		address:         conn.RemoteAddr().String(),
		protocolVersion: 70016,
		network:         wire.TestNet, // regtest == testnet
	}

	// Send version
	mv := &wire.MsgVersion{
		ProtocolVersion: 70016,
	}
	err := p.write(time.Second, mv)
	if err != nil {
		b.t.Logf("write version %v: %v", p, err)
		return
	}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := p.read()
		if errors.Is(err, wire.ErrUnknownMessage) {
			// skip unknown
			b.t.Log("wire: unknown message")
			continue
		} else if err != nil {
			b.t.Logf("peer read %v: %v", p, err)
			return
		}
		switch m := msg.(type) {
		case *wire.MsgVersion:
			mva := &wire.MsgVerAck{}
			err := p.write(time.Second, mva)
			if err != nil {
				b.t.Logf("write %v: %v", p, err)
				return
			}
			_ = m

		case *wire.MsgGetHeaders:
			b.t.Logf("get headers %v", spew.Sdump(m))
			headers, err := b.handleGetHeaders(m)
			if err != nil {
				b.t.Logf("write %v: %v", p, err)
				return
			}
			// b.t.Logf("%v", spew.Sdump(headers))
			err = p.write(time.Second, headers)
			if err != nil {
				b.t.Logf("write %v: %v", p, err)
				return
			}

		case *wire.MsgGetData:
			b.t.Logf("get data %v", spew.Sdump(m))
			data, err := b.handleGetData(m)
			if err != nil {
				b.t.Logf("write %v: %v", p, err)
				return
			}
			// b.t.Logf("%v", spew.Sdump(data))
			err = p.write(time.Second, data)
			if err != nil {
				b.t.Logf("write %v: %v", p, err)
				return
			}

		default:
			b.t.Logf("unhandled command: %v", spew.Sdump(msg))
		}
	}
}

func (b *btcNode) dumpChain(parent *chainhash.Hash) error {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for {
		block, ok := b.chain[parent.String()]
		if !ok {
			return fmt.Errorf("parent not found: %v", parent)
		}
		b.t.Logf("%v: %v", block.Height(), block.Hash())

		bh := block.MsgBlock().Header
		parent = &bh.PrevBlock
		if block.Height() == 0 {
			return nil
		}
	}
}

func newBlockTemplate(params *chaincfg.Params, payToAddress btcutil.Address, nextBlockHeight int32, parent *chainhash.Hash) (*btcutil.Block, error) {
	extraNonce := uint64(0)
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(params, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}

	reqDifficulty := uint32(0xffffff)

	var blockTxns []*btcutil.Tx
	blockTxns = append(blockTxns, coinbaseTx)

	nextBlockVersion := int32(vbTopBits)
	var msgBlock wire.MsgBlock
	msgBlock.Header = wire.BlockHeader{
		Version:    nextBlockVersion,
		PrevBlock:  *parent,
		MerkleRoot: blockchain.CalcMerkleRoot(blockTxns, false),
		Timestamp:  time.Now(),
		Bits:       reqDifficulty,
	}
	for _, tx := range blockTxns {
		if err := msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, err
		}
	}

	b := btcutil.NewBlock(&msgBlock)
	b.SetHeight(nextBlockHeight)
	return b, nil
}

func (b *btcNode) insertBlock(block *btcutil.Block) (int, error) {
	b.chain[block.Hash().String()] = block
	bAtHeight := b.blocksAtHeight[block.Height()]
	b.blocksAtHeight[block.Height()] = append(bAtHeight, block)
	return len(b.blocksAtHeight[block.Height()]), nil
}

func (b *btcNode) Best() []*chainhash.Hash {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.best
}

func (b *btcNode) BlockHeadersAtHeight(height int32) ([]*wire.BlockHeader, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	bs, ok := b.blocksAtHeight[height]
	if !ok {
		return nil, fmt.Errorf("no block headers at: %v", height)
	}
	bhs := make([]*wire.BlockHeader, 0, len(bs))
	for _, v := range bs {
		bhs = append(bhs, &v.MsgBlock().Header)
	}
	return bhs, nil
}

func (b *btcNode) Mine(count int, from *chainhash.Hash, payToAddress btcutil.Address) ([]*btcutil.Block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("not found")
	}

	blocks := make([]*btcutil.Block, 0, count)
	for i := 0; i < count; i++ {
		nextBlockHeight := parent.Height() + 1
		block, err := newBlockTemplate(b.params, payToAddress, nextBlockHeight,
			parent.Hash())
		if err != nil {
			return nil, fmt.Errorf("height %v: %v", nextBlockHeight, err)
		}
		blocks = append(blocks, block)
		b.t.Logf("mined %v: %v", nextBlockHeight, block.Hash())

		n, err := b.insertBlock(block)
		if err != nil {
			return nil, fmt.Errorf("inser height %v: %v", nextBlockHeight, err)
		}
		_ = n

		parent = block
	}
	// b.t.Logf("Best: %v", spew.Sdump(blocks))
	b.best = []*chainhash.Hash{parent.Hash()}

	return blocks, nil
}

func (b *btcNode) Run(ctx context.Context) error {
	lc := &net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", "localhost:"+b.port)
	if err != nil {
		return err
	}

	for {
		b.t.Logf("waiting for connection")
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go b.handleRPC(ctx, conn)
	}
}

func newPKAddress(params *chaincfg.Params) (*btcec.PrivateKey, *btcutil.AddressPubKey, error) {
	key, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, err
	}

	pk := key.PubKey().SerializeUncompressed()
	address, err := btcutil.NewAddressPubKey(pk, params)
	if err != nil {
		return nil, nil, err
	}
	return key, address, nil
}

func TestBasic(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, address, err := newPKAddress(&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key    : %v", key)
	t.Logf("address: %v", address)

	n, err := newFakeNode(t, "18444")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err = n.Run(ctx)
		if err != nil {
			panic(err)
		}
	}()

	startHash := n.Best()
	count := 9
	expectedHeight := uint64(count)
	_, err = n.Mine(count, startHash[0], address)
	if err != nil {
		t.Fatal(err)
	}
	err = n.dumpChain(n.Best()[0])
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%v", spew.Sdump(n.chain[n.Best()[0].String()]))
	time.Sleep(1 * time.Second) // XXX

	// Connect tbc service
	cfg := &Config{
		AutoIndex:     true, // XXX for now
		BlockSanity:   false,
		LevelDBHome:   t.TempDir(),
		ListenAddress: tbcapi.DefaultListen,
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
	}
	loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.ignoreUlimit = true
	go func() {
		err = s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}

		// See if we are synced
		si := s.Synced(ctx)
		if !(si.Synced && si.BlockHeaderHeight == expectedHeight) {
			log.Infof("not synced")
			continue
		}

		// Execute tests
		balance, err := s.BalanceByAddress(ctx, address.String())
		if err != nil {
			t.Fatal(err)
		}
		if balance != uint64(count*5000000000) {
			t.Fatalf("balance got %v wanted %v", balance, count*5000000000)
		}
		t.Logf("balance %v", spew.Sdump(balance))
		utxos, err := s.UtxosByAddress(ctx, address.String(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v", spew.Sdump(utxos))
		return
	}
}

func TestFork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, address, err := newPKAddress(&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key    : %v", key)
	t.Logf("address: %v", address)

	n, err := newFakeNode(t, "18444")
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err = n.Run(ctx)
		if err != nil {
			panic(err)
		}
	}()

	startHash := n.Best()
	count := 9
	expectedHeight := uint64(count)
	_, err = n.Mine(count, startHash[0], address)
	if err != nil {
		t.Fatal(err)
	}
	err = n.dumpChain(n.Best()[0])
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%v", spew.Sdump(n.chain[n.Best()[0].String()]))
	time.Sleep(1 * time.Second) // XXX

	// Connect tbc service
	cfg := &Config{
		AutoIndex:     false, // XXX for now
		BlockSanity:   false,
		LevelDBHome:   t.TempDir(),
		ListenAddress: tbcapi.DefaultListen,
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
	}
	loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		err = s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}

		// See if we are at the right height
		si := s.Synced(ctx)
		if !(si.BlockHeaderHeight == expectedHeight) {
			log.Infof("not synced")
			continue
		}

		//// Execute tests
		//balance, err := s.BalanceByAddress(ctx, address.String())
		//if err != nil {
		//	t.Fatal(err)
		//}
		//if balance != uint64(count*5000000000) {
		//	t.Fatalf("balance got %v wanted %v", balance, count*5000000000)
		//}
		//t.Logf("balance %v", spew.Sdump(balance))
		//utxos, err := s.UtxosByAddress(ctx, address.String(), 0, 100)
		//if err != nil {
		//	t.Fatal(err)
		//}
		//t.Logf("%v", spew.Sdump(utxos))
		break
	}
}

// borrowed from btcd
//
// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
var (
	CoinbaseFlags = "/P2SH/btcd/"
	vbTopBits     = 0x20000000
)

func standardCoinbaseScript(nextBlockHeight int32, extraNonce uint64) ([]byte, error) {
	return txscript.NewScriptBuilder().AddInt64(int64(nextBlockHeight)).
		AddInt64(int64(extraNonce)).AddData([]byte(CoinbaseFlags)).
		Script()
}

func createCoinbaseTx(params *chaincfg.Params, coinbaseScript []byte, nextBlockHeight int32, addr btcutil.Address) (*btcutil.Tx, error) {
	// Create the script to pay to the provided payment address if one was
	// specified.  Otherwise create a script that allows the coinbase to be
	// redeemable by anyone.
	var pkScript []byte
	if addr != nil {
		var err error
		pkScript, err = txscript.PayToAddrScript(addr)
		if err != nil {
			return nil, err
		}
	} else {
		var err error
		scriptBuilder := txscript.NewScriptBuilder()
		pkScript, err = scriptBuilder.AddOp(txscript.OP_TRUE).Script()
		if err != nil {
			return nil, err
		}
	}

	tx := wire.NewMsgTx(wire.TxVersion)
	tx.AddTxIn(&wire.TxIn{
		// Coinbase transactions have no inputs, so previous outpoint is
		// zero hash and max index.
		PreviousOutPoint: *wire.NewOutPoint(&chainhash.Hash{},
			wire.MaxPrevOutIndex),
		SignatureScript: coinbaseScript,
		Sequence:        wire.MaxTxInSequenceNum,
	})
	tx.AddTxOut(&wire.TxOut{
		Value:    blockchain.CalcBlockSubsidy(nextBlockHeight, params),
		PkScript: pkScript,
	})
	return btcutil.NewTx(tx), nil
}

// end borrowed from btcd
