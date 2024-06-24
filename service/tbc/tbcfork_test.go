// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
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
	t    *testing.T
	port string
	p    *peer

	mtx            sync.RWMutex
	chain          map[string]*btcutil.Block
	blocksAtHeight map[int32][]*btcutil.Block
	height         int32
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
	}

	genesis := btcutil.NewBlock(chaincfg.RegressionNetParams.GenesisBlock)
	genesis.SetHeight(0)
	// node.chain[chaincfg.RegressionNetParams.GenesisHash.String()] = genesis
	_, err := node.insertBlock(genesis)
	if err != nil {
		return nil, err
	}
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

	nmh := wire.NewMsgHeaders()
	height := from.Height() + 1
	b.t.Logf("start from %v", height)
	for range 2000 {
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
			return nil, fmt.Errorf("add header: %w", err)
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
		return nil, errors.New("not supported multi invlist requests")
	}

	v := m.InvList[0]
	if v.Type != wire.InvTypeBlock {
		return nil, fmt.Errorf("unsuported data type: %v", v.Type)
	}

	block, ok := b.chain[v.Hash.String()]
	if !ok {
		return nil, fmt.Errorf("block not found: %v", v.Hash)
	}

	return block.MsgBlock(), nil
}

func (b *btcNode) handleRPC(ctx context.Context, conn net.Conn) {
	b.t.Logf("handleRPC %v", conn.RemoteAddr())
	defer b.t.Logf("handleRPC exit %v", conn.RemoteAddr())

	p := &peer{
		conn:            conn,
		connected:       time.Now(),
		address:         conn.RemoteAddr().String(),
		protocolVersion: wire.AddrV2Version,
		network:         wire.TestNet, // regtest == testnet
	}

	// Send version
	mv := &wire.MsgVersion{
		ProtocolVersion: int32(wire.AddrV2Version),
	}
	if err := p.write(time.Second, mv); err != nil {
		b.t.Logf("write version %v: %v", p, err)
		return
	}

	b.mtx.Lock()
	b.p = p
	b.mtx.Unlock()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		msg, err := p.read()
		if err != nil {
			if errors.Is(err, wire.ErrUnknownMessage) {
				// ignore unknown
				b.t.Log("wire: unknown message")
				continue
			}
			b.t.Logf("peer read %v: %v", p, err)
			return
		}

		if err = b.handleMsg(ctx, p, msg); err != nil {
			b.t.Logf("handle message %v: %v", p, err)
			return
		}
	}
}

func (b *btcNode) handleMsg(ctx context.Context, p *peer, msg wire.Message) error {
	switch m := msg.(type) {
	case *wire.MsgVersion:
		mva := &wire.MsgVerAck{}
		if err := p.write(time.Second, mva); err != nil {
			return fmt.Errorf("write version ack: %w", err)
		}

	case *wire.MsgGetHeaders:
		// b.t.Logf("get headers %v", spew.Sdump(m))
		headers, err := b.handleGetHeaders(m)
		if err != nil {
			return fmt.Errorf("handle get headers: %w", err)
		}
		// b.t.Logf("%v", spew.Sdump(headers))
		if err = p.write(time.Second, headers); err != nil {
			return fmt.Errorf("write headers: %w", err)
		}

	case *wire.MsgGetData:
		// b.t.Logf("get data %v", spew.Sdump(m))
		data, err := b.handleGetData(m)
		if err != nil {
			return fmt.Errorf("handle get data: %w", err)
		}
		// b.t.Logf("%v", spew.Sdump(data))
		if err = p.write(time.Second, data); err != nil {
			return fmt.Errorf("write data: %w", err)
		}

	default:
		b.t.Logf("unhandled command: %v", spew.Sdump(msg))
	}

	return nil
}

func (b *btcNode) SendBlockheader(ctx context.Context, bh wire.BlockHeader) error {
	msg := wire.NewMsgHeaders()
	msg.AddBlockHeader(&bh)
	return b.p.write(defaultCmdTimeout, msg)
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

func newBlockTemplate(params *chaincfg.Params, payToAddress btcutil.Address, nextBlockHeight int32, parent *chainhash.Hash, extraNonce uint64) (*btcutil.Block, error) {
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(params, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}

	reqDifficulty := uint32(0x1d00ffff) // XXX

	var blockTxs []*btcutil.Tx
	blockTxs = append(blockTxs, coinbaseTx)

	msgBlock := &wire.MsgBlock{
		Header: wire.BlockHeader{
			Version:    int32(vbTopBits),
			PrevBlock:  *parent,
			MerkleRoot: blockchain.CalcMerkleRoot(blockTxs, false),
			Timestamp:  time.Now(),
			Bits:       reqDifficulty,
		},
	}
	for _, tx := range blockTxs {
		if err = msgBlock.AddTransaction(tx.MsgTx()); err != nil {
			return nil, fmt.Errorf("add transaction to block: %w", err)
		}
	}

	b := btcutil.NewBlock(msgBlock)
	b.SetHeight(nextBlockHeight)
	return b, nil
}

func (b *btcNode) insertBlock(block *btcutil.Block) (int, error) {
	b.chain[block.Hash().String()] = block
	bAtHeight := b.blocksAtHeight[block.Height()]
	b.blocksAtHeight[block.Height()] = append(bAtHeight, block)
	return len(b.blocksAtHeight[block.Height()]), nil
}

func (b *btcNode) blockHeadersAtHeight(height int32) ([]*wire.BlockHeader, error) {
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

func (b *btcNode) BlockHeadersAtHeight(height int32) ([]*wire.BlockHeader, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	return b.blockHeadersAtHeight(height)
}

func (b *btcNode) Best() []*chainhash.Hash {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	bhs, err := b.blockHeadersAtHeight(b.height)
	if err != nil {
		panic(err)
	}
	chs := make([]*chainhash.Hash, 0, len(bhs))
	for _, v := range bhs {
		ch := v.BlockHash()
		chs = append(chs, &ch)
	}
	return chs
}

func random(count int) []byte {
	b := make([]byte, count)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

func (b *btcNode) Mine(count int, from *chainhash.Hash, payToAddress btcutil.Address) ([]*btcutil.Block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}

	blocks := make([]*btcutil.Block, 0, count)
	for range count {
		// extra nonce is needed to prevent block collisions
		en := random(8)
		extraNonce := binary.BigEndian.Uint64(en)

		nextBlockHeight := parent.Height() + 1
		block, err := newBlockTemplate(b.params, payToAddress, nextBlockHeight,
			parent.Hash(), extraNonce)
		if err != nil {
			return nil, fmt.Errorf("height %v: %w", nextBlockHeight, err)
		}
		blocks = append(blocks, block)
		b.t.Logf("mined %v: %v", nextBlockHeight, block.Hash())

		n, err := b.insertBlock(block)
		if err != nil {
			return nil, fmt.Errorf("insert block at height %v: %v",
				nextBlockHeight, err)
		}
		if n != 1 {
			b.t.Logf("fork at: %v blocks %v", nextBlockHeight, n)
		}
		parent = block
		b.height = nextBlockHeight
	}

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

// XXX: Fix and re-enable test.
// func TestBasic(t *testing.T) {
//	t.Skip()
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//
//	key, address, err := newPKAddress(&chaincfg.RegressionNetParams)
//	if err != nil {
//		t.Fatal(err)
//	}
//	t.Logf("key    : %v", key)
//	t.Logf("address: %v", address)
//
//	n, err := newFakeNode(t, "18444") // TODO: should use random free port
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	go func() {
//		if err := n.Run(ctx); err != nil {
//			panic(fmt.Errorf("node exited with error: %w", err))
//		}
//	}()
//
//	startHash := n.Best()
//	count := 9
//	expectedHeight := uint64(count)
//
//	if _, err = n.Mine(count, startHash[0], address); err != nil {
//		t.Fatal(fmt.Errorf("mine: %w", err))
//	}
//
//	if err = n.dumpChain(n.Best()[0]); err != nil {
//		t.Fatal(fmt.Errorf("dump chain: %w", err))
//	}
//	// t.Logf("%v", spew.Sdump(n.chain[n.Best()[0].String()]))
//	time.Sleep(1 * time.Second) // XXX
//
//	// Connect tbc service
//	cfg := &Config{
//		AutoIndex:     true, // XXX for now
//		BlockSanity:   false,
//		LevelDBHome:   t.TempDir(),
//		ListenAddress: tbcapi.DefaultListen, // TODO: should use random free port
//		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
//		MaxCachedTxs:            1000, // XXX
//		Network:                 networkLocalnet,
//		PrometheusListenAddress: "",
//	}
//	_ = loggo.ConfigureLoggers(cfg.LogLevel)
//	s, err := NewServer(cfg)
//	if err != nil {
//		t.Fatal(err)
//	}
//	s.ignoreUlimit = true
//	go func() {
//		err := s.Run(ctx)
//		if err != nil && !errors.Is(err, context.Canceled) {
//			panic(err)
//		}
//	}()
//
//	for {
//		select {
//		case <-ctx.Done():
//			return
//		case <-time.After(time.Second):
//		}
//
//		// See if we are synced
//		si := s.Synced(ctx)
//		if !(si.Synced && si.BlockHeaderHeight == expectedHeight) {
//			log.Infof("not synced")
//			continue
//		}
//
//		// Execute tests
//		balance, err := s.BalanceByAddress(ctx, address.String())
//		if err != nil {
//			t.Fatal(err)
//		}
//		// TODO: magic numbers should be extract into constants
//		if balance != uint64(count*5000000000) {
//			t.Fatalf("balance got %v wanted %v", balance, count*5000000000)
//		}
//		t.Logf("balance %v", spew.Sdump(balance))
//
//		utxos, err := s.UtxosByAddress(ctx, address.String(), 0, 100)
//		if err != nil {
//			t.Fatal(err)
//		}
//		t.Logf("%v", spew.Sdump(utxos))
//		return
//	}
// }

func TestFork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	key, address, err := newPKAddress(&chaincfg.RegressionNetParams)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("key    : %v", key)
	t.Logf("address: %v", address)

	n, err := newFakeNode(t, "18444") // TODO: should use random free port
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		if err := n.Run(ctx); err != nil {
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
	time.Sleep(500 * time.Millisecond) // XXX

	// Connect tbc service
	cfg := &Config{
		AutoIndex:     false,
		BlockSanity:   false,
		LevelDBHome:   t.TempDir(),
		ListenAddress: tbcapi.DefaultListen, // TODO: should use random free port
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	s.ignoreUlimit = true
	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}

		// See if we are at the right height
		si := s.Synced(ctx)
		if !(si.BlockHeader.Height == expectedHeight) {
			log.Infof("not synced")
			continue
		}

		// Don't execute balance tests if index is disabled.
		if cfg.AutoIndex {
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
		}
		break
	}

	// Check cumulative difficulty
	difficulty, err := s.DifficultyAtHash(ctx, n.Best()[0])
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("----- %x", blockchain.BigToCompact(difficulty))
	t.Logf("difficulty: 0x%064x", difficulty)

	// Advance both heads
	b9 := n.Best()[0]
	b10a, err := n.Mine(1, b9, address)
	if err != nil {
		t.Fatal(err)
	}
	b10b, err := n.Mine(1, b9, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b10a: %v", b10a[0].Hash())
	t.Logf("b10b: %v", b10b[0].Hash())
	b10s := n.Best()
	if len(b10s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b10s))
	}

	// Tell tbcd
	err = n.SendBlockheader(ctx, b10a[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	err = n.SendBlockheader(ctx, b10b[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	// XXX check hashes
	time.Sleep(500 * time.Millisecond)

	// Advance both heads again
	b10aHash := b10a[0].MsgBlock().Header.BlockHash()
	b11a, err := n.Mine(1, &b10aHash, address)
	if err != nil {
		t.Fatal(err)
	}
	b10bHash := b10b[0].MsgBlock().Header.BlockHash()
	b11b, err := n.Mine(1, &b10bHash, address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b11a: %v", b11a[0].Hash())
	t.Logf("b11b: %v", b11b[0].Hash())
	b11s := n.Best()
	if len(b11s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b11s))
	}
	// Tell tbcd
	err = n.SendBlockheader(ctx, b11a[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	err = n.SendBlockheader(ctx, b11b[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	// Let's see if tbcd agrees
	si := s.Synced(ctx)
	// t.Logf("--- %v", si)
	bhsAt11, err := s.BlockHeadersByHeight(ctx, 11)
	if err != nil {
		t.Fatal(err)
	}

	// XXX - this is fragile, audit.  we sometimes get a length of 1
	if len(bhsAt11) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(bhsAt11))
	}
	// XXX check hashes
	// t.Logf("block headers at 11: %v", spew.Sdump(bhsAt11))
	time.Sleep(500 * time.Millisecond)
	if cfg.AutoIndex && !si.Synced {
		t.Fatalf("expected synced chain")
	}

	// Move 10b forward and overtake 11 a/b

	// go from
	//           /-> 11b ->
	// 9 -> 10a  ->  11a ->
	//   \-> 10b ->
	//
	// to
	//
	//           /-> 11b ->
	// 9 -> 10a  ->  11a ->
	//   \-> 10b ->  11c -> 12
	t.Logf("mine 11c")
	b11c, err := n.Mine(1, &b10bHash, address)
	if err != nil {
		t.Fatal(err)
	}
	b11cHash := b11c[0].MsgBlock().Header.BlockHash()
	err = n.SendBlockheader(ctx, b11c[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	// 12
	t.Logf("mine 12")
	b12, err := n.Mine(1, &b11cHash, address)
	if err != nil {
		t.Fatal(err)
	}
	err = n.SendBlockheader(ctx, b12[0].MsgBlock().Header)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)

	t.Logf("did we fork?")

	// Dump best chain
	if err = n.dumpChain(n.Best()[0]); err != nil {
		t.Fatal(err)
	}
}

// XXX this needs to actually test stuff. RN it is visual only.
func TestWork(t *testing.T) {
	reqDifficulty := uint32(0x1d00ffff) // difficulty at genesis
	hmm := (reqDifficulty & 0xf0000000) >> (7 * 4)
	bits := uint32(419465580)
	t.Logf("calc work: %x", hmm)
	t.Logf("calc work: %x", blockchain.CalcWork(reqDifficulty))
	t.Logf("calc work: %v", blockchain.CalcWork(reqDifficulty))
	t.Logf("compact to big: %064x", blockchain.CompactToBig(reqDifficulty))
	t.Logf("compact to big: %v", blockchain.CompactToBig(reqDifficulty))
	targetDifficulty := blockchain.CompactToBig(bits)
	t.Logf("%064x", targetDifficulty.Bytes())

	x := uint32(0x1b0404cb) // difficulty at genesis
	pp := new(big.Rat).SetInt(blockchain.CalcWork(x))
	t.Logf("0x%x: %064x  %v", x, blockchain.CompactToBig(x), pp)

	// big.Int
	// big.Rat
	// func (z *Rat) SetFrac(a, b *Int) *Rat {
	y := "0x00000000ffff0000000000000000000000000000000000000000000000000000"
	yy, ok := new(big.Int).SetString(y, 0)
	if !ok {
		t.Fatal("yy")
	}
	z := "0x00000000000404CB000000000000000000000000000000000000000000000000"
	zz, ok := new(big.Int).SetString(z, 0)
	if !ok {
		t.Fatal("zz")
	}

	xx := new(big.Rat).SetFrac(yy, zz)
	ff, _ := xx.Float64()
	t.Logf("%v: %0.16f", xx, ff)

	// minimum target / target of difficulty
	aaa := blockchain.CalcWork(reqDifficulty)
	_bbb := "0x0000000000000000000000000000000000000000000000000000000900090009"
	bbb, ok := new(big.Int).SetString(_bbb, 0)
	if !ok {
		t.Fatal("bbb")
	}
	zzz := new(big.Rat).SetFrac(bbb, aaa)
	fff, _ := zzz.Float64()
	t.Logf("%v: %0.16f", zzz, fff)

	t.Logf("calc work    : 0x%x 0x%x", 0x170331db, blockchain.CalcWork(0x170331db))
	t.Logf("compact to big: 0x%x", blockchain.CompactToBig(0x170331db))
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
	// specified.  Otherwise, create a script that allows the coinbase to be
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
