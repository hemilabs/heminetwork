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
	"github.com/hemilabs/heminetwork/database/tbcd"
)

type block struct {
	name string
	b    *btcutil.Block

	txs map[tbcd.TxKey]*tbcd.TxValue // Parsed Txs in cache format
}

func newBlock(params *chaincfg.Params, name string, b *btcutil.Block) *block {
	blk := &block{
		name: name,
		b:    b,
		txs:  make(map[tbcd.TxKey]*tbcd.TxValue, 10),
	}
	err := processTxs(params, b.Hash(), b.Transactions(), blk.txs)
	if err != nil {
		panic(fmt.Errorf("processTxs: %v", err))
	}
	return blk
}

func (b block) Hash() *chainhash.Hash {
	return b.b.Hash()
}

func (b block) Height() int32 {
	return b.b.Height()
}

func (b block) MsgBlock() *wire.MsgBlock {
	return b.b.MsgBlock()
}

func (b block) String() string {
	return fmt.Sprintf("%v: %v %v", b.name, b.Height(), b.Hash())
}

type btcNode struct {
	t    *testing.T // for logging
	le   bool       // log enable
	port string
	p    *peer

	mtx            sync.RWMutex
	chain          map[string]*block
	blocksAtHeight map[int32][]*block
	height         int32
	params         *chaincfg.Params
	genesis        *block
}

func newFakeNode(t *testing.T, port string) (*btcNode, error) {
	genesis := btcutil.NewBlock(chaincfg.RegressionNetParams.GenesisBlock)
	genesis.SetHeight(0)
	node := &btcNode{
		t:              t,
		le:             false,
		port:           port,
		chain:          make(map[string]*block, 10),
		blocksAtHeight: make(map[int32][]*block, 10),
		height:         0,
		params:         &chaincfg.RegressionNetParams,
	}
	node.genesis = newBlock(node.params, "genesis", genesis)
	_, err := node.insertBlock(node.genesis)
	if err != nil {
		return nil, err
	}
	return node, nil
}

func (b *btcNode) logf(format string, args ...any) {
	if !b.le {
		return
	}
	b.t.Logf(format, args...)
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
	b.logf("start from %v", height)
	for range 2000 {
		bs, ok := b.blocksAtHeight[height]
		if !ok {
			b.logf("no more blocks at: %v", height)
			return nmh, nil
		}
		var parentBlock *block
		for _, v := range bs {
			if from.Hash().IsEqual(v.Hash()) {
				continue
			}
			parentBlock = v
			break
		}
		if parentBlock == nil {
			return nil, fmt.Errorf("no parent at: %v", height)
		}
		err := nmh.AddBlockHeader(&parentBlock.MsgBlock().Header)
		if err != nil {
			return nil, fmt.Errorf("add header: %w", err)
		}

		b.logf("%v: %v", height, parentBlock.MsgBlock().Header.BlockHash())
		height++
	}

	return nmh, nil
}

func (b *btcNode) handleGetData(m *wire.MsgGetData) (*wire.MsgBlock, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	// b.logf("get data: %v", spew.Sdump(m))
	if len(m.InvList) != 1 {
		return nil, errors.New("not supported multi invlist requests")
	}

	v := m.InvList[0]
	if v.Type != wire.InvTypeBlock {
		return nil, fmt.Errorf("unsuported data type: %v", v.Type)
	}

	blk, ok := b.chain[v.Hash.String()]
	if !ok {
		return nil, fmt.Errorf("block not found: %v", v.Hash)
	}

	return blk.b.MsgBlock(), nil
}

func (b *btcNode) handleRPC(ctx context.Context, conn net.Conn) error {
	b.t.Logf("handleRPC %v", conn.RemoteAddr())
	defer b.t.Logf("handleRPC exit %v", conn.RemoteAddr())

	b.logf("handleRPC %v", conn.RemoteAddr())
	defer b.logf("handleRPC exit %v", conn.RemoteAddr())

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
		b.logf("write version %v: %v", p, err)
		return err
	}

	b.mtx.Lock()
	b.p = p
	b.mtx.Unlock()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		msg, err := p.read()
		if err != nil {
			if errors.Is(err, wire.ErrUnknownMessage) {
				// ignore unknown
				b.t.Log("wire: unknown message")
				continue
			}
			return fmt.Errorf("peer read %v: %w", p, err)
		}

		if err = b.handleMsg(ctx, p, msg); err != nil {
			return fmt.Errorf("handle message %v: %w", p, err)
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
		// b.logf("get headers %v", spew.Sdump(m))
		headers, err := b.handleGetHeaders(m)
		if err != nil {
			return fmt.Errorf("handle get headers: %w", err)
		}
		// b.logf("%v", spew.Sdump(headers))
		if err = p.write(time.Second, headers); err != nil {
			return fmt.Errorf("write headers: %w", err)
		}

	case *wire.MsgGetData:
		// b.logf("get data %v", spew.Sdump(m))
		data, err := b.handleGetData(m)
		if err != nil {
			return fmt.Errorf("handle get data: %w", err)
		}
		// b.logf("%v", spew.Sdump(data))
		if err = p.write(time.Second, data); err != nil {
			return fmt.Errorf("write data: %w", err)
		}

	default:
		b.logf("unhandled command: %v", spew.Sdump(msg))
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
		blk, ok := b.chain[parent.String()]
		if !ok {
			return fmt.Errorf("parent not found: %v", parent)
		}
		b.t.Logf("%v", blk)

		bh := blk.MsgBlock().Header
		parent = &bh.PrevBlock
		if blk.Height() == 0 {
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
	log.Infof("coinbase tx %v", spew.Sdump(coinbaseTx.Hash()))

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

func (b *btcNode) insertBlock(blk *block) (int, error) {
	b.chain[blk.Hash().String()] = blk
	bAtHeight := b.blocksAtHeight[blk.Height()]
	b.blocksAtHeight[blk.Height()] = append(bAtHeight, blk)
	return len(b.blocksAtHeight[blk.Height()]), nil
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

func (b *btcNode) mine(name string, from *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}
	// extra nonce is needed to prevent block collisions
	en := random(8)
	extraNonce := binary.BigEndian.Uint64(en)

	nextBlockHeight := parent.Height() + 1
	bt, err := newBlockTemplate(b.params, payToAddress, nextBlockHeight,
		parent.Hash(), extraNonce)
	if err != nil {
		return nil, fmt.Errorf("height %v: %w", nextBlockHeight, err)
	}
	blk := newBlock(b.params, name, bt)
	_, err = b.insertBlock(blk)
	if err != nil {
		return nil, fmt.Errorf("insert block at height %v: %v",
			nextBlockHeight, err)
	}
	// XXX this really sucks, we should get rid of height as a best indicator
	if blk.Height() > b.height {
		b.height = blk.Height()
	}

	return blk, nil
}

func (b *btcNode) mineN(count int, from *chainhash.Hash, payToAddress btcutil.Address) ([]*block, error) {
	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}

	blocks := make([]*block, 0, count)
	for range count {
		nextBlockHeight := parent.Height() + 1
		blk, err := b.mine(fmt.Sprintf("b%v", nextBlockHeight), parent.Hash(), payToAddress)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, blk)
		parent = blk
	}

	return blocks, nil
}

func (b *btcNode) Mine(name string, parent *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.mine(name, parent, payToAddress)
}

func (b *btcNode) MineN(count int, from *chainhash.Hash, payToAddress btcutil.Address) ([]*block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.mineN(count, from, payToAddress)
}

func (b *btcNode) MineAndSend(ctx context.Context, name string, parent *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	blk, err := b.Mine(name, parent, payToAddress)
	if err != nil {
		return nil, err
	}

	err = b.SendBlockheader(ctx, blk.MsgBlock().Header)
	if err != nil {
		return nil, err
	}

	time.Sleep(250 * time.Millisecond)

	return blk, nil
}

func (b *btcNode) Run(ctx context.Context) error {
	lc := &net.ListenConfig{}
	l, err := lc.Listen(ctx, "tcp", "localhost:"+b.port)
	if err != nil {
		return err
	}

	b.logf("waiting for connection")
	conn, err := l.Accept()
	if err != nil {
		return err
	}
	return b.handleRPC(ctx, conn)
}

func (b *btcNode) Stop() error {
	b.mtx.Lock()
	p := b.p
	b.p = nil
	b.mtx.Unlock()
	if p == nil {
		return nil
	}
	return p.conn.Close()
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

func mustHave(ctx context.Context, s *Server, blocks ...*block) error {
	for _, b := range blocks {
		bh, height, err := s.BlockHeaderByHash(ctx, b.Hash())
		if err != nil {
			return err
		}
		_ = bh
		if height != uint64(b.Height()) {
			return fmt.Errorf("%v != %v", height, uint64(b.Height()))
		}

		// Verify Txs
		for ktx, vtx := range b.txs {
			_ = vtx
			switch ktx[0] {
			case 's':
				//log.Infof(spew.Sdump(ktx))
				//log.Infof(spew.Sdump(vtx))
				//si, err := tbcd.SpendInfoFromTxSpentKeyValue(ktx, *vtx)
				//if err != nil {
				//	return fmt.Errorf("invalid spend info: %w", err)
				//}
				//log.Infof(spew.Sdump(si))
				//sis, err := s.SpendOutputsByTxId(ctx, si.TxId.Hash())
				//if err != nil {
				//	return fmt.Errorf("invalid spend infos: %w", err)
				//}
				//_ = sis
				//log.Infof("xx")

			case 't':
				txId, blockHash, err := tbcd.TxIdBlockHashFromTxKey(ktx)
				if err != nil {
					return fmt.Errorf("invalid tx key: %w", err)
				}
				tx, err := s.TxByTxId(ctx, txId.Hash())
				if err != nil {
					return fmt.Errorf("tx by id: %w", err)
				}
				_ = tx
				// db block retrieval tested by TxById
				if !b.Hash().IsEqual(blockHash.Hash()) {
					return errors.New("t cache block hash invalid")
				}
			default:
				return fmt.Errorf("invalid tx type %v", ktx[0])
			}
		}
	}

	return nil
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
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

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
	// n.le = true
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := n.Run(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()

	startHash := n.Best()
	count := 9
	expectedHeight := uint64(count)
	_, err = n.MineN(count, startHash[0], address)
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
	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Infof("s run")
		defer log.Infof("s run done")
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
		if si.BlockHeader.Height != expectedHeight {
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
	b10a, err := n.MineAndSend(ctx, "b10a", b9, address)
	if err != nil {
		t.Fatal(err)
	}
	b10b, err := n.MineAndSend(ctx, "b10b", b9, address)
	if err != nil {
		t.Fatal(err)
	}
	// XXX check hashes
	time.Sleep(50 * time.Millisecond)
	t.Logf("b10a: %v", b10a.Hash())
	t.Logf("b10b: %v", b10b.Hash())
	b10s := n.Best()
	if len(b10s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b10s))
	}

	// Advance both heads again
	b11a, err := n.MineAndSend(ctx, "b11a", b10a.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}
	b11b, err := n.MineAndSend(ctx, "b11b", b10b.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("b11a: %v", b11a.Hash())
	t.Logf("b11b: %v", b11b.Hash())
	b11s := n.Best()
	if len(b11s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b11s))
	}
	time.Sleep(50 * time.Millisecond)

	// Let's see if tbcd agrees
	si := s.Synced(ctx)
	// t.Logf("--- %v", si)
	bhsAt11, err := s.BlockHeadersByHeight(ctx, 11)
	if err != nil {
		t.Fatal(err)
	}

	// XXX: this is fragile, audit.  we sometimes get a length of 1
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
	b11c, err := n.MineAndSend(ctx, "b11c", b10b.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)

	// 12
	t.Logf("mine 12")
	b12, err := n.MineAndSend(ctx, "b12", b11c.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}
	_ = b12
	time.Sleep(50 * time.Millisecond)

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

func TestIndexFork(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
	}()

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
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()
	go func() {
		if err := n.Run(ctx); err != nil && !errors.Is(err, net.ErrClosed) {
			panic(err)
		}
	}()
	time.Sleep(time.Second)

	// Connect tbc service
	cfg := &Config{
		AutoIndex:     false,
		BlockSanity:   false,
		LevelDBHome:   t.TempDir(),
		ListenAddress: tbcapi.DefaultListen,
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
	time.Sleep(time.Second)

	// Create a bunch of weird geometries to catch all corner cases in the indexer.

	//   /-> b1a -> b2a
	// g ->  b1 ->  b2 -> b3
	//   \-> b1b -> b2b

	// best is b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	b1, err := n.MineAndSend(ctx, "b1", parent, address)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}

	// a chain
	b1a, err := n.MineAndSend(ctx, "b1a", parent, address)
	if err != nil {
		t.Fatal(err)
	}
	b2a, err := n.MineAndSend(ctx, "b2a", b1a.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}

	// b chain
	b1b, err := n.MineAndSend(ctx, "b1b", parent, address)
	if err != nil {
		t.Fatal(err)
	}
	b2b, err := n.MineAndSend(ctx, "b2b", b1b.Hash(), address)
	if err != nil {
		t.Fatal(err)
	}

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := s.TxIndexIsLinear(ctx, b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Index to b3
	err = s.SyncIndexersToHash(ctx, b3.Hash())
	if err != nil {
		t.Fatal(err)
	}
	// XXX verify indexes
	err = mustHave(ctx, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}

	// Verify linear indexing. Current TxIndex is sitting at b3
	t.Logf("b3: %v", b3)

	// b3 -> genesis should work with postive direction (cdiff is greater than target)
	direction, err = s.TxIndexIsLinear(ctx, s.chainParams.GenesisHash)
	if err != nil {
		t.Fatalf("expected success b3 -> genesis, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b1 should work with positive direction
	direction, err = s.TxIndexIsLinear(ctx, b1.Hash())
	if err != nil {
		t.Fatalf("expected success b3 -> b1, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}
	// b3 -> b2a should fail
	direction, err = s.TxIndexIsLinear(ctx, b2a.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2a is not linear to b3: %v", err)
	}

	// b3 -> b2b should fail
	direction, err = s.TxIndexIsLinear(ctx, b2b.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2b is not linear to b3: %v", err)
	}

	// make sure syncing to iself is non linear
	err = s.SyncIndexersToHash(ctx, b3.Hash())
	if err != nil {
		t.Fatalf("at b3, should have returned nil, got %v", err)
	}

	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, s.chainParams.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	// XXX verify indexes
	txHH, err := s.TxIndexHash(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txHH.Hash.IsEqual(s.chainParams.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txHH)
	}
	if txHH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txHH.Height)
	}

	// see if we can move to b2z
	direction, err = s.TxIndexIsLinear(ctx, b2a.Hash())
	if err != nil {
		t.Fatalf("expected success genesis -> b2a, got %v", err)
	}
	if direction != 1 {
		t.Fatalf("expected 1 going from genesis to b2a, got %v", direction)
	}

	//// Should fail
	//t.Logf("=== index b2a ===")
	//err = s.SyncIndexersToHash(ctx, b2a.Hash())
	//if err != nil {
	//	t.Fatal(err)
	//}

	//t.Logf("=== index b2b ===")
	//err = s.SyncIndexersToHash(ctx, b2b.Hash())
	//if err != nil {
	//	t.Fatal(err)
	//}

	time.Sleep(time.Second)
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
