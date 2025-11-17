// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/blockchain"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	btcmempool "github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/go-test/deep"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/v2/bitcoin"
	"github.com/hemilabs/heminetwork/v2/database"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/hemi"
	"github.com/hemilabs/heminetwork/v2/hemi/pop"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
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
	err := processTxs(context.Background(), b, 1, blk.txs)
	if err != nil {
		panic(fmt.Errorf("processTxs: %w", err))
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

func (b block) TxByIndex(index int) *btcutil.Tx {
	tx, err := b.b.Tx(index)
	if err != nil {
		panic(err)
	}
	return tx
}

func (b block) String() string {
	return fmt.Sprintf("%v: %v %v", b.name, b.Height(), b.Hash())
}

type namedKey struct {
	name string
	key  *btcec.PrivateKey
}

type btcNode struct {
	t    *testing.T // for logging
	le   bool       // log enable
	port string
	p    *rawpeer.RawPeer

	mtx            sync.RWMutex
	chain          map[string]*block
	blocksAtHeight map[int32][]*block
	height         int32
	params         *chaincfg.Params
	genesis        *block
	gtx            *btcutil.Tx // for printing and diagnostics
	private        *btcec.PrivateKey
	public         *btcec.PublicKey
	address        *btcutil.AddressPubKeyHash

	msgCh chan string

	keys      map[string]*namedKey        // keys used to sign various tx'
	keystones map[string]*hemi.L2Keystone // keystones found in various tx'

	listener net.Listener
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
		keys:           make(map[string]*namedKey, 10),
		keystones:      make(map[string]*hemi.L2Keystone, 10),
		msgCh:          make(chan string, 10),
	}

	// Add miner key to key pool
	var err error
	node.private, node.public, node.address, err = node.newKey("miner")
	if err != nil {
		return nil, err
	}
	node.genesis = newBlock(node.params, "genesis", genesis)
	_, err = node.insertBlock(node.genesis)
	if err != nil {
		return nil, err
	}
	node.gtx, err = node.genesis.b.Tx(0)
	if err != nil {
		return nil, err
	}
	t.Logf("genesis")
	t.Logf("  block: %v", node.genesis.Hash())
	t.Logf("  tx   : %v", node.gtx.Hash())
	t.Logf("")
	t.Logf("miner keys")
	t.Logf("  private: %x", node.private.Serialize())
	t.Logf("  public : %x", node.public.SerializeCompressed())
	t.Logf("  address: %v", node.address)

	return node, nil
}

// lookupKey is used by the sign function.
func (b *btcNode) lookupKey(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
	nk, ok := b.keys[a.String()]
	if !ok {
		return nil, false, fmt.Errorf("key not found: %v", a.String())
	}
	return nk.key, true, nil
}

func (b *btcNode) findKeyByName(name string) (*btcec.PrivateKey, error) {
	for k, v := range b.keys {
		b.t.Logf("findKeyByName %v == %v ---- %v", name, v.name, k)
		if v.name == name {
			return v.key, nil
		}
	}
	return nil, errors.New("not found")
}

// newKey creates and inserts a new key into the lookup table.
// Must be called locked
func (b *btcNode) newKey(name string) (*btcec.PrivateKey, *btcec.PublicKey, *btcutil.AddressPubKeyHash, error) {
	privateKey, err := btcec.NewPrivateKey()
	if err != nil {
		return nil, nil, nil, err
	}
	publicKey := privateKey.PubKey()
	address, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(publicKey.SerializeCompressed()), b.params)
	if err != nil {
		return nil, nil, nil, err
	}

	// Add to lookup
	b.keys[address.String()] = &namedKey{name: name, key: privateKey}

	return privateKey, publicKey, address, nil
}

func (b *btcNode) lookupKeystone(name string) (*hemi.L2Keystone, error) {
	kss, ok := b.keystones[name]
	if !ok {
		return nil, fmt.Errorf("key not found: %v", name)
	}
	return kss, nil
}

func (b *btcNode) newKeystone(name string) *chainhash.Hash {
	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      2,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes(name+"parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes(name+"prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes(name+"stateroot", 32),
		EPHash:             testutil.FillBytes(name+"ephash", 32),
	}

	b.keystones[name] = &l2Keystone
	return hemi.L2KeystoneAbbreviate(l2Keystone).Hash()
}

func (b *btcNode) newSignedTxFromTx(name string, inTx *btcutil.Tx, amount btcutil.Amount) (*btcutil.Tx, error) {
	utxos := inTx.MsgTx().TxOut
	redeemTx := wire.NewMsgTx(wire.TxVersion)
	inHash := inTx.Hash()

	total, err := btcutil.NewAmount(0)
	if err != nil {
		return nil, err
	}
	for _, txOut := range utxos {
		total += btcutil.Amount(txOut.Value)
	}
	if amount > total {
		return nil, fmt.Errorf("can't fund %v, got %v", amount, total)
	}

	// create new key to redeem
	redeemPrivate, redeemPublic, redeemAddress, err := b.newKey(name)
	if err != nil {
		return nil, err
	}
	pkScript, err := txscript.PayToAddrScript(redeemAddress)
	if err != nil {
		return nil, err
	}
	b.t.Logf("redeem pkScript (%v): %x", name, pkScript)
	b.t.Logf("redeem keys:")
	b.t.Logf("  private    : %x", redeemPrivate.Serialize())
	b.t.Logf("  public     : %x", redeemPublic.SerializeCompressed())
	b.t.Logf("  address    : %v", redeemAddress)

	// find enough utxos to cover amount
	left := amount
	prevOuts := make(map[string][]byte, len(utxos))
	for i, txOut := range utxos {
		prevOut := wire.NewOutPoint(inHash, uint32(i))
		txIn := wire.NewTxIn(prevOut, nil, nil)
		redeemTx.AddTxIn(txIn)
		prevOuts[prevOut.String()] = txOut.PkScript
		value := btcutil.Amount(txOut.Value) // amount to send

		// extract txout script address to subtract value
		sc, as, sigs, err := txscript.ExtractPkScriptAddrs(txOut.PkScript, b.params)
		if err != nil {
			return nil, err
		}
		_ = sc
		_ = sigs

		// only support one address for now
		if len(as) != 1 {
			return nil, fmt.Errorf("only 1 address supported in pkScript got %v", len(as))
		}

		// b.t.Logf("left %v value %v", left, value)
		if left > value {
			redeemTx.AddTxOut(wire.NewTxOut(int64(value), pkScript))
			left -= value
			continue
		}
		// Remaining bits
		redeemTx.AddTxOut(wire.NewTxOut(int64(left), pkScript))

		change := value - left
		if change != 0 {
			payToAddress := as[0]
			b.t.Logf("%v", spew.Sdump(as[0]))
			changeScript, err := txscript.PayToAddrScript(payToAddress)
			if err != nil {
				return nil, err
			}
			txOutChange := wire.NewTxOut(int64(change), changeScript)
			redeemTx.AddTxOut(txOutChange)
			b.t.Logf("change address %v value %v", payToAddress, change)
		}
		break
	}
	for i, txIn := range redeemTx.TxIn {
		prevPkScript, ok := prevOuts[txIn.PreviousOutPoint.String()]
		if !ok {
			panic("xx")
		}
		sigScript, err := txscript.SignTxOutput(b.params, redeemTx, i,
			prevPkScript, txscript.SigHashAll,
			txscript.KeyClosure(b.lookupKey), nil, nil)
		if err != nil {
			return nil, err
		}
		redeemTx.TxIn[i].SignatureScript = sigScript
	}

	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig | txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(utxos[0].PkScript, redeemTx, 0, flags, nil, nil, -1, nil)
	if err != nil {
		return nil, err
	}
	if err := vm.Execute(); err != nil {
		return nil, err
	}

	// Verify it would make it into the mempool
	err = btcmempool.CheckTransactionStandard(btcutil.NewTx(redeemTx), 0,
		time.Now(), btcmempool.DefaultMinRelayTxFee, 2)
	if err != nil {
		return nil, err
	}

	return btcutil.NewTx(redeemTx), nil
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

	if len(m.BlockLocatorHashes) == 0 {
		return nil, fmt.Errorf("get headers: invalid count got 0 wanted %v",
			len(m.BlockLocatorHashes))
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
		return nil, fmt.Errorf("unsupported data type: %v", v.Type)
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

	p, err := rawpeer.NewFromConn(conn, wire.TestNet, wire.AddrV2Version, 0xbeef)
	if err != nil {
		b.logf("new from connection %v: %v", conn.RemoteAddr(), err)
		return err
	}

	// Send version
	mv := &wire.MsgVersion{
		ProtocolVersion: int32(wire.AddrV2Version),
	}
	if err := p.Write(time.Second, mv); err != nil {
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

		msg, _, err := p.Read(15 * time.Second)
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

		select {
		case b.msgCh <- msg.Command():
		default:
		}
	}
}

func (b *btcNode) handleMsg(ctx context.Context, p *rawpeer.RawPeer, msg wire.Message) error {
	// b.t.Logf("%v", spew.Sdump(msg))
	// b.t.Logf("%T", msg)
	switch m := msg.(type) {
	case *wire.MsgVersion:
		mva := &wire.MsgVerAck{}
		if err := p.Write(time.Second, mva); err != nil {
			return fmt.Errorf("write version ack: %w", err)
		}

	case *wire.MsgGetHeaders:
		// b.logf("get headers %v", spew.Sdump(m))
		headers, err := b.handleGetHeaders(m)
		if err != nil {
			return fmt.Errorf("handle get headers: %w", err)
		}
		// b.logf("%v", spew.Sdump(headers))
		if err = p.Write(time.Second, headers); err != nil {
			return fmt.Errorf("write headers: %w", err)
		}

	case *wire.MsgGetData:
		// b.logf("get data %v", spew.Sdump(m))
		data, err := b.handleGetData(m)
		if err != nil {
			return fmt.Errorf("handle get data: %w", err)
		}
		// b.logf("%v", spew.Sdump(data))
		if err = p.Write(time.Second, data); err != nil {
			return fmt.Errorf("write data: %w", err)
		}

	default:
		b.logf("unhandled command: %v", spew.Sdump(msg))
	}

	return nil
}

func (b *btcNode) SendBlockheader(ctx context.Context, bh wire.BlockHeader) error {
	msg := wire.NewMsgHeaders()
	if err := msg.AddBlockHeader(&bh); err != nil {
		return fmt.Errorf("add block header: %w", err)
	}

	return b.p.Write(defaultCmdTimeout, msg)
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

var reqDifficulty uint32

func newBlockTemplate(t *testing.T, params *chaincfg.Params, payToAddress btcutil.Address, nextBlockHeight int32, parent *chainhash.Hash, extraNonce uint64, mempool []*btcutil.Tx) (*btcutil.Block, error) {
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		return nil, err
	}
	coinbaseTx, err := createCoinbaseTx(params, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		return nil, err
	}
	t.Logf("coinbase tx %v: %v", nextBlockHeight, coinbaseTx.Hash())

	if reqDifficulty == 0 {
		reqDifficulty = uint32(0x1d00ffff)
	}

	var blockTxs []*btcutil.Tx
	blockTxs = append(blockTxs, coinbaseTx)
	if mempool != nil {
		blockTxs = append(blockTxs, mempool...)
	}
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

// type addressToKey struct {
// 	key        *btcec.PrivateKey
// 	compressed bool
// }

// func mkGetKey(keys map[string]addressToKey) txscript.KeyDB {
// 	if keys == nil {
// 		return txscript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
// 			bool, error,
// 		) {
// 			return nil, false, errors.New("nope")
// 		})
// 	}
// 	return txscript.KeyClosure(func(addr btcutil.Address) (*btcec.PrivateKey,
// 		bool, error,
// 	) {
// 		a2k, ok := keys[addr.EncodeAddress()]
// 		if !ok {
// 			return nil, false, errors.New("nope")
// 		}
// 		return a2k.key, a2k.compressed, nil
// 	})
// }
//
// func mkGetScript(scripts map[string][]byte) txscript.ScriptDB {
// 	if scripts == nil {
// 		return txscript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
// 			return nil, errors.New("nope")
// 		})
// 	}
// 	return txscript.ScriptClosure(func(addr btcutil.Address) ([]byte, error) {
// 		script, ok := scripts[addr.EncodeAddress()]
// 		if !ok {
// 			return nil, errors.New("nope")
// 		}
// 		return script, nil
// 	})
// }

func executeTX(t *testing.T, dump bool, scriptPubKey []byte, tx *btcutil.Tx) error {
	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig | txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(scriptPubKey, tx.MsgTx(), 0, flags, nil, nil, -1, nil)
	if err != nil {
		return err
	}
	if dump {
		t.Logf("=== executing tx %v", tx.Hash())
	}
	for i := 0; ; i++ {
		d, err := vm.DisasmPC()
		if err != nil {
			return err
		}
		if dump {
			t.Logf("%v: %v", i, d)
		}
		done, err := vm.Step()
		if err != nil {
			return err
		}
		stack := vm.GetStack()
		if dump {
			t.Logf("%v: stack %v", i, spew.Sdump(stack))
		}
		if done {
			break
		}
	}
	err = vm.CheckErrorCondition(true)
	if err != nil {
		return err
	}

	if dump {
		t.Logf("=== SUCCESS tx %v", tx.Hash())
	}
	return nil
}

func createPopTx(btcHeight uint64, l2Keystone *hemi.L2Keystone, minerPrivateKeyBytes []byte, recipient *secp256k1.PublicKey, inTx *btcutil.Tx, idx uint32) (*btcutil.Tx, error) {
	btx := &wire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(*l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		return nil, err
	}

	privateKey := secp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)
	publicKey := privateKey.PubKey() // just send it back to the miner
	var btcAddress *btcutil.AddressPubKey
	if recipient == nil {
		pubKeyBytes := publicKey.SerializeCompressed()
		btcAddress, err = btcutil.NewAddressPubKey(pubKeyBytes, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, err
		}
	} else {
		pubKeyBytes := recipient.SerializeCompressed()
		btcAddress, err = btcutil.NewAddressPubKey(pubKeyBytes, &chaincfg.TestNet3Params)
		if err != nil {
			return nil, err
		}
	}

	payToScript, err := txscript.PayToAddrScript(btcAddress.AddressPubKeyHash())
	if err != nil {
		return nil, err
	}

	if len(payToScript) != 25 {
		return nil, fmt.Errorf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}

	var (
		outPoint     wire.OutPoint
		changeAmount int64
		PkScript     []byte
	)

	// idx := uint32(1)
	outPoint = *wire.NewOutPoint(inTx.Hash(), idx)
	changeAmount = inTx.MsgTx().TxOut[idx].Value // spend entire tx
	PkScript = inTx.MsgTx().TxOut[idx].PkScript  // Lift PkScript from utxo we are spending

	btx.TxIn = []*wire.TxIn{wire.NewTxIn(&outPoint, payToScript, nil)}
	btx.TxOut = []*wire.TxOut{wire.NewTxOut(changeAmount, payToScript)}
	btx.TxOut = append(btx.TxOut, wire.NewTxOut(0, popTxOpReturn))
	err = bitcoin.SignTx(btx, PkScript, privateKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("sign Bitcoin transaction: %w", err)
	}

	tx := btcutil.NewTx(btx)

	return tx, nil
}

func (b *btcNode) mine(name string, from *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}
	// extra nonce is needed to prevent block collisions
	en := random(8)
	extraNonce := binary.BigEndian.Uint64(en)
	var mempool []*btcutil.Tx

	nextBlockHeight := parent.Height() + 1
	switch nextBlockHeight {
	case 2:
		// spend block 1 coinbase
		tx, err := b.newSignedTxFromTx(name, parent.TxByIndex(0), 3000000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx.Hash(),
			tx.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = []*btcutil.Tx{tx}
	case 3:
		// spend block 2 transaction 1
		tx, err := b.newSignedTxFromTx(name+":0", parent.TxByIndex(1), 1100000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx.Hash(),
			tx.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = []*btcutil.Tx{tx}

		// spend above tx in same block
		tx2, err := b.newSignedTxFromTx(name+":1", tx, 3000000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx2.Hash(),
			tx2.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = append(mempool, tx2)
	}

	bt, err := newBlockTemplate(b.t, b.params, payToAddress, nextBlockHeight,
		parent.Hash(), extraNonce, mempool)
	if err != nil {
		return nil, fmt.Errorf("height %v: %w", nextBlockHeight, err)
	}
	blk := newBlock(b.params, name, bt)
	_, err = b.insertBlock(blk)
	if err != nil {
		return nil, fmt.Errorf("insert block at height %v: %w",
			nextBlockHeight, err)
	}
	// XXX this really sucks, we should get rid of height as a best indicator
	if blk.Height() > b.height {
		b.height = blk.Height()
	}

	return blk, nil
}

func (b *btcNode) mineMultiple(name string, from *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}
	// extra nonce is needed to prevent block collisions
	en := random(8)
	extraNonce := binary.BigEndian.Uint64(en)
	var mempool []*btcutil.Tx

	nextBlockHeight := parent.Height() + 1
	if nextBlockHeight >= 2 {
		// spend block 1 coinbase
		tx, err := b.newSignedTxFromTx(name, parent.TxByIndex(0), 3000000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx.Hash(),
			tx.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = []*btcutil.Tx{tx}

		// Add keystone
		l2Keystone, err := b.lookupKeystone(fmt.Sprintf("kss%d", nextBlockHeight))
		if err == nil {
			b.t.Logf("adding kss%d to %v", nextBlockHeight, name)
			signer, err := b.findKeyByName("miner")
			if err != nil {
				return nil, err
			}
			recipient, err := b.findKeyByName("pop")
			if err != nil {
				return nil, err
			}
			popTx, err := createPopTx(uint64(nextBlockHeight), l2Keystone, signer.Serialize(), recipient.PubKey(), tx, 1)
			if err != nil {
				return nil, err
			}

			err = executeTX(b.t, false, tx.MsgTx().TxOut[1].PkScript, popTx)
			if err != nil {
				return nil, err
			}

			mempool = append(mempool, popTx)
		}
	}

	bt, err := newBlockTemplate(b.t, b.params, payToAddress, nextBlockHeight,
		parent.Hash(), extraNonce, mempool)
	if err != nil {
		return nil, fmt.Errorf("height %v: %w", nextBlockHeight, err)
	}
	blk := newBlock(b.params, name, bt)
	_, err = b.insertBlock(blk)
	if err != nil {
		return nil, fmt.Errorf("insert block at height %v: %w",
			nextBlockHeight, err)
	}
	// XXX this really sucks, we should get rid of height as a best indicator
	b.t.Logf("%v height is %v", name, blk.Height())
	if blk.Height() > b.height {
		b.height = blk.Height()
	}

	return blk, nil
}

func (b *btcNode) mineKss(name string, from *chainhash.Hash, payToAddress btcutil.Address) (*block, error) {
	parent, ok := b.chain[from.String()]
	if !ok {
		return nil, errors.New("parent hash not found")
	}
	// extra nonce is needed to prevent block collisions
	en := random(8)
	extraNonce := binary.BigEndian.Uint64(en)
	var mempool []*btcutil.Tx

	nextBlockHeight := parent.Height() + 1
	switch nextBlockHeight {
	case 2:
		// spend block 1 coinbase
		tx, err := b.newSignedTxFromTx(name, parent.TxByIndex(0), 3000000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx.Hash(),
			tx.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = []*btcutil.Tx{tx}

		// Add keystone
		l2Keystone, err := b.lookupKeystone("kss1")
		if err != nil {
			return nil, err
		}

		signer, err := b.findKeyByName("miner")
		if err != nil {
			return nil, err
		}
		recipient, err := b.findKeyByName("pop")
		if err != nil {
			return nil, err
		}
		popTx, err := createPopTx(uint64(nextBlockHeight), l2Keystone, signer.Serialize(), recipient.PubKey(), tx, 1)
		if err != nil {
			return nil, err
		}

		err = executeTX(b.t, true, tx.MsgTx().TxOut[1].PkScript, popTx)
		if err != nil {
			return nil, err
		}

		popTxAlt, err := createPopTx(uint64(nextBlockHeight), l2Keystone, recipient.Serialize(), recipient.PubKey(), popTx, 0)
		if err != nil {
			return nil, err
		}

		err = executeTX(b.t, true, popTx.MsgTx().TxOut[0].PkScript, popTxAlt)
		if err != nil {
			return nil, err
		}

		mempool = append(mempool, popTx, popTxAlt)
		// b.t.Logf("added popTx %v", popTx)
	case 3:
		// spend block 2 transaction 1
		tx, err := b.newSignedTxFromTx(name+":0", parent.TxByIndex(0), 1100000000)
		if err != nil {
			return nil, fmt.Errorf("new tx from tx: %w", err)
		}
		b.t.Logf("tx %v: %v spent from %v", nextBlockHeight, tx.Hash(),
			tx.MsgTx().TxIn[0].PreviousOutPoint)
		mempool = []*btcutil.Tx{tx}

		// Add keystone
		l2Keystonedup, err := b.lookupKeystone("kss1")
		if err != nil {
			return nil, err
		}

		// Add keystone
		l2Keystone, err := b.lookupKeystone("kss2")
		if err != nil {
			return nil, err
		}

		signer, err := b.findKeyByName("miner")
		if err != nil {
			return nil, err
		}
		recipient, err := b.findKeyByName("pop")
		if err != nil {
			return nil, err
		}
		popTxDup, err := createPopTx(uint64(nextBlockHeight), l2Keystonedup,
			signer.Serialize(), recipient.PubKey(), tx, 1)
		if err != nil {
			return nil, err
		}

		err = executeTX(b.t, true, tx.MsgTx().TxOut[1].PkScript, popTxDup)
		if err != nil {
			return nil, err
		}

		popTx, err := createPopTx(uint64(nextBlockHeight), l2Keystone,
			recipient.Serialize(), recipient.PubKey(), popTxDup, 0)
		if err != nil {
			return nil, err
		}

		err = executeTX(b.t, true, popTxDup.MsgTx().TxOut[0].PkScript, popTx)
		if err != nil {
			return nil, err
		}

		mempool = append(mempool, popTxDup, popTx)
		// b.t.Logf("added popTx %v", popTx)
	}

	bt, err := newBlockTemplate(b.t, b.params, payToAddress, nextBlockHeight,
		parent.Hash(), extraNonce, mempool)
	if err != nil {
		return nil, fmt.Errorf("height %v: %w", nextBlockHeight, err)
	}
	blk := newBlock(b.params, name, bt)
	_, err = b.insertBlock(blk)
	if err != nil {
		return nil, fmt.Errorf("insert block at height %v: %w",
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

// Types of mining
const (
	MineNoKeystones = iota
	MineWithKeystones
	MineWithMultiple
)

func (b *btcNode) Mine(name string, parent *chainhash.Hash, payToAddress btcutil.Address, mineType int) (*block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	switch mineType {
	case 1:
		return b.mineKss(name, parent, payToAddress)
	case 2:
		return b.mineMultiple(name, parent, payToAddress)
	default:
		return b.mine(name, parent, payToAddress)
	}
}

func (b *btcNode) MineN(count int, from *chainhash.Hash, payToAddress btcutil.Address) ([]*block, error) {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.mineN(count, from, payToAddress)
}

func (b *btcNode) MineAndSend(ctx context.Context, name string, parent *chainhash.Hash, payToAddress btcutil.Address, mineType int) (*block, error) {
	blk, err := b.Mine(name, parent, payToAddress, mineType)
	if err != nil {
		return nil, err
	}
	b.t.Logf("mined %v: %v", blk.name, blk.MsgBlock().Header.BlockHash())
	err = b.SendBlockheader(ctx, blk.MsgBlock().Header)
	if err != nil {
		return nil, err
	}

	return blk, nil
}

func (b *btcNode) MineAndSendEmpty(ctx context.Context) error {
	b.t.Logf("send empty headers message")
	return b.p.Write(defaultCmdTimeout, wire.NewMsgHeaders())
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

	b.listener = l

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

	if err := p.Close(); err != nil {
		return err
	}

	return b.listener.Close()
}

type zkTxInfo struct {
	tx     *btcutil.Tx
	errors []error
}

type zkTxInInfo struct {
	zkTxInfo

	inIndex  int
	utxoTxId chainhash.Hash
	utxoVal  uint64
}

type zkTxOutInfo struct {
	zkTxInfo

	outIndex int
	balance  uint64
	value    uint64
}

func (i *zkTxInfo) Err() error {
	var errSeen error
	for _, err := range i.errors {
		errSeen = errors.Join(errSeen, err)
	}
	return errSeen
}

func zkValidateTxOut(ctx context.Context, s *Server, i *zkTxOutInfo) {
	txOut := i.tx.MsgTx().TxOut[i.outIndex]
	sh := tbcd.NewScriptHashFromScript(txOut.PkScript)

	// assert SpendableOutput exists
	_, err := spendableOutByTxOut(ctx, s, sh, i.tx.Hash(), i.outIndex)
	if err != nil {
		i.errors = append(i.errors, err)
	}

	// assert spendable UTXO exists
	_, err = spendingOutByTxOut(ctx, s, *i.tx.Hash(), i.outIndex)
	if err != nil {
		i.errors = append(i.errors, err)
	}

	// assert balance matches expected
	rb, err := s.g.db.ZKBalanceByScriptHash(ctx, sh)
	if err != nil {
		// should never happen
		panic("ZKBalanceByScriptHash")
	}
	if rb != i.balance {
		err = fmt.Errorf("bad balance: expected %v, got %d", i.balance, rb)
		i.errors = append(i.errors, err)
	}

	// assert value matches expected
	op := tbcd.NewOutpoint(*i.tx.Hash(), uint32(i.outIndex))
	rv, _, err := s.ZKValueAndScriptByOutpoint(ctx, op)
	if err != nil {
		i.errors = append(i.errors, err)
	}
	if rv != btcutil.Amount(i.value) {
		err = fmt.Errorf("bad value: expected %v, got %d", i.value, rv)
		i.errors = append(i.errors, err)
	}
}

func zkValidateTxIn(ctx context.Context, s *Server, i *zkTxInInfo) {
	txIn := i.tx.MsgTx().TxIn[i.inIndex]
	pop := tbcd.NewOutpoint(txIn.PreviousOutPoint.Hash,
		txIn.PreviousOutPoint.Index)
	val, tout, err := s.g.db.ZKValueAndScriptByOutpoint(ctx, pop) // Rename
	if err != nil {
		i.errors = append(i.errors, err)
	}
	if val != i.utxoVal {
		err := fmt.Errorf("prev outpoint value: expected %v, got %v", i.utxoVal, val)
		i.errors = append(i.errors, err)
	}
	sh := tbcd.NewScriptHashFromScript(tout)

	_, err = spendingOutByTxIn(ctx, s, i.utxoTxId,
		*i.tx.Hash(), i.inIndex)
	if err != nil {
		i.errors = append(i.errors, err)
	}

	_, err = spentOutByTxIn(ctx, s, sh, *i.tx.Hash(), i.inIndex)
	if err != nil {
		i.errors = append(i.errors, err)
	}
}

func spendingOutByTxIn(ctx context.Context, s *Server, prevTxId, txId chainhash.Hash, index int) (tbcd.ZKSpendingOutpoint, error) {
	spendingOps, err := s.g.db.ZKSpendingOutpoints(ctx, prevTxId)
	if err != nil {
		return tbcd.ZKSpendingOutpoint{}, err
	}

	for _, so := range spendingOps {
		spv := so.SpendingOutpoint
		if spv != nil && spv.TxID.IsEqual(&txId) && spv.Index == uint32(index) {
			return so, nil
		}
	}
	return tbcd.ZKSpendingOutpoint{}, database.NotFoundError("spending outpoint by txIn")
}

func spendingOutByTxOut(ctx context.Context, s *Server, txId chainhash.Hash, index int) (tbcd.ZKSpendingOutpoint, error) {
	spendingOps, err := s.g.db.ZKSpendingOutpoints(ctx, txId)
	if err != nil {
		return tbcd.ZKSpendingOutpoint{}, err
	}
	for _, so := range spendingOps {
		if so.TxID.IsEqual(&txId) && so.VOutIndex == uint32(index) {
			return so, nil
		}
	}
	return tbcd.ZKSpendingOutpoint{}, database.NotFoundError("spending outpoint by txOut")
}

func spentOutByTxIn(ctx context.Context, s *Server, sh tbcd.ScriptHash, txId chainhash.Hash, inIndex int) (tbcd.ZKSpentOutput, error) {
	spentOps, err := s.g.db.ZKSpentOutputs(ctx, sh)
	if err != nil {
		return tbcd.ZKSpentOutput{}, err
	}
	for _, so := range spentOps {
		if so.TxID.IsEqual(&txId) && so.TxInIndex == uint32(inIndex) {
			return so, nil
		}
	}
	return tbcd.ZKSpentOutput{}, database.NotFoundError("spent outpoint")
}

func spendableOutByTxOut(ctx context.Context, s *Server, sh tbcd.ScriptHash, txId *chainhash.Hash, outIndex int) (tbcd.ZKSpendableOutput, error) {
	spendableOut, err := s.g.db.ZKSpendableOutputs(ctx, sh)
	if err != nil {
		return tbcd.ZKSpendableOutput{}, err
	}
	for _, so := range spendableOut {
		if so.TxID.IsEqual(txId) && so.TxOutIndex == uint32(outIndex) {
			return so, nil
		}
	}
	return tbcd.ZKSpendableOutput{}, database.NotFoundError("spendable output")
}

func mustHave(ctx context.Context, t *testing.T, s *Server, blocks ...*block) error {
	for _, b := range blocks {
		_, height, err := s.BlockHeaderByHash(ctx, *b.Hash())
		if err != nil {
			return err
		}
		if height != uint64(b.Height()) {
			return fmt.Errorf("%v != %v", height, uint64(b.Height()))
		}

		t.Logf("mustHave: %v", b.Hash())
		// Verify Txs cache
		for ktx, vtx := range b.txs {
			switch ktx[0] {
			case 's':
				// grab previous outpoint from the key
				tx, err := chainhash.NewHash(ktx[1:33])
				if err != nil {
					return fmt.Errorf("invalid tx hash: %w", err)
				}
				sis, err := s.SpentOutputsByTxId(ctx, *tx)
				if err != nil {
					return fmt.Errorf("invalid spend infos: %w", err)
				}
				found := false
				for _, si := range sis {
					if !bytes.Equal(b.Hash()[:], si.BlockHash[:]) {
						continue
					}
					found = true
					break
				}
				if !found {
					t.Logf("tx hash: %v", tx)
					t.Logf("ktx: %v", spew.Sdump(ktx))
					t.Logf("vtx: %v", spew.Sdump(vtx))
					t.Logf("%s", spew.Sdump(sis))
					return errors.New("block mismatch")
				}
			case 't':
				txId, blockHash, err := tbcd.TxIdBlockHashFromTxKey(ktx)
				if err != nil {
					return fmt.Errorf("invalid tx key: %w", err)
				}
				_, err = s.TxById(ctx, *txId)
				if err != nil {
					return fmt.Errorf("tx by id: %w", err)
				}
				// db block retrieval tested by TxById
				if !b.Hash().IsEqual(blockHash) {
					return errors.New("t cache block hash invalid")
				}
			default:
				return fmt.Errorf("invalid tx type %v", ktx[0])
			}
		}
	}

	return nil
}

func mustNotHave(ctx context.Context, t *testing.T, s *Server, blocks ...*block) error {
	for _, b := range blocks {
		_, height, err := s.BlockHeaderByHash(ctx, *b.Hash())
		if err != nil {
			return err
		}
		if height != uint64(b.Height()) {
			return fmt.Errorf("%v != %v", height, uint64(b.Height()))
		}

		t.Logf("mustNotHave: %v", b.Hash())
		// Verify Txs cache
		for ktx := range b.txs {
			switch ktx[0] {
			case 's':
				// grab previous outpoint from the key
				tx, err := chainhash.NewHash(ktx[1:33])
				if err != nil {
					return fmt.Errorf("invalid tx hash: %w", err)
				}
				_, err = s.SpentOutputsByTxId(ctx, *tx)
				var expected database.NotFoundError
				if !errors.Is(err, expected) {
					return fmt.Errorf("expected invalid spend infos %v: %w", tx, err)
				}

			case 't':
				txId, _, err := tbcd.TxIdBlockHashFromTxKey(ktx)
				if err != nil {
					return fmt.Errorf("invalid tx key: %w", err)
				}
				_, err = s.TxById(ctx, *txId)
				var expected database.NotFoundError
				if !errors.Is(err, expected) {
					return fmt.Errorf("expected no tx by id %v: %w", txId, err)
				}
			default:
				return fmt.Errorf("invalid tx type %v", ktx[0])
			}
		}
	}

	return nil
}

func errorIsOneOf(err error, errs []error) bool {
	if err == nil {
		return false
	}

	for _, v := range errs {
		if errors.Is(err, v) {
			return true
		}
	}

	return false
}

func (s *Server) hasAllBlocks(ctx context.Context, m map[int32][]*block) (bool, error) {
	for _, k := range m {
		for _, blk := range k {
			_, err := s.g.db.BlockByHash(ctx, *blk.Hash())
			if err != nil {
				if !errors.Is(err, database.ErrBlockNotFound) {
					return false, err
				}
				return false, nil
			}
		}
	}
	return true, nil
}

func (s *Server) waitForBlocks(ctx context.Context, l *Listener, m map[int32][]*block) error {
	for hasBlocks := false; !hasBlocks; {
		msg, err := l.Listen(ctx)
		if err != nil {
			return err
		}
		if !msg.Is(NotificationBlock(chainhash.Hash{})) {
			continue
		}
		if msg.Error != nil {
			return msg.Error
		}
		hasBlocks, err = s.hasAllBlocks(ctx, m)
		if err != nil {
			return err
		}
	}
	return nil
}

func TestFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
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

	go func() {
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	popPriv, popPublic, popAddress, err := n.newKey("pop")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pop keys:")
	t.Logf("  private    : %x", popPriv.Serialize())
	t.Logf("  public     : %x", popPublic.SerializeCompressed())
	t.Logf("  address    : %v", popAddress)

	startHash := n.Best()
	count := 9
	address := n.address
	_, err = n.MineN(count, startHash[0], address)
	if err != nil {
		t.Fatal(err)
	}
	err = n.dumpChain(n.Best()[0])
	if err != nil {
		t.Fatal(err)
	}

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
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
		utxos, err := s.UtxosByAddress(ctx, true, address.String(), 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v", spew.Sdump(utxos))
	}

	// Check cumulative difficulty
	difficulty, err := s.DifficultyAtHash(ctx, *n.Best()[0])
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("----- %x", blockchain.BigToCompact(difficulty))
	t.Logf("difficulty: 0x%064x", difficulty)

	// Advance both heads
	b9 := n.Best()[0]
	b10a, err := n.MineAndSend(ctx, "b10a", b9, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b10b, err := n.MineAndSend(ctx, "b10b", b9, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}

	t.Logf("b10a: %v", b10a.Hash())
	t.Logf("b10b: %v", b10b.Hash())
	b10s := n.Best()
	if len(b10s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b10s))
	}

	// Advance both heads again
	b11a, err := n.MineAndSend(ctx, "b11a", b10a.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b11b, err := n.MineAndSend(ctx, "b11b", b10b.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}

	t.Logf("b11a: %v", b11a.Hash())
	t.Logf("b11b: %v", b11b.Hash())
	b11s := n.Best()
	if len(b11s) != 2 {
		t.Fatalf("expected 2 best blocks, got %v", len(b11s))
	}

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
	b11c, err := n.MineAndSend(ctx, "b11c", b10b.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// 12
	t.Logf("mine 12")
	b12, err := n.MineAndSend(ctx, "b12", b11c.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	_ = b12

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}

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

func TestIndexNoFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 17*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
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
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// creat a linear chain with some tx's
	// g ->  b1 ->  b2 -> b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Index to b3
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatal(err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}

	// XXX verify all balances
	for address, key := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v (%v): %v", address, key.name, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// make sure genesis tx is in db
	_, err = s.TxById(ctx, *n.gtx.Hash())
	if err != nil {
		t.Fatalf("genesis not found: %v", err)
	}
	// make sure gensis was not spent
	_, err = s.SpentOutputsByTxId(ctx, *n.gtx.Hash())
	if err == nil {
		t.Fatal("genesis coinbase tx should not be spent")
	}

	// Spot check tx 1 from b2
	tx := b2.b.Transactions()[1]
	txb2, err := s.TxById(ctx, *tx.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if !btcutil.NewTx(txb2).Hash().IsEqual(tx.Hash()) {
		t.Fatal("hash not equal")
	}
	si, err := s.SpentOutputsByTxId(ctx, *b1.b.Transactions()[0].Hash())
	if err != nil {
		t.Fatal(err)
	}
	_ = si
	// t.Logf("%v: %v", b1.b.Transactions()[0].Hash(), spew.Sdump(si))
	si, err = s.SpentOutputsByTxId(ctx, *b2.b.Transactions()[1].Hash())
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%v: %v", b2.b.Transactions()[1].Hash(), spew.Sdump(si))
	_ = si

	// unwind back to b3 (removes b3 and b2)
	err = s.SyncIndexersToHash(ctx, *b2.Hash())
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1)
	if err != nil {
		t.Fatalf("expected an error from mustHave: %v", err)
	}

	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.TxById(ctx, *n.gtx.Hash())
	if err != nil {
		t.Fatal("expected genesis")
	}

	// Expect 0 balances everywhere
	for address, key := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		log.Infof("balance address %v  %v", address, btcutil.Amount(balance))
		if balance != 0 {
			t.Fatalf("%v (%v) invalid balance expected 0, got %v",
				key.name, address, btcutil.Amount(balance))
		}
	}
}

func TestKeystoneIndexNoFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
	if err != nil {
		t.Fatal(err)
	}

	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()

	popPriv, popPublic, popAddress, err := n.newKey("pop")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pop keys:")
	t.Logf("  private    : %x", popPriv.Serialize())
	t.Logf("  public     : %x", popPublic.SerializeCompressed())
	t.Logf("  address    : %v", popAddress)

	kss1Hash := n.newKeystone("kss1")
	kss2Hash := n.newKeystone("kss2")

	go func() {
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		HemiIndex:            true, // Test keystone index
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		MaxCachedKeystones:      1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// creat a linear chain with some tx's
	// g ->  b1 ->  b2 -> b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Index to b2
	err = s.SyncIndexersToHash(ctx, *b2.Hash())
	if err != nil {
		t.Fatal(err)
	}

	// check if keystone in db
	rv, err := s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}

	// check if keystone stored with correct block hash
	if !rv.BlockHash.IsEqual(b2.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err := s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// Index to b3
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatal(err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}

	// XXX verify all balances
	for address, key := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v (%v): %v", address, key.name, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// check if kss1 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss1 stored with correct block hash
	if !rv.BlockHash.IsEqual(b2.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// check if kss2 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss2Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss2 stored with correct block hash
	if !rv.BlockHash.IsEqual(b3.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss2Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b3.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 3, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// make sure genesis tx is in db
	_, err = s.TxById(ctx, *n.gtx.Hash())
	if err != nil {
		t.Fatalf("genesis not found: %v", err)
	}

	// make sure gensis was not spent
	_, err = s.SpentOutputsByTxId(ctx, *n.gtx.Hash())
	if err == nil {
		t.Fatal("genesis coinbase tx should not be spent")
	}

	// Spot check tx 1 from b2
	tx := b2.b.Transactions()[1]
	txb2, err := s.TxById(ctx, *tx.Hash())
	if err != nil {
		t.Fatal(err)
	}
	if !btcutil.NewTx(txb2).Hash().IsEqual(tx.Hash()) {
		t.Fatal("hash not equal")
	}
	si, err := s.SpentOutputsByTxId(ctx, *b1.b.Transactions()[0].Hash())
	if err != nil {
		t.Fatal(err)
	}
	_ = si
	// t.Logf("%v: %v", b1.b.Transactions()[0].Hash(), spew.Sdump(si))
	si, err = s.SpentOutputsByTxId(ctx, *b2.b.Transactions()[1].Hash())
	if err != nil {
		t.Fatal(err)
	}
	// t.Logf("%v: %v", b2.b.Transactions()[1].Hash(), spew.Sdump(si))
	_ = si

	// unwind back to b3 (removes b3 and b2)
	err = s.SyncIndexersToHash(ctx, *b2.Hash())
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}

	err = mustHave(ctx, t, s, n.genesis, b1)
	if err != nil {
		t.Fatalf("expected an error from mustHave: %v", err)
	}

	// check if keystone in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if keystone stored with correct block hash
	if !rv.BlockHash.IsEqual(b2.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", *kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.TxById(ctx, *n.gtx.Hash())
	if err != nil {
		t.Fatal("expected genesis")
	}

	// Expect 0 balances everywhere
	for address, key := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("balance address %v  %v", address, btcutil.Amount(balance))
		if balance != 0 {
			t.Fatalf("%v (%v) invalid balance expected 0, got %v",
				key.name, address, btcutil.Amount(balance))
		}
	}

	lastKssAt, err := s.ki.IndexerAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// check if keystones unwound to genesis
	if lastKssAt.Height != 0 {
		t.Fatalf("expected keystone index hash 0, got %v", lastKssAt.Height)
	}

	// check if keystones not in db
	for _, v := range n.keystones {
		abrvKss := hemi.L2KeystoneAbbreviate(*v).Hash()
		_, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *abrvKss)
		if err == nil {
			t.Fatalf("expected fail in db query for keystone: %v", abrvKss)
		}
	}

	// check if no keystones in heighthash index
	_, err = s.g.db.KeystonesByHeight(ctx, 6, -5)
	if err == nil {
		t.Fatalf("expected fail in db query for keystones at height 5 and below")
	}
}

func TestIndexFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
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
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// Create a bunch of weird geometries to catch all corner cases in the indexer.

	//   /-> b1a -> b2a
	// g ->  b1 ->  b2 -> b3
	//   \-> b1b -> b2b

	// best is b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// a chain
	b1a, err := n.MineAndSend(ctx, "b1a", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2a, err := n.MineAndSend(ctx, "b2a", b1a.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// b chain
	b1b, err := n.MineAndSend(ctx, "b1b", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2b, err := n.MineAndSend(ctx, "b2b", b1b.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Index to b3
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatal(err)
	}
	// XXX verify indexes
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}
	// XXX add mustNotHave
	// verify tx
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// Verify linear indexing. Current TxIndex is sitting at b3
	t.Logf("b3: %v", b3)

	// b3 -> genesis should work with positive direction (cdiff is greater than target)
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("expected success b3 -> genesis, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b1 should work with positive direction
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b1.Hash())
	if err != nil {
		t.Fatalf("expected success b3 -> b1, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b2a should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2a.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2a is not linear to b3: %v", err)
	}

	// b3 -> b2b should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2b.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2b is not linear to b3: %v", err)
	}

	// make sure syncing to itself is non linear
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatalf("at b3, should have returned nil, got %v", err)
	}

	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// XXX verify indexes
	txBH, err := s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}

	// see if we can move to b2a
	direction, err = indexIsLinear(ctx, s.g, txBH.Hash, *b2a.Hash())
	if err != nil {
		t.Fatalf("expected success genesis -> b2a, got %v", err)
	}
	if direction != 1 {
		t.Fatalf("expected 1 going from genesis to b2a, got %v", direction)
	}

	err = s.SyncIndexersToHash(ctx, *b2a.Hash())
	if err != nil {
		t.Fatalf("wind to b2a: %v", err)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}
	txBH, err = s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	t.Logf("---------------------------------------- going to b2b")
	err = s.SyncIndexersToHash(ctx, *b2b.Hash())
	if err != nil {
		t.Fatalf("wind to b2b: %v", err)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// t.Logf("---------------------------------------- going to b3")
	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("xxxx %v", err)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}
}

func TestKeystoneIndexFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()

	popPriv, popPublic, popAddress, err := n.newKey("pop")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pop keys:")
	t.Logf("  private    : %x", popPriv.Serialize())
	t.Logf("  public     : %x", popPublic.SerializeCompressed())
	t.Logf("  address    : %v", popAddress)

	kss1Hash := n.newKeystone("kss1")
	kss2Hash := n.newKeystone("kss2")

	go func() {
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		HemiIndex:            true, // Test keystone index
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		MaxCachedKeystones:      1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// Create a bunch of weird geometries to catch all corner cases in the indexer.

	//   /-> b1a -> b2a
	// g ->  b1 ->  b2 -> b3
	//   \-> b1b -> b2b

	// best is b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// a chain
	b1a, err := n.MineAndSend(ctx, "b1a", parent, address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2a, err := n.MineAndSend(ctx, "b2a", b1a.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// b chain
	b1b, err := n.MineAndSend(ctx, "b1b", parent, address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2b, err := n.MineAndSend(ctx, "b2b", b1b.Hash(), address, MineWithKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Index to b2
	err = s.SyncIndexersToHash(ctx, *b2.Hash())
	if err != nil {
		t.Fatal(err)
	}

	// check if keystone in db
	rv, err := s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}

	// check if keystone stored with correct block hash
	if !rv.BlockHash.IsEqual(b2.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}
	// check if keystone stored using heighthash index
	hk, err := s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// Index to b3
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatal(err)
	}
	// XXX verify indexes
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}
	// XXX add mustNotHave
	// verify tx
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// check if kss1 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss1 stored with correct block hash
	if !rv.BlockHash.IsEqual(b2.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// check if kss2 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss2Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss2 stored with correct block hash
	if !rv.BlockHash.IsEqual(b3.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss2Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b3.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 3, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// Verify linear indexing. Current TxIndex is sitting at b3
	t.Logf("b3: %v", b3)

	// b3 -> genesis should work with positive direction (cdiff is greater than target)
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("expected success b3 -> genesis, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b1 should work with positive direction
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b1.Hash())
	if err != nil {
		t.Fatalf("expected success b3 -> b1, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b2a should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2a.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2a is not linear to b3: %v", err)
	}

	// b3 -> b2b should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2b.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2b is not linear to b3: %v", err)
	}

	// make sure syncing to itself is non linear
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatalf("at b3, should have returned nil, got %v", err)
	}

	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// XXX verify indexes
	txBH, err := s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}

	// see if we can move to b2a
	direction, err = indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b2a.Hash())
	if err != nil {
		t.Fatalf("expected success genesis -> b2a, got %v", err)
	}
	if direction != 1 {
		t.Fatalf("expected 1 going from genesis to b2a, got %v", direction)
	}

	err = s.SyncIndexersToHash(ctx, *b2a.Hash())
	if err != nil {
		t.Fatalf("wind to b2a: %v", err)
	}

	// check if kss1 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss1 stored with correct block hash
	if !rv.BlockHash.IsEqual(b2a.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}
	txBH, err = s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	t.Logf("---------------------------------------- going to b2b")
	err = s.SyncIndexersToHash(ctx, *b2b.Hash())
	if err != nil {
		t.Fatalf("wind to b2b: %v", err)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// check if kss1 in db
	rv, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kss1Hash)
	if err != nil {
		t.Fatal(err)
	}
	// check if kss1 stored with correct block hash
	if !rv.BlockHash.IsEqual(b2b.Hash()) {
		t.Fatalf("wrong blockhash for stored keystone: %v", kss1Hash)
	}

	// check if keystone stored using heighthash index
	hk, err = s.g.db.KeystonesByHeight(ctx, uint32(b2.Height()-1), 1)
	if err != nil {
		t.Fatal(err)
	}

	if len(hk) != 1 {
		t.Fatalf("expected 1 keystone at height 2, got %d", len(hk))
	}

	if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
		t.Fatalf("unexpected keystone diff: %s", diff)
	}

	// t.Logf("---------------------------------------- going to b3")
	// unwind back to genesis
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("xxxx %v", err)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	lastKssAt, err := s.ki.IndexerAt(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// check if keystones unwound to genesis
	if lastKssAt.Height != 0 {
		t.Fatalf("expected keystone index hash 0, got %v", lastKssAt.Height)
	}

	// check if keystones not in db
	for _, v := range n.keystones {
		abrvKss := hemi.L2KeystoneAbbreviate(*v).Hash()
		_, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *abrvKss)
		if err == nil {
			t.Fatalf("expected fail in db query for keystone: %v", abrvKss)
		}
	}

	// check if no keystones in heighthash index
	_, err = s.g.db.KeystonesByHeight(ctx, 6, -5)
	if err == nil {
		t.Fatalf("expected fail in db query for keystones at height 5 and below")
	}
}

func TestTransactions(t *testing.T) {
	params := &chaincfg.RegressionNetParams
	nextBlockHeight := int32(2)
	extraNonce := uint64(nextBlockHeight)
	coinbaseScript, err := standardCoinbaseScript(nextBlockHeight, extraNonce)
	if err != nil {
		t.Fatal(err)
	}
	payToKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	payToKeyPublic := payToKey.PubKey()
	payToAddress, err := btcutil.NewAddressPubKeyHash(
		btcutil.Hash160(payToKeyPublic.SerializeCompressed()), params)
	if err != nil {
		t.Fatal(err)
	}

	coinbaseTx, err := createCoinbaseTx(params, coinbaseScript,
		nextBlockHeight, payToAddress)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("coinbase: %v", spew.Sdump(coinbaseTx))
	wireCoinbaseTx := coinbaseTx.MsgTx()
	disasm, err := txscript.DisasmString(wireCoinbaseTx.TxOut[0].PkScript)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("coinbase: %v", disasm)

	// now create a tx that spends  the above TxIn
	redeemKey, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	redeemKeyPublic := redeemKey.PubKey()
	redeemAddress, err := btcutil.NewAddressPubKeyHash(btcutil.Hash160(redeemKeyPublic.SerializeCompressed()), params)
	if err != nil {
		t.Fatal(err)
	}

	redeemTx := wire.NewMsgTx(wire.TxVersion)
	prevOut := wire.NewOutPoint(coinbaseTx.Hash(), 0)
	txIn := wire.NewTxIn(prevOut, nil, nil)
	redeemTx.AddTxIn(txIn)
	pkScript, err := txscript.PayToAddrScript(redeemAddress)
	if err != nil {
		t.Fatal(err)
	}
	txOut := wire.NewTxOut(3000000000, pkScript)
	redeemTx.AddTxOut(txOut)
	sc, as, sigs, err := txscript.ExtractPkScriptAddrs(pkScript, params)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%v %v: %v", sc, sigs, spew.Sdump(as))

	// add cgange
	changeScript, err := txscript.PayToAddrScript(payToAddress)
	if err != nil {
		t.Fatal(err)
	}
	txOutChange := wire.NewTxOut(2000000000, changeScript)
	redeemTx.AddTxOut(txOutChange)
	// sign
	lookupKey := func(a btcutil.Address) (*btcec.PrivateKey, bool, error) {
		return payToKey, true, nil
	}
	sigScript, err := txscript.SignTxOutput(&chaincfg.MainNetParams,
		redeemTx, 0, wireCoinbaseTx.TxOut[0].PkScript, txscript.SigHashAll,
		txscript.KeyClosure(lookupKey), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	redeemTx.TxIn[0].SignatureScript = sigScript
	t.Logf("redeem tx: %v", spew.Sdump(redeemTx))

	flags := txscript.ScriptBip16 | txscript.ScriptVerifyDERSignatures |
		txscript.ScriptStrictMultiSig |
		txscript.ScriptDiscourageUpgradableNops
	vm, err := txscript.NewEngine(wireCoinbaseTx.TxOut[0].PkScript, redeemTx, 0,
		flags, nil, nil, -1, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := vm.Execute(); err != nil {
		t.Fatal(err)
	}
	disasm, err = vm.DisasmScript(0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("coinbase signed tx in 0: %v", disasm)
	disasm, err = vm.DisasmScript(1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("coinbase signed tx out 0: %v", disasm)

	err = btcmempool.CheckTransactionStandard(btcutil.NewTx(redeemTx), 0,
		time.Now(), btcmempool.DefaultMinRelayTxFee, 2)
	if err != nil {
		t.Fatal(err)
	}
}

func TestForkCanonicity(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 7*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
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
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	//		   		 /--> b3aa
	//        / --> b2a - b3a - b4a - b5a - b6a
	// g - b1 ---->	b2  - b3  - b4  - b5
	//        \ --> b2b

	// b2 -> b5 has highest cumulative work, so b5 is best

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address

	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	mainChainHashes := map[string]*chainhash.Hash{"genesis": parent, "b1": b1.Hash()}

	// increase difficulty to ensure b1 -> b5 remains canonical
	reqDifficulty = uint32(0x1d000fff)

	// mine b2 to b5
	prevHash := b1.Hash()
	for i := 2; i <= 5; i++ {
		blk, err := n.MineAndSend(ctx, "b"+strconv.Itoa(i), prevHash, address, MineNoKeystones)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = blk.Hash()
		mainChainHashes["b"+strconv.Itoa(i)] = blk.Hash()
	}

	altChainHashes := make(map[string]*chainhash.Hash, 0)
	prevHash = b1.Hash()

	// reset difficulty
	reqDifficulty = 0

	// chain a
	for i := 2; i <= 6; i++ {
		blk, err := n.MineAndSend(ctx, "b"+strconv.Itoa(i)+"a", prevHash, address, MineNoKeystones)
		if err != nil {
			t.Fatal(err)
		}
		prevHash = blk.Hash()
		altChainHashes["b"+strconv.Itoa(i)+"a"] = blk.Hash()
	}

	// chain b
	b2b, err := n.MineAndSend(ctx, "b2b", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	altChainHashes["b2b"] = b2b.Hash()

	// chain aa
	b3aa, err := n.MineAndSend(ctx, "b3aa", altChainHashes["b2a"], address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	altChainHashes["b3aa"] = b3aa.Hash()

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// set checkpoints to genesis, b2 and b4
	s.g.chain.Checkpoints = []chaincfg.Checkpoint{
		{Height: 4, Hash: mainChainHashes["b4"]},
		{Height: 2, Hash: mainChainHashes["b2"]},
		{Height: 0, Hash: parent},
	}
	defer func() {
		s.g.chain.Checkpoints = localnetCheckpoints
	}()

	// assert genesis -> b5 are canonical
	for bname, hs := range mainChainHashes {
		bh, err := s.g.db.BlockHeaderByHash(ctx, *hs)
		if err != nil {
			t.Fatal(err)
		}
		ic, err := isCanonical(ctx, s.g, bh)
		if err != nil {
			t.Fatal(err)
		}

		if !ic {
			t.Fatalf("expected %v to be canonical", bname)
		}
		t.Logf("%v is canonical", bname)
	}

	// assert a and b chain blocks are not canonical
	for bname, hs := range altChainHashes {
		bh, err := s.g.db.BlockHeaderByHash(ctx, *hs)
		if err != nil {
			t.Fatal(err)
		}
		ic, err := isCanonical(ctx, s.g, bh)
		if err != nil {
			t.Fatal(err)
		}
		if ic {
			t.Fatalf("expected %v to not be canonical", bname)
		}
		t.Logf("%v is not canonical", bname)
	}
}

func TestCacheOverflow(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()

	popPriv, popPublic, popAddress, err := n.newKey("pop")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("pop keys:")
	t.Logf("  private    : %x", popPriv.Serialize())
	t.Logf("  public     : %x", popPublic.SerializeCompressed())
	t.Logf("  address    : %v", popAddress)

	go func() {
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:   false,
		BlockSanity: false,
		HemiIndex:   true, // Test keystone index
		LevelDBHome: t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            5,
		MaxCachedKeystones:      5,
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	const blockCount = 30 // must be >= 2
	blocks := make([]*block, blockCount)

	// mine blocks
	prevHash := chaincfg.RegressionNetParams.GenesisHash
	for i := 1; i <= blockCount; i++ {
		n.newKeystone(fmt.Sprintf("kss%d", i))
		blk, err := n.MineAndSend(ctx, "b"+strconv.Itoa(i), prevHash, n.address, MineWithMultiple)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("inserted %v / kss%d", blk.name, i)
		prevHash = blk.Hash()
		blocks[i-1] = blk
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Index to last block
	err = s.SyncIndexersToHash(ctx, *blocks[len(blocks)-1].Hash())
	if err != nil {
		t.Fatal(err)
	}

	// Checks
	for i := 2; i <= blockCount; i++ {
		kssName := fmt.Sprintf("kss%d", i)
		blk := blocks[i-1]
		t.Logf("checking %v / %v", blk.name, kssName)

		// keystones
		kss, err := n.lookupKeystone(kssName)
		if err != nil {
			t.Fatalf("%v not found: %v", kssName, err)
		}
		kssHash := hemi.L2KeystoneAbbreviate(*kss).Hash()
		rv, err := s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kssHash)
		if err != nil {
			t.Fatal(err)
		}
		if !rv.BlockHash.IsEqual(blk.Hash()) {
			t.Fatalf("wrong blockhash for stored %v: %v", kssName, rv.BlockHash)
		}
		hk, err := s.g.db.KeystonesByHeight(ctx, uint32(blk.Height()-1), 1)
		if err != nil {
			t.Fatal(err)
		}

		if len(hk) != 1 {
			t.Fatalf("expected 1 keystone at height %v, got %d", blk.Height(), len(hk))
		}

		if diff := deep.Equal(hk[0], *rv); len(diff) > 0 {
			t.Fatalf("unexpected keystone diff: %s %s", spew.Sdump(rv), spew.Sdump(hk[0]))
		}
	}

	if err = mustHave(ctx, t, s, blocks...); err != nil {
		t.Fatal(err)
	}

	// Index to genesis
	err = s.SyncIndexersToHash(ctx, *chaincfg.RegressionNetParams.GenesisHash)
	if err != nil {
		t.Fatal(err)
	}

	// Negative Checks
	for i := 2; i <= blockCount; i++ {
		kssName := fmt.Sprintf("kss%d", i)
		// keystones
		kss, err := n.lookupKeystone(kssName)
		if err != nil {
			t.Fatalf("%v not found: %v", kssName, err)
		}
		kssHash := hemi.L2KeystoneAbbreviate(*kss).Hash()
		_, err = s.g.db.BlockKeystoneByL2KeystoneAbrevHash(ctx, *kssHash)
		var expected database.NotFoundError
		if !errors.Is(err, expected) {
			t.Fatal(err)
		}
	}

	if err = mustNotHave(ctx, t, s, blocks...); err != nil {
		t.Fatal(err)
	}
}

func TestZKIndexFork(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 21*time.Second)
	defer func() {
		cancel()
	}()

	port := testutil.FreePort()
	n, err := newFakeNode(t, port)
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
		if err := n.Run(ctx); !errorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	// Connect tbc service
	cfg := &Config{
		AutoIndex:            false,
		BlockCacheSize:       "10mb",
		BlockheaderCacheSize: "1mb",
		BlockSanity:          false,
		ZKIndex:              true, // Test zk index
		LevelDBHome:          t.TempDir(),
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1000, // XXX
		MaxCachedKeystones:      1000, // XXX
		MaxCachedZK:             1000, // XXX
		Network:                 networkLocalnet,
		PeersWanted:             1,
		PrometheusListenAddress: "",
		MempoolEnabled:          true,
		Seeds:                   []string{"127.0.0.1:" + port},
		NotificationBlocking:    true,
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// Create a bunch of weird geometries to catch all corner cases in the indexer.

	//   /-> b1a -> b2a
	// g ->  b1 ->  b2 -> b3
	//   \-> b1b -> b2b

	// best is b3

	// best chain
	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// a chain
	b1a, err := n.MineAndSend(ctx, "b1a", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2a, err := n.MineAndSend(ctx, "b2a", b1a.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// b chain
	b1b, err := n.MineAndSend(ctx, "b1b", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2b, err := n.MineAndSend(ctx, "b2b", b1b.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	t.Logf("sync to b2")
	// Index to b2
	err = s.SyncIndexersToHash(ctx, *b2.Hash())
	if err != nil {
		t.Fatal(err)
	}

	err = mustHave(ctx, t, s, n.genesis, b1, b2)
	if err != nil {
		t.Fatal(err)
	}

	// append every zkInfo to verify everything gets unwound
	zki := make([]zkTxInInfo, 0)
	zko := make([]zkTxOutInfo, 0)

	// Check b2 TX
	txInfo := zkTxInfo{tx: b2.TxByIndex(1)}

	// b2 tx: txIn 0
	utxoTxId := *b1.TxByIndex(0).Hash()
	inInfo := zkTxInInfo{txInfo, 0, utxoTxId, 5e9}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2 tx: txOut 0
	outInfo := zkTxOutInfo{txInfo, 0, 3e9, 3e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2 tx: txOut 1
	outInfo = zkTxOutInfo{txInfo, 1, 7e9, 2e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// Index to b3
	t.Logf("sync to b3")
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatal(err)
	}

	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}

	// Check b3 TX1, which serves as TxIn for b3 TX2
	txInfo = zkTxInfo{tx: b3.TxByIndex(1)}

	// b3 tx1: txIn 0
	utxoTxId = *b2.TxByIndex(1).Hash()
	inInfo = zkTxInInfo{txInfo, 0, utxoTxId, 3e09}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b3 tx1: txOut 0
	outInfo = zkTxOutInfo{txInfo, 0, 0, 11e8}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b3 tx1: txOut 1
	outInfo = zkTxOutInfo{txInfo, 1, 0, 19e8}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// Check b3 TX2
	txInfo = zkTxInfo{tx: b3.TxByIndex(2)}

	// b3 tx2: txIn 0
	utxoTxId = *b3.TxByIndex(1).Hash()
	inInfo = zkTxInInfo{txInfo, 0, utxoTxId, 11e08}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b3 tx2: txIn 1
	inInfo = zkTxInInfo{txInfo, 1, utxoTxId, 19e8}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b3 tx2: txOut 0
	outInfo = zkTxOutInfo{txInfo, 0, 3e9, 11e8}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b3 tx2: txOut 1
	outInfo = zkTxOutInfo{txInfo, 1, 3e9, 19e8}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// Verify linear indexing. Current TxIndex is sitting at b3
	t.Logf("b3: %v", b3)

	// b3 -> genesis should work with positive direction (cdiff is greater than target)
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("expected success b3 -> genesis, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b1 should work with positive direction
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b1.Hash())
	if err != nil {
		t.Fatalf("expected success b3 -> b1, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b2a should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2a.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2a is not linear to b3: %v", err)
	}

	// b3 -> b2b should fail
	_, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b2b.Hash())
	if !errors.Is(err, ErrNotLinear) {
		t.Fatalf("b2b is not linear to b3: %v", err)
	}

	// make sure syncing to itself is non linear
	err = s.SyncIndexersToHash(ctx, *b3.Hash())
	if err != nil {
		t.Fatalf("at b3, should have returned nil, got %v", err)
	}

	// unwind back to genesis
	t.Logf("unwind to genesis")
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	// check everything was unwound
	for _, zkIn := range zki {
		zkValidateTxIn(ctx, s, &zkIn)
		if len(zkIn.errors) != 4 {
			t.Fatalf("expected 4 checks to fail, got: %v", zkIn.Err())
		}
	}
	for _, zkOut := range zko {
		zkOut.balance = 1 // prevent valid 0 on error
		zkValidateTxOut(ctx, s, &zkOut)
		if len(zkOut.errors) != 5 {
			t.Fatalf("expected 5 checks to fail, got: %v", zkOut.Err())
		}
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// XXX verify indexes
	txBH, err := s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}

	// see if we can move to b2a
	direction, err = indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b2a.Hash())
	if err != nil {
		t.Fatalf("expected success genesis -> b2a, got %v", err)
	}
	if direction != 1 {
		t.Fatalf("expected 1 going from genesis to b2a, got %v", direction)
	}

	t.Logf("sync to b2a")
	err = s.SyncIndexersToHash(ctx, *b2a.Hash())
	if err != nil {
		t.Fatalf("wind to b2a: %v", err)
	}

	// append every zkInfo to verify everything gets unwound
	zki = make([]zkTxInInfo, 0)
	zko = make([]zkTxOutInfo, 0)

	// Check b2a TX
	txInfo = zkTxInfo{tx: b2a.TxByIndex(1)}

	// b2a tx: txIn 0
	utxoTxId = *b1a.TxByIndex(0).Hash()
	inInfo = zkTxInInfo{txInfo, 0, utxoTxId, 5e9}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2a tx: txOut 0
	outInfo = zkTxOutInfo{txInfo, 0, 3e9, 3e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2a tx: txOut 1
	outInfo = zkTxOutInfo{txInfo, 1, 7e9, 2e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// unwind back to genesis
	t.Logf("unwind to genesis 2")
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	// check everything was unwound
	for _, zkIn := range zki {
		zkValidateTxIn(ctx, s, &zkIn)
		if len(zkIn.errors) != 4 {
			t.Fatalf("expected 4 checks to fail, got: %v", zkIn.Err())
		}
	}
	for _, zkOut := range zko {
		zkOut.balance = 1 // prevent valid 0 on error
		zkValidateTxOut(ctx, s, &zkOut)
		if len(zkOut.errors) != 5 {
			t.Fatalf("expected 5 checks to fail, got: %v", zkOut.Err())
		}
	}

	txBH, err = s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	t.Logf("sync to b2b")
	err = s.SyncIndexersToHash(ctx, *b2b.Hash())
	if err != nil {
		t.Fatalf("wind to b2b: %v", err)
	}

	// append every zkInfo to verify everything gets unwound
	zki = make([]zkTxInInfo, 0)
	zko = make([]zkTxOutInfo, 0)

	// Check b2b TX
	txInfo = zkTxInfo{tx: b2b.TxByIndex(1)}

	// b2b tx: txIn 0
	utxoTxId = *b1b.TxByIndex(0).Hash()
	inInfo = zkTxInInfo{txInfo, 0, utxoTxId, 5e9}
	zki = append(zki, inInfo)
	zkValidateTxIn(ctx, s, &inInfo)
	if err := inInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2b tx: txOut 0
	outInfo = zkTxOutInfo{txInfo, 0, 3e9, 3e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	// b2b tx: txOut 1
	outInfo = zkTxOutInfo{txInfo, 1, 7e9, 2e9}
	zko = append(zko, outInfo)
	zkValidateTxOut(ctx, s, &outInfo)
	if err := outInfo.Err(); err != nil {
		t.Fatal(err)
	}

	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// unwind back to genesis
	t.Logf("unwind to genesis 3")
	err = s.SyncIndexersToHash(ctx, *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("unwinding to genesis should have returned nil, got %v", err)
	}
	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err == nil {
		t.Fatalf("expected an error from mustHave")
	}

	// check everything was unwound
	for _, zkIn := range zki {
		zkValidateTxIn(ctx, s, &zkIn)
		if len(zkIn.errors) != 4 {
			t.Fatalf("expected 4 checks to fail, got: %v", zkIn.Err())
		}
	}
	for _, zkOut := range zko {
		zkOut.balance = 1 // prevent valid 0 on error
		zkValidateTxOut(ctx, s, &zkOut)
		if len(zkOut.errors) != 5 {
			t.Fatalf("expected 5 checks to fail, got: %v", zkOut.Err())
		}
	}

	txBH, err = s.ti.IndexerAt(ctx)
	if err != nil {
		t.Fatalf("expected success getting tx index hash, got: %v", err)
	}
	if !txBH.Hash.IsEqual(s.g.chain.GenesisHash) {
		t.Fatalf("expected tx index hash to be equal to genesis, got: %v", txBH)
	}
	if txBH.Height != 0 {
		t.Fatalf("expected tx index height to be 0, got: %v", txBH.Height)
	}
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
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
