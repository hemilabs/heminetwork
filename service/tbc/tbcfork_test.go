package tbc

import (
	"context"
	"errors"
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

type heightHeader struct {
	height int
	block  *btcutil.Block
}

type btcNode struct {
	mtx    sync.RWMutex
	t      *testing.T
	port   string
	chain  map[string]heightHeader
	height int
	best   *chainhash.Hash
	params *chaincfg.Params
}

func newFakeNode(t *testing.T, port string) (*btcNode, error) {
	return &btcNode{
		t:      t,
		port:   port,
		chain:  make(map[string]heightHeader, 10),
		height: 0,
		params: &chaincfg.RegressionNetParams,
		best:   chaincfg.RegressionNetParams.GenesisHash,
	}, nil
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

		default:
			b.t.Logf("unhandled command: %v", spew.Sdump(msg))
		}
	}
}

// borrowed from btcd
//
// Copyright (c) 2014-2016 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
var CoinbaseFlags = "/P2SH/btcd/"

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

func newBlockTemplate(params *chaincfg.Params, payToAddress btcutil.Address) (*wire.MsgBlock, error) {
	block := &wire.MsgBlock{}

	nextBlockHeight := int32(1)
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

	return block, nil
}

func (b *btcNode) Best() *chainhash.Hash {
	b.mtx.Lock()
	defer b.mtx.Unlock()
	return b.best
}

func (b *btcNode) Mine(count int, from *chainhash.Hash) (*wire.MsgBlock, error) {
	best := b.Best()
	b.t.Logf("Best: %v", spew.Sdump(best))

	block := &wire.MsgBlock{}

	// bh := wire.NewBlockHeader(1, best, mrh, bits, nonce)

	//var msgBlock wire.MsgBlock
	//msgBlock.Header = wire.BlockHeader{
	//	Version:    nextBlockVersion,
	//	PrevBlock:  *from,
	//	MerkleRoot: blockchain.CalcMerkleRoot(blockTxns, false),
	//	Timestamp:  time.Now(),
	//	Bits:       reqDifficulty,
	//}

	return block, nil
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
			t.Fatal(err)
		}
	}()

	startHash := n.Best()
	_, err = n.Mine(10, startHash)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second) // XXX

	//t.Logf("connecting")
	//d := &net.Dialer{}
	//conn, err := d.DialContext(ctx, "tcp", "127.0.0.1:18444")
	//if err != nil {
	//	t.Fatal(err)
	//}
	//t.Logf("writing")
	//_, err = conn.Write([]byte("moo"))
	//if err != nil {
	//	t.Fatal(err)
	//}

	cfg := &Config{
		AutoIndex:               false, // XXX for now
		BlockSanity:             false,
		LevelDBHome:             "/tmp/xxx", // XXX
		ListenAddress:           tbcapi.DefaultListen,
		LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
		MaxCachedTxs:            1, // XXX
		Network:                 networkLocalnet,
		PrometheusListenAddress: "",
	}
	loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	err = s.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
}
