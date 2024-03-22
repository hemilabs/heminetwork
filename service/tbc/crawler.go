package tbc

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"

	"github.com/hemilabs/heminetwork/database/tbcd"
)

// Outpoint is a bitcoin structure that points to a transaction in a block. It
// is expressed as an array of bytes in order to pack it as dense as possible
// for memory conservation reasons.
type Outpoint [36]byte // Outpoint Tx id

// String returns a reversed pretty printed outpoint.
func (o Outpoint) String() string {
	hash, _ := chainhash.NewHash(o[0:32])
	return fmt.Sprintf("%s:%d", hash, binary.BigEndian.Uint32(o[32:]))
}

func (o Outpoint) TxId() []byte {
	return o[0:32]
}

func (o Outpoint) TxIndex() uint32 {
	return binary.BigEndian.Uint32(o[32:])
}

func NewOutpoint(txid [32]byte, index uint32) (op Outpoint) {
	copy(op[0:32], txid[:])
	binary.BigEndian.PutUint32(op[32:], index)
	return
}

// Utxo is a densely packed representation of a bitcoin UTXo. The fields are
// script_hash + value + out_index. It is packed for
// memory conservation reasons.
type Utxo [32 + 8 + 4]byte // scipt_hash + value + out_idx

// String reutrns pretty printable Utxo. Hash is not reversed since it is an
// opaque pointer. It prints satoshis@script_hash:output_index
func (u Utxo) String() string {
	return fmt.Sprintf("%d @ %x:%d", binary.BigEndian.Uint64(u[32:40]),
		u[0:32], binary.BigEndian.Uint32(u[40:]))
}

func (u Utxo) ScriptHash() []byte {
	return u[0:32]
}

func (u Utxo) Value() uint64 {
	return binary.BigEndian.Uint64(u[32:40])
}

func (u Utxo) OutputIndex() uint32 {
	return binary.BigEndian.Uint32(u[40:])
}

func NewUtxo(scriptHash [32]byte, value uint64, outIndex uint32) (utxo Utxo) {
	copy(utxo[0:32], scriptHash[:])
	binary.BigEndian.PutUint64(utxo[32:40], value)
	binary.BigEndian.PutUint32(utxo[40:], outIndex)
	return
}

//type Tx struct {
//	Id    chainhash.Hash // TxId
//	Index int            // Transaction index in block
//	In    []Outpoint     // Inputs
//	Out   []Utxo         // Outputs
//}

var DeleteUtxo Utxo

func init() {
	// Initialize sentinel that marks utxo cache entries for deletion
	for i := 0; i < len(DeleteUtxo); i++ {
		DeleteUtxo[i] = 0xff
	}
}

//// parseBlock walks a iraw bitcoin block's transactions and generates an in
//// order list of execution parameters to update the utxo cache. This function
//// should not be creating an intermediate data structure but take functios to
//// add/remove/update entries in the cache instead.
//func parseBlock(cp *chaincfg.Params, bb []byte) (*chainhash.Hash, []Tx, error) {
//	b, err := btcutil.NewBlockFromBytes(bb)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	txs := b.Transactions()
//	btxs := make([]Tx, 0, len(txs))
//	for _, tx := range txs {
//		btx := Tx{
//			Id:    *tx.Hash(),
//			Index: tx.Index(),
//			In:    make([]Outpoint, 0, len(tx.MsgTx().TxIn)),
//			Out:   make([]Utxo, 0, len(tx.MsgTx().TxOut)),
//		}
//		for _, txIn := range tx.MsgTx().TxIn {
//			btx.In = append(btx.In, NewOutpoint(
//				txIn.PreviousOutPoint.Hash,
//				txIn.PreviousOutPoint.Index,
//			))
//		}
//		for outIndex, txOut := range tx.MsgTx().TxOut {
//			btx.Out = append(btx.Out, NewUtxo(
//				sha256.Sum256(txOut.PkScript),
//				uint64(txOut.Value),
//				uint32(outIndex),
//			))
//		}
//		btxs = append(btxs, btx)
//	}
//
//	return b.Hash(), btxs, nil
//}

func OutpointFromTx(tx *btcutil.Tx) Outpoint {
	return NewOutpoint(*tx.Hash(), uint32(tx.Index()))
}

func parseBlockAndCache(cp *chaincfg.Params, bb []byte, utxos map[Outpoint]Utxo) (*btcutil.Block, error) {
	b, err := btcutil.NewBlockFromBytes(bb)
	if err != nil {
		return nil, err
	}

	txs := b.Transactions()
	for idx, tx := range txs {
		for _, txIn := range tx.MsgTx().TxIn {
			if idx == 0 {
				// Skip coinbase inputs
			}
			op := NewOutpoint(txIn.PreviousOutPoint.Hash,
				txIn.PreviousOutPoint.Index)
			if _, ok := utxos[op]; ok {
				delete(utxos, op)
				continue
			}
			// mark for deletion
			utxos[op] = DeleteUtxo
		}
		for outIndex, txOut := range tx.MsgTx().TxOut {
			utxos[OutpointFromTx(tx)] = NewUtxo(
				sha256.Sum256(txOut.PkScript),
				uint64(txOut.Value),
				uint32(outIndex))
		}
	}
	// log.Infof("%v", spew.Sdump(utxos))
	return b, nil
}

func (s *Server) indexBlock(ctx context.Context, height uint64, b *tbcd.Block) error {
	log.Tracef("indexBlock")
	defer log.Tracef("indexBlock")

	_, err := parseBlockAndCache(s.chainParams, b.Block, s.utxos)
	//bh, txs, err := parseBlock(s.chainParams, b.Block)
	//if err != nil {
	//	return fmt.Errorf("index block: %w", err)
	//}
	//log.Infof("%v: %v", bh)
	//log.Infof("%%v", txs)

	return err
}

func (s *Server) indexBlocks(ctx context.Context, startHeight uint64) (int, error) {
	log.Tracef("indexBlocks")
	defer log.Tracef("indexBlocks")

	blocksProcessed := 0
	for height := startHeight; ; height++ {
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			return 0, fmt.Errorf("block headers by height %v: %v", height, err)
		}
		eb, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			return 0, fmt.Errorf("block by hash %v: %v", height, err)
		}
		b, err := parseBlockAndCache(s.chainParams, eb.Block, s.utxos)
		if err != nil {
			return 0, fmt.Errorf("parse block %v: %v", height, err)
		}
		_ = b

		blocksProcessed++

		// Try not to overshoot the cache to prevent costly allocations
		cp := len(s.utxos) * 100 / s.utxosMax
		if height%10000 == 0 || cp > s.utxosPercentage || blocksProcessed == 1 {
			log.Infof("Height: %v utxo cache %v%%", height, cp)
		}
		if cp > s.utxosPercentage {
			// Set utxosMax to the largest utxo capacity seen
			s.utxosMax = max(len(s.utxos), s.utxosMax)
			// Flush
			break
		}
	}

	return blocksProcessed, nil
}

func (s *Server) indexer(ctx context.Context) error {
	height := uint64(0)
	log.Infof("Start indexing at height %v", height)
	for {
		start := time.Now()
		blocksProcessed, err := s.indexBlocks(ctx, height)
		if err != nil {
			return fmt.Errorf("index blocks: %w", err)
		}
		log.Infof("blocks processed %v in %v utxos cached %v cache unused %v avg tx/blk %v",
			blocksProcessed, time.Now().Sub(start), len(s.utxos),
			s.utxosMax-len(s.utxos), len(s.utxos)/blocksProcessed)

		// This is where we flush, simulate behavior by deleting utxos
		for k := range s.utxos {
			delete(s.utxos, k)
		}

		height += uint64(blocksProcessed)
	}
}
