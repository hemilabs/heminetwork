// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbcd

import (
	"context"

	"github.com/hemilabs/heminetwork/database"
)

type Database interface {
	database.Database

	// Metadata
	Version(ctx context.Context) (int, error)
	MetadataGet(ctx context.Context, key []byte) ([]byte, error)
	MetadataPut(ctx context.Context, key, value []byte) error

	// Block header
	BlockHeaderByHash(ctx context.Context, hash []byte) (*BlockHeader, error)
	BlockHeadersBest(ctx context.Context) ([]BlockHeader, error)
	BlockHeadersInsert(ctx context.Context, bhs []BlockHeader) error
	BlockHeadersByHeight(ctx context.Context, height uint64) ([]BlockHeader, error)

	// Block
	BlocksMissing(ctx context.Context, count int) ([]BlockIdentifier, error)
	BlockInsert(ctx context.Context, b *Block) (int64, error)
	// XXX replace BlockInsert with plural version
	// BlocksInsert(ctx context.Context, bs []*Block) (int64, error)
	BlockByHash(ctx context.Context, hash []byte) (*Block, error)

	// Transactions
	// UTxosInsert(ctx context.Context, butxos []BlockUtxo) error
	// BlockTxUpdate(ctx context.Context, blockhash []byte, btxs []Tx) error

	// Peer manager
	PeersStats(ctx context.Context) (int, int)               // good, bad count
	PeersInsert(ctx context.Context, peers []Peer) error     // insert or update
	PeerDelete(ctx context.Context, host, port string) error // remove peer
	PeersRandom(ctx context.Context, count int) ([]Peer, error)
}

// BlockHeader contains the first 80 raw bytes of a bitcoin block and its
// location information (hash+height).
type BlockHeader struct {
	Hash   database.ByteArray
	Height uint64
	Header database.ByteArray
}

// Block contains a raw bitcoin block and its corresponding hash.
type Block struct {
	Hash  database.ByteArray
	Block database.ByteArray
}

// BlockIdentifier uniquely identifies a block using it's hash and height.
type BlockIdentifier struct {
	Height uint64
	Hash   database.ByteArray
}

// Peer
type Peer struct {
	Host      string
	Port      string
	LastAt    database.Timestamp `deep:"-"` // Last time connected
	CreatedAt database.Timestamp `deep:"-"`
}

//// TxIn is a cooked bitcoin input.
//type TxIn struct {
//	Hash  database.ByteArray // Previous hash
//	Index uint32             // Previous index
//}
//
//// TxIn is a cooked bitcoin output.
//type TxOut struct {
//	PkScript database.ByteArray // Spend script
//	Value    uint64             // Satoshis
//}
//
//// Tx is a cooked bitcoin transaction.
//type Tx struct {
//	Id    database.ByteArray // TxId
//	Index uint32             // Transaction index in block
//	In    []TxIn             // Inputs
//	Out   []TxOut            // Outputs
//}
//
//// Utxos extracts all transactions from the provided block and returns the
//// block and a, in sequence, list of all transactions.
//func BlockTxs(cp *chaincfg.Params, bb []byte) (*chainhash.Hash, []Tx, error) {
//	b, err := btcutil.NewBlockFromBytes(bb)
//	if err != nil {
//		return nil, nil, err
//	}
//
//	txs := b.Transactions()
//	btxs := make([]Tx, 0, len(txs))
//	for _, tx := range txs {
//		txCHash := tx.Hash()
//		btx := Tx{
//			Id:    txCHash[:],
//			Index: uint32(tx.Index()),
//			In:    make([]TxIn, 0, len(tx.MsgTx().TxIn)),
//			Out:   make([]TxOut, 0, len(tx.MsgTx().TxOut)),
//		}
//		for _, txIn := range tx.MsgTx().TxIn {
//			btx.In = append(btx.In, TxIn{
//				Hash:  txIn.PreviousOutPoint.Hash[:],
//				Index: txIn.PreviousOutPoint.Index,
//			})
//		}
//		for , txOut := range tx.MsgTx().TxOut {
//			btx.Out = append(btx.Out, TxOut{
//				PkScript: txOut.PkScript,
//				Value:    uint64(txOut.Value),
//			})
//		}
//		btxs = append(btxs, btx)
//	}
//
//	return b.Hash(), btxs, nil
//}
