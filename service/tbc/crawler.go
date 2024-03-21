package tbc

import (
	"context"
	"encoding/binary"
	"fmt"

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

func (s *Server) indexBlock(ctx context.Context, b *tbcd.Block) error {
	log.Tracef("indexBlock")
	defer log.Tracef("indexBlock")

	return nil
}

func (s *Server) indexBlocks(ctx context.Context, b *tbcd.Block) error {
	log.Tracef("indexBlocks")
	defer log.Tracef("indexBlocks")

	startHeight := uint64(0)
	count := uint64(382)
	for height := startHeight; height < startHeight+count; height++ {
		bhs, err := s.db.BlockHeadersByHeight(ctx, height)
		if err != nil {
			fmt.Errorf("block headers by height %v: %v", height, err)
		}
		b, err := s.db.BlockByHash(ctx, bhs[0].Hash)
		if err != nil {
			fmt.Errorf("block by hash %v: %v", height, err)
		}
		_ = b
		//bh, btxs, err := tbcd.BlockTxs(&chaincfg.TestNet3Params, b.Block)
		//if err != nil {
		//	t.Fatalf("block transactions %v: %v", height, err)
		//}
		//err = db.BlockTxUpdate(ctx, bh[:], btxs)
		//if err != nil {
		//	// t.Fatalf("%v", spew.Sdump(btxs))
		//	t.Fatalf("block utxos %v: %v", height, err)
		//}
		//if height%1000 == 0 {
		//	log.Infof("height %v %v", height, time.Now().Sub(elapsed))
		//	elapsed = time.Now()
		//}
	}

	return nil
}
