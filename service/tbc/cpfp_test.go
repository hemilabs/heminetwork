// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/v2/database/tbcd"
)

// stubDB implements tbcd.Database by returning errors for every
// method that parseTx's call chain can reach.  This lets us verify
// the CPFP mempool fallback without a real database.
type stubDB struct{}

func (stubDB) Close() error { return nil }

// BlockHashByTxId is the first thing txOutFromOutPoint calls.
// Returning an error simulates "parent not in block db", which
// is the trigger for the CPFP mempool fallback.
func (stubDB) BlockHashByTxId(context.Context, chainhash.Hash) (*chainhash.Hash, *wire.TxLoc, error) {
	return nil, nil, errors.New("not found")
}

// The remaining methods satisfy the tbcd.Database interface but
// should never be reached by parseTx when BlockHashByTxId fails.
func (stubDB) Version(context.Context) (int, error)                { panic("stub") }
func (stubDB) MetadataDel(context.Context, []byte) error           { panic("stub") }
func (stubDB) MetadataGet(context.Context, []byte) ([]byte, error) { panic("stub") }
func (stubDB) MetadataPut(context.Context, []byte, []byte) error   { panic("stub") }
func (stubDB) MetadataBatchGet(context.Context, bool, [][]byte) ([]tbcd.Row, error) {
	panic("stub")
}
func (stubDB) MetadataBatchPut(context.Context, []tbcd.Row) error { panic("stub") }
func (stubDB) BlockHeaderBest(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockHeaderByHash(context.Context, chainhash.Hash) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockHeaderGenesisInsert(context.Context, wire.BlockHeader, uint64, *big.Int) error {
	panic("stub")
}
func (stubDB) BlockHeaderCacheStats() tbcd.CacheStats { panic("stub") }
func (stubDB) BlockHeadersByHeight(context.Context, uint64) ([]tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockHeadersInsert(context.Context, *wire.MsgHeaders, tbcd.BatchHook) (tbcd.InsertType, *tbcd.BlockHeader, *tbcd.BlockHeader, int, error) {
	panic("stub")
}

func (stubDB) BlockHeadersRemove(context.Context, *wire.MsgHeaders, *wire.BlockHeader, tbcd.BatchHook) (tbcd.RemoveType, *tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlocksMissing(context.Context, int) ([]tbcd.BlockIdentifier, error) {
	panic("stub")
}

func (stubDB) BlockMissingDelete(context.Context, int64, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) BlockInsert(context.Context, *btcutil.Block) (int64, error) {
	panic("stub")
}

func (stubDB) BlockByHash(context.Context, chainhash.Hash) (*btcutil.Block, error) {
	panic("stub")
}

func (stubDB) BlockRawByHash(context.Context, chainhash.Hash) ([]byte, error) {
	panic("stub")
}

func (stubDB) BlockExistsByHash(context.Context, chainhash.Hash) (bool, error) {
	panic("stub")
}
func (stubDB) BlockCacheStats() tbcd.CacheStats { panic("stub") }
func (stubDB) BlockHeaderByUtxoIndex(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockHeaderByTxIndex(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockUtxoUpdate(context.Context, int, map[tbcd.Outpoint]tbcd.CacheOutput, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) BlockTxUpdate(context.Context, int, map[tbcd.TxKey]*tbcd.TxValue, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) SpentOutputsByTxId(context.Context, chainhash.Hash) ([]tbcd.SpentInfo, error) {
	panic("stub")
}

func (stubDB) BalanceByScriptHash(context.Context, tbcd.ScriptHash) (uint64, error) {
	panic("stub")
}

func (stubDB) BlockInTxIndex(context.Context, chainhash.Hash) (bool, error) {
	panic("stub")
}

func (stubDB) ScriptHashByOutpoint(context.Context, tbcd.Outpoint) (*tbcd.ScriptHash, error) {
	panic("stub")
}

func (stubDB) ScriptHashesByOutpoint(context.Context, []*tbcd.Outpoint, func(tbcd.Outpoint, tbcd.ScriptHash) error) error {
	panic("stub")
}

func (stubDB) UtxosByScriptHash(context.Context, tbcd.ScriptHash, uint64, uint64) ([]tbcd.Utxo, error) {
	panic("stub")
}

func (stubDB) UtxosByScriptHashCount(context.Context, tbcd.ScriptHash) (uint64, error) {
	panic("stub")
}

func (stubDB) BlockKeystoneUpdate(context.Context, int, map[chainhash.Hash]tbcd.Keystone, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) BlockKeystoneByL2KeystoneAbrevHash(context.Context, chainhash.Hash) (*tbcd.Keystone, error) {
	panic("stub")
}

func (stubDB) BlockHeaderByKeystoneIndex(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) KeystonesByHeight(context.Context, uint32, int) ([]tbcd.Keystone, error) {
	panic("stub")
}

func (stubDB) BlockHeaderByZKIndex(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockZKUpdate(context.Context, int, map[tbcd.ZKIndexKey][]byte, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) ZKValueAndScriptByOutpoint(context.Context, tbcd.Outpoint) (uint64, []byte, error) {
	panic("stub")
}

func (stubDB) ZKBalanceByScriptHash(context.Context, tbcd.ScriptHash) (uint64, error) {
	panic("stub")
}

func (stubDB) ZKSpentOutputs(context.Context, tbcd.ScriptHash) ([]tbcd.ZKSpentOutput, error) {
	panic("stub")
}

func (stubDB) ZKSpendingOutpoints(context.Context, chainhash.Hash) ([]tbcd.ZKSpendingOutpoint, error) {
	panic("stub")
}

func (stubDB) ZKSpendableOutputs(context.Context, tbcd.ScriptHash) ([]tbcd.ZKSpendableOutput, error) {
	panic("stub")
}

func (stubDB) BlockHeaderByOrdinalIndex(context.Context) (*tbcd.BlockHeader, error) {
	panic("stub")
}

func (stubDB) BlockOrdinalUpdate(context.Context, int, map[tbcd.OrdinalKey][]byte, chainhash.Hash) error {
	panic("stub")
}

func (stubDB) OrdinalSatRangesByOutpoint(context.Context, tbcd.Outpoint) ([]byte, error) {
	panic("stub")
}

func (stubDB) OrdinalInscriptionByID(context.Context, [36]byte) ([]byte, error) {
	panic("stub")
}

func (stubDB) OrdinalInscriptionsByBlockHash(context.Context, chainhash.Hash) ([][36]byte, error) {
	panic("stub")
}

func (stubDB) OrdinalInscribedSatsInRange(context.Context, uint64, uint64) ([]uint64, error) {
	panic("stub")
}

func (stubDB) OrdinalOutpointBySat(context.Context, uint64) (*tbcd.Outpoint, error) {
	panic("stub")
}

func (stubDB) OrdinalInscriptionsBySat(context.Context, uint64) ([][36]byte, error) {
	panic("stub")
}

// TestTxOutByOutpoint verifies that txOutByOutpoint resolves an
// output from a parent transaction that is in the mempool.
func TestTxOutByOutpoint(t *testing.T) {
	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	// Build a parent transaction with a known output.
	parentTx := wire.NewMsgTx(2)
	parentTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.DoubleHashH([]byte("coinbase")),
			Index: 0,
		},
	})
	parentTx.AddTxOut(wire.NewTxOut(50_000, []byte{0x00, 0x14, 0xaa}))
	parentTx.AddTxOut(wire.NewTxOut(30_000, []byte{0x00, 0x14, 0xbb}))

	parentHash := parentTx.TxHash()

	mptx := NewMempoolTx(parentTx)
	mptx.expires = time.Now().Add(time.Minute)
	mptx.size = 250
	ctx := context.Background()
	if err := mp.TxInsert(ctx, &mptx); err != nil {
		t.Fatal(err)
	}

	// Index 0 should return the first output.
	out := mp.txOutByOutpoint(parentHash, 0)
	if out == nil {
		t.Fatal("expected output at index 0")
	}
	if out.Value != 50_000 {
		t.Fatalf("expected value 50000, got %d", out.Value)
	}

	// Index 1 should return the second output.
	out = mp.txOutByOutpoint(parentHash, 1)
	if out == nil {
		t.Fatal("expected output at index 1")
	}
	if out.Value != 30_000 {
		t.Fatalf("expected value 30000, got %d", out.Value)
	}
}

// TestTxOutByOutpointNotFound verifies that txOutByOutpoint returns
// nil when the transaction is not in the mempool.
func TestTxOutByOutpointNotFound(t *testing.T) {
	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	missing := chainhash.DoubleHashH([]byte("missing-tx"))
	if out := mp.txOutByOutpoint(missing, 0); out != nil {
		t.Fatalf("expected nil for missing tx, got %v", out)
	}
}

// TestTxOutByOutpointBadIndex verifies that txOutByOutpoint returns
// nil when the output index is out of range.
func TestTxOutByOutpointBadIndex(t *testing.T) {
	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	parentTx := wire.NewMsgTx(2)
	parentTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.DoubleHashH([]byte("coinbase")),
			Index: 0,
		},
	})
	parentTx.AddTxOut(wire.NewTxOut(50_000, []byte{0x00, 0x14, 0xaa}))

	mptx := NewMempoolTx(parentTx)
	mptx.expires = time.Now().Add(time.Minute)
	mptx.size = 250
	ctx := context.Background()
	if err := mp.TxInsert(ctx, &mptx); err != nil {
		t.Fatal(err)
	}

	parentHash := parentTx.TxHash()

	// Index 1 is out of range (only one output).
	if out := mp.txOutByOutpoint(parentHash, 1); out != nil {
		t.Fatalf("expected nil for out-of-range index, got %v", out)
	}

	// Large index.
	if out := mp.txOutByOutpoint(parentHash, 999); out != nil {
		t.Fatalf("expected nil for large index, got %v", out)
	}
}

// TestParseTxCPFP verifies the child-pays-for-parent path in
// parseTx: when a child transaction spends an output from an
// unconfirmed parent, parseTx resolves the input value from the
// mempool instead of the block database.
func TestParseTxCPFP(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	// Build and insert a parent transaction into the mempool.
	parentTx := wire.NewMsgTx(2)
	parentTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  chainhash.DoubleHashH([]byte("coinbase")),
			Index: 0,
		},
	})
	parentTx.AddTxOut(wire.NewTxOut(100_000, []byte{0x00, 0x14, 0xcc}))

	mptx := NewMempoolTx(parentTx)
	mptx.expires = time.Now().Add(time.Minute)
	mptx.inValue = 100_000
	mptx.outValue = 100_000
	mptx.size = 250
	if err := mp.TxInsert(ctx, &mptx); err != nil {
		t.Fatal(err)
	}

	// Build a child that spends the parent's output 0.
	childTx := wire.NewMsgTx(2)
	childTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{
			Hash:  parentTx.TxHash(),
			Index: 0,
		},
	})
	childTx.AddTxOut(wire.NewTxOut(90_000, []byte{0x00, 0x14, 0xdd}))

	// parseTx with a stub db that always fails lookups — the CPFP
	// path should resolve the parent's output from the mempool.
	db := stubDB{}
	inVal, outVal, err := parseTx(ctx, db, mp, childTx)
	if err != nil {
		t.Fatalf("parseTx CPFP failed: %v", err)
	}
	if inVal != 100_000 {
		t.Fatalf("expected input value 100000, got %d", inVal)
	}
	if outVal != 90_000 {
		t.Fatalf("expected output value 90000, got %d", outVal)
	}
}

// TestParseTxCPFPNoMempool verifies that parseTx fails when the
// parent is not in the block database AND no mempool is provided.
func TestParseTxCPFPNoMempool(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	parentHash := chainhash.DoubleHashH([]byte("parent"))
	childTx := wire.NewMsgTx(2)
	childTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0},
	})
	childTx.AddTxOut(wire.NewTxOut(90_000, []byte{0x00, 0x14, 0xdd}))

	db := stubDB{}
	_, _, err := parseTx(ctx, db, nil, childTx)
	if err == nil {
		t.Fatal("expected error when parent not in db and no mempool")
	}
}

// TestParseTxCPFPParentNotInMempool verifies that parseTx fails when
// the parent is in neither the block database nor the mempool.
func TestParseTxCPFPParentNotInMempool(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	mp, err := NewMempool()
	if err != nil {
		t.Fatal(err)
	}

	parentHash := chainhash.DoubleHashH([]byte("missing-parent"))
	childTx := wire.NewMsgTx(2)
	childTx.AddTxIn(&wire.TxIn{
		PreviousOutPoint: wire.OutPoint{Hash: parentHash, Index: 0},
	})
	childTx.AddTxOut(wire.NewTxOut(90_000, []byte{0x00, 0x14, 0xdd}))

	db := stubDB{}
	_, _, err = parseTx(ctx, db, mp, childTx)
	if err == nil {
		t.Fatal("expected error when parent not in db or mempool")
	}
}
