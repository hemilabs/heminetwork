package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

func bytes2Header(header []byte) (*wire.BlockHeader, error) {
	var bh wire.BlockHeader
	err := bh.Deserialize(bytes.NewReader(header))
	if err != nil {
		return nil, fmt.Errorf("Deserialize: %v", err)
	}
	return &bh, nil
}

func h2b(wbh *wire.BlockHeader) []byte {
	hb, err := header2Bytes(wbh)
	if err != nil {
		panic(err)
	}
	return hb
}

func header2Bytes(wbh *wire.BlockHeader) ([]byte, error) {
	var b bytes.Buffer
	err := wbh.Serialize(&b)
	if err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

func TestKey(t *testing.T) {
	height := uint64(0xffeeddcc11223344)
	hv := []byte{1, 3, 3, 7}
	hash := chainhash.DoubleHashH(hv)
	key := heightHashToKey(height, hash[:])

	heightO, hashO := keyToHeightHash(key)
	if height != heightO {
		t.Fatalf("invalid height wanted %v got %v", height, heightO)
	}
	if !bytes.Equal(hash[:], hashO) {
		t.Fatalf("invalid hash wanted %v got %v",
			spew.Sdump(hash), spew.Sdump(hashO))
	}

	t.Logf("height %x", height)
	t.Logf("key %v", spew.Sdump(key))
	t.Logf("%v%v", spew.Sdump(hash[:]), spew.Sdump(hashO))
}

type ByteSlice [][]byte

func (x ByteSlice) Len() int           { return len(x) }
func (x ByteSlice) Less(i, j int) bool { return bytes.Compare(x[i], x[j]) == -1 }
func (x ByteSlice) Swap(i, j int)      { x[i], x[j] = x[j], x[i] }

func TestKeyOrder(t *testing.T) {
	// Create slice in reverse order
	count := uint64(10)
	keys := make(ByteSlice, count)
	for i := uint64(0); i < count; i++ {
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, i)
		hash := chainhash.DoubleHashH(b)
		keys[count-1-i] = heightHashToKey(i, hash[:])
	}
	log.Infof("%v", spew.Sdump(keys))

	// Now sort
	sort.Sort(keys)
	log.Infof("%v", spew.Sdump(keys))

	for i := uint64(0); i < count; i++ {
		height, hash := keyToHeightHash(keys[i])
		if i != height {
			t.Fatalf("invalid height wanted %v got %v", i, height)
		}

		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, i)
		expectedHash := chainhash.DoubleHashH(b)
		if !bytes.Equal(expectedHash[:], hash) {
			t.Fatalf("invalid hash wanted %x got %x", expectedHash, hash)
		}
	}
}

func TestLevelDB(t *testing.T) {
	// Missing blocks
	// 1 000 000 000

	dir, err := os.MkdirTemp("", "leveldbtest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)

	ctx := context.Background()
	ldb, err := New(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := ldb.Close()
		if err != nil {
			t.Fatalf("close: %v", err)
		}
	}()

	// Create fake blockchain somewhat resembling tbc calls

	// Insert genesis
	cp := &chaincfg.TestNet3Params
	gbh, err := header2Bytes(&cp.GenesisBlock.Header)
	if err != nil {
		t.Fatal(err)
	}

	// Insert genesis
	tgbh := tbcd.BlockHeader{
		Height: 0,
		Hash:   cp.GenesisHash[:],
		Header: gbh,
	}
	err = ldb.BlockHeadersInsert(ctx, []tbcd.BlockHeader{tgbh})
	if err != nil {
		t.Fatalf("block headers insert: %v", err)
	}

	missing, err := ldb.BlocksMissing(ctx, 16)
	if err != nil {
		t.Fatalf("block headers missing: %v", err)
	}

	if len(missing) != 0 {
		t.Fatal("genesis should not be returned")
	}

	// Insert fake block headers
	count := uint64(64)
	bhs := make([]tbcd.BlockHeader, 0, count+1)
	bhs = append(bhs, tgbh) // need genesis for prevhash
	for i := uint64(1); i < count; i++ {
		bits := uint32(i + 4567)
		nonce := uint32(i + 1337)
		prevHash, err := chainhash.NewHash(bhs[i-1].Hash[:])
		if err != nil {
			t.Fatalf("prevhash %v", err)
		}
		merkleHash := chainhash.DoubleHashH(prevHash[:])
		wbh := wire.NewBlockHeader(1, prevHash, &merkleHash, bits, nonce)
		blockHash := wbh.BlockHash()
		t.Logf("height %v prev %v", i, prevHash)
		bhs = append(bhs, tbcd.BlockHeader{
			Height: i,
			Hash:   database.ByteArray(blockHash[:]),
			Header: h2b(wbh),
		})
	}
	t.Logf("%v", spew.Sdump(bhs))
	// Insert missing blocks
	err = ldb.BlockHeadersInsert(ctx, bhs[1:]) // skip genesis insert
	if err != nil {
		t.Fatalf("block headers insert: %v", err)
	}

	expectedMissingBH := 16
	missing, err = ldb.BlocksMissing(ctx, expectedMissingBH)
	if err != nil {
		t.Fatalf("block headers missing: %v", err)
	}
	t.Logf("%v", spew.Sdump(missing))

	if len(missing) != min(expectedMissingBH, int(count-1)) {
		t.Fatalf("%v %v %v", len(missing), expectedMissingBH, count)
	}

	// Start at height 1
	height := uint64(1)
	for k := range missing {
		if height != bhs[height].Height {
			t.Fatalf("unexpected internal height wanted %v got %v",
				height, bhs[height].Height)
		}
		if bhs[height].Height != missing[k].Height {
			t.Fatalf("unexpected missing height wanted %v got %v",
				bhs[height].Height, missing[k].Height)
		}
		if !bytes.Equal(bhs[height].Hash, missing[k].Hash) {
			t.Fatalf("unexpected missing hash wanted %v got %v",
				bhs[height].Hash, missing[k].Hash)
		}

		height++
	}

	// Insert missing blocks
	for i := uint64(1); i < count; i++ {
		b := tbcd.Block{
			Hash:  bhs[i].Hash,
			Block: []byte{'i', 'a', 'm', 'b', 'l', 'o', 'c', 'k'},
		}
		insertedHeight, err := ldb.BlockInsert(ctx, &b)
		if err != nil {
			t.Fatal(err)
		}
		log.Infof("inserted height: %v", insertedHeight)
	}

	// Ensure blocks missing table is updated
	missing, err = ldb.BlocksMissing(ctx, expectedMissingBH)
	if err != nil {
		t.Fatalf("block headers missing: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("expected missing table to be empty: %v", spew.Sdump(missing))
	}
	if len(ldb.blocksMissingCache) != 0 {
		t.Fatalf("expected missing blocks cache to be empty: %v",
			spew.Sdump(ldb.blocksMissingCache))
	}
}
