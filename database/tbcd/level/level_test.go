package level

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"testing"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/hemilabs/heminetwork/database"
	"github.com/hemilabs/heminetwork/database/tbcd"
	"github.com/juju/loggo"
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

	loggo.ConfigureLoggers("TRACE")

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

func TestBitcoinBits(t *testing.T) {
	// Decode block
	block381 := `01000000c5b9489065fa7e1ac4facc51a5a0ccc2111911609f43386ebe7ca1d200000000a0db3bbb22a2a8441d84dbe335c24959ea3d3d6e91bf67e66bbcb0d7e0a9c4836a834a4dffff001d041813660201000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0e046a834a4d017e062f503253482fffffffff0100f2052a01000000232103dac3fb8de40965f42fb4afb3baa07d3304bc2aa28cfc25f12b52f1523681451dac00000000010000001518b50db063333a3261b9b41e887b4aa5b69becdc9967550507c120e22a764967000000004a493046022100e49de3c89180769db346145cdda48323ddecc2af0041293432528767b18407650221009f7878deb054e4f9c0e6aecbe6de15f5d829041c11f7952d33e96c76ada1258b01ffffffff322948a4806acfeca2b32248d0e183c8eb09d5e5ef48adf33777307635414cc0000000004a493046022100ba88d34e4d4fd85ab5e4d77cb74f71c87a24235bcbe39cf4334633f70ff27233022100b5aa1b96bab59457d3d837473de1e4f9f89ba3ee39964463952271c5b4140fa001ffffffffcf330295467623ec1378dc6fa312103ad8a210b3e1351f2f4b6a57ac43fcd472000000004a493046022100b21560dfda52352c4416c1e48496659ea3d29e4e25706a991986864210bc759e0221009c1e45af6e2eba0883a862442d85a2b48c3395e35a4276f535cd70d45a971c7401ffffffffeeed0f4d975db8f66788f809ecf8c351d19ff5805276ef31983bc5682548342d0000000049483045022100e02cc0b4bf8a126807b1577819944c1bb13e8f4028cf7df0a0729013d511b071022010a1bcdefca334588939f9fe40e0d8607588191684fce0f46180a139305b8b4001ffffffffc8ac0a2fb1c01e0e0a5339d296eb072b2b9f9cb1d410a1fdd69a2c797094dda50000000049483045022016ba8f50d7f30be7e4a68c3d50368d577e2ef6c8b60842725ae636b2985776fc022100bb39d47d1955ffca47920d743bcd6f05b31ea2bf3dc7ede225eb4c901126b48901fffffffff1b03cf0680b9ef33fd311f6bbc6db3f1c164f9341f48a02df1905cec4ce241b000000004948304502201dbbfabc47f6da84ceedbc92b792d4a8ef632f0bddf7ebfad5ca21f3731f450502210098751ccf37fd97ff82446486d4c1d62860c2080a1128ea5ddb0d30bfde3cd7a801ffffffff1fe6898ac074a680fe7458ff87a03956db73a880d2ace6539efcc43002bd97ed000000004a493046022100f8a83fadb06af9c0cc730f17ae47fe7a09cada9eae623b8dd86bf365ef0e20480221009a10b073b2a8b313d975f801213efdf12b94141d7b6a8e98de3b0c67ee1cef4c01ffffffff6fd85c0213cfe9863573596a4d5f1509ac41a91b572e6c1bdafe46d9249a5fa4000000004a493046022100f3e98f3e76cc0f533b0e1cccd82650b704e31e3e7e62bf81bb474cf2add58ebf022100f77003eec814a3336cc305b8461cf3ccb19b1f18f06f66208ed31c3e468466ed01ffffffff9e93a056a6515e7916fc049578708d188c2146d3c12638acac92e0b72e076edd000000004a4930460221008ee8d7348aed82a8d074753ab4c8dbdd28a668da821269c4cd0c5c253738cab7022100b06a0208d60af1be6303dd883fd05f964a42f7de317761641ec1158944f52b6b01ffffffff0ecc7b73d8cd5d377d74d836bb6e3473478554a923154286ddaf6985948fd9d300000000494830450221008159ed783bc717ff5a6502cd87a8d8144fae74c6fc6943a5a38da7170203cb3802207e31577a576bc01510cb2280f918a371f63eee44cd2b4490c0994d261787916e01ffffffff78966e9f0a2d4452ab2418249fa6fb1a325a04f039d015899141a82aa5a6c05c000000004847304402206655b13198e413ac8f1aa8926d4617560758cf8b5045afdfc9116da0873ed89802205db55cf3f398467bfc6997f68c881e5f2a7225293ebbd2af40d15df6de4ef87701ffffffff69f2096bbede7015fee2fb307f7d7dd084641b7f4af5c3074dc7b2b6df03277c000000004a493046022100c9199296673a1beae598a6d2348ef13ad1b9f15eebaa825d2282adf017cbb5f0022100b54934e40ff0194a53dcaa9d017c36a93dbb53aa45fe21ab93b07fbb58570d5501ffffffff3c11b146d43fd62ec36b733942a52ba0c352c95a3f078808a38d080898cb83300000000048473044022004c64773b9e6a17cfca7ff583be650104c0538940289b2da8f8bebbd32e486b302200174d8f0938a0f9eeab4c4b137581e032f06d4740e3b0ad9d0423a0a8de65af101ffffffff59ac3c37adfa89b9a907ef9d485c57262e9283e1eb96069c2de04369ef1b3c7600000000494830450220306f3ac72de9dbeb1ec139e4e89cc3b3b9bcb63747bf0e165fcfc773f3669832022100c00a16800f16bf1c71ac6c2989b42d974b0ec2f3e3671325fb2cae52a1c569d801ffffffffb4bbecee818dd986e5ab82f36dbd5ccc29ab134614e304c0a397e14082fe7bb7000000004a493046022100ed68e0303052b41ffd80c1e905cee5547e92422d43b73e473a615e4a47146bb5022100ecab3f92c62477350753b4efea19d608fcce15b1b2c38fbe905e9d1f9ad7631f01ffffffff7546bbac9ae1c8980da6e8c154b368eb4df305b6f3f27ff38f195a13c9ee0484000000004948304502202288566af2b68b6982d1244e293ea3d7c156a425329b7f61b272e4deec317bea022100d9739976b442d35c32830cb2c105e0d7275f7efaa99eaeea4b24a553267a31fc01ffffffffd15854d1e5ba349daf72089f470b24557a2be25105b7831a3f18a62fb8bab677000000004948304502206e3a23075e0248ea8cabc7c875b4cfd9f036c1c4f358a00ec152fc96d1cb6cf8022100d34c018815f63c65f5364061369382b31d579cd6d8a4afe9ec1f03ba66d7717801ffffffffdf686a7f31c2c1de6a608553b26d6336434719fa45428eb3df59bbef75ce9e7e000000004948304502200a22a24a8f817a2f24d3f8c2670f3cb25cd389ce25e0d45eeb0aea08563c5c9802210081ff14edb230a44e5b52e35f573676096a937fc27cc830b153b229b92cac75c101ffffffffd226fea91b99c5a31a034d340f647b722e50950c96a876eb96569efaeaf3b227000000004a4930460221009684e60a7fd61362d0dad79858044aa4a7b878b3f0bd432e384fe4c7e6c90bde0221009883e4f739cffe574bac5bed0a4e69708433973a2490d9415d303614fc31be4701fffffffff640c60ea438dc020048599869836f5323ef47477ee17caddf076ed428898f7100000000494830450220028eb7617dc161a282512c81975d41a1594c05f34cb26fb759682bf784da7071022100a0913abea7229b3c465a4fa32dc861f72ef684e8dd3f19aac5f0f74ea39c03cf01ffffffffd59d2a49b1883c6f7ac68a9d2649dc0dde3f0205e19d8fdaf8065381f9ba61cc000000004a4930460221009f5b27dfd397423a04cab52ee6e8215e290e9666309f0f59f5bc5f6c207d3639022100f5a79133db2cc786140aeee0bf7c8a81adca6071928e8210f1c9f0c653e2f04201ffffffff0240195e29010000001976a914944a7d4b3a8d3a5ecf19dfdfd8dcc18c6f1487dd88acc0c01e49170000001976a91432040178c5cf81cb200ab99af1131f187745b51588ac00000000`

	bb, err := hex.DecodeString(block381)
	if err != nil {
		t.Fatal(err)
	}
	// decode
	b, err := btcutil.NewBlockFromBytes(bb)
	if err != nil {
		t.Fatal(err)
	}
	log.Infof("%v", spew.Sdump(b))
}
