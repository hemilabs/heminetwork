package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"path/filepath"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"

	"github.com/hemilabs/heminetwork/cmd/btctool/blockstream"
	"github.com/hemilabs/heminetwork/database/tbcd/level"
)

// crossReference downloads block headers base on best tip and walks the chain
// back while cross referencing it with esplora.
func crossReference(ctx context.Context) error {
	levelDBHome := "~/.tbcd" // XXX
	network := "testnet3"
	db, err := level.New(ctx, filepath.Join(levelDBHome, network))
	if err != nil {
		return err
	}
	defer db.Close()
	pool := db.DB()
	_ = pool

	// get best tip
	bhbs, err := db.BlockHeadersBest(ctx)
	if err != nil {
		return fmt.Errorf("block headers best: %w", err)
	}
	if len(bhbs) != 1 {
		return fmt.Errorf("block headers best: only one tip exptected")
	}
	bh := bhbs[0]
	ch, err := chainhash.NewHash(bh.Hash)
	if err != nil {
		return fmt.Errorf("new hash: %w", err)
	}
	log.Infof("starting at: %v %v", bh.Height, ch)

	for {
		bh, err := db.BlockHeaderByHash(ctx, ch[:])
		if err != nil {
			return fmt.Errorf("block header %v: %w", ch, err)
		}
		log.Infof("height %v hash %v", bh.Height, ch)

		// Get block header from esplora
		var bhs string
		bhs, err = blockstream.BlockHeader(ctx, ch.String())
		if err != nil {
			return fmt.Errorf("block header esplora %v %v: %w", bh.Height, ch, err)
		}
		if hex.EncodeToString(bh.Header) != bhs {
			return fmt.Errorf("block header not equal %v %v: expected %v got %v",
				bh.Height, ch, hex.EncodeToString(bh.Header), bhs)
		}

		// Get block
		b, err := db.BlockByHash(ctx, bh.Hash)
		if err != nil {
			return fmt.Errorf("block by hash %v %v: %w", bh.Height, ch, err)
		}
		_ = b
		// XXX skip comparing for now
		//bx := make([]byte, len(b.Block))
		//copy(bx, b.Block[:])
		//be, err := blockstream.BlockBytes(ctx, ch.String())
		//if err != nil {
		//	log.Infof("vlodod block %v", err)
		//	return fmt.Errorf("block esplora %v %v: %w", bh.Height, ch, err)
		//}
		//if !bytes.Equal(bx, be) {
		//	return fmt.Errorf("block not equal %v %v: expected %v got %v",
		//		bh.Height, ch, spew.Sdump(bx), spew.Sdump(be))
		//}

		// log.Infof("VLODOD %v", err)
		// Get previous block hash
		var wbh wire.BlockHeader
		err = wbh.Deserialize(bytes.NewReader(bh.Header))
		if err != nil {
			return fmt.Errorf("deserialize %v %v: %v", bh.Height, ch, err)
		}
		ch = &wbh.PrevBlock
	}

	//log.Infof("bh.Prev: %v", spew.Sdump(wbh))
	//mdDB := pool[ldb.MetadataDB]
	//it := mdDB.NewIterator(nil, nil)
	//defer it.Release()
	//for it.Next() {
	//	fmt.Printf("metadata key %vvalue %v", spew.Sdump(it.Key()), spew.Sdump(it.Value()))
	//}

	// log.Infof("going out")
	// return nil
}
