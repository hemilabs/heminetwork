package gkvdb

import (
	"context"
	"errors"
	"io"
)

var defaultMaxRestoreChunk = 256 * 1024 * 1024

func dumpTables(ctx context.Context, db Database, tables []string, target Encoder) error {
	for _, table := range tables {
		it, err := db.NewIterator(ctx, table)
		if err != nil {
			return err
		}
		for it.Next(ctx) {
			op := Operation{
				Op:    OpPut,
				Table: table,
				Key:   it.Key(ctx),
				Value: it.Value(ctx),
			}
			err := target.Encode(op)
			if err != nil {
				it.Close(ctx)
				return err
			}
		}
		it.Close(ctx)
	}

	return nil
}

func restore(ctx context.Context, db Database, source Decoder) error {
	batch, err := db.NewBatch(ctx)
	if err != nil {
		return err
	}

	var done bool
	for !done {
		totalWritten := 0
		for {
			var op Operation
			err := source.Decode(&op)
			if err != nil {
				if errors.Is(err, io.EOF) {
					done = true
					break
				}
				return err
			}
			switch op.Op {
			case OpPut:
				batch.Put(ctx, op.Table, op.Key, op.Value)
			case OpDel:
				batch.Del(ctx, op.Table, op.Key)
			}

			// Break out of loop to commit chunk.
			totalWritten += len(op.Key) + len(op.Value)
			if totalWritten > defaultMaxRestoreChunk {
				break
			}
		}

		err = db.Update(ctx, func(ctx context.Context, tx Transaction) error {
			return tx.Write(ctx, batch)
		})
		if err != nil {
			return err
		}
		batch.Reset(ctx)
	}

	return nil
}
