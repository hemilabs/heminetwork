package gkvdb

import (
	"context"
	"errors"
	"io"
)

// DumpTables and Restore are used to create portable backups. Any
// Encoder/Decoder can be used provided thet conform to the interface.  The
// caller is responsible for quiescing the tables. The backup itself will be
// made using a consistent view.
//
// Typical use:
//	var b bytes.Buffer
//	zw, _ := zstd.NewWriter(&b)
//	je := json.NewEncoder(zw)
//	_ = db.DumpTables(ctx, tables, je)
//	_ = zw.Close()
//
//	zr, _ := zstd.NewReader(&b)
//	jd := json.NewDecoder(zr)
//	_ = db.Restore(ctx, jd)

// OperationT is used to tag what database operation is being described. These
// operations are used to perform database dump/restores.
type OperationT uint8

const (
	OpPut OperationT = 1 // Database put
	OpDel            = 2 // Database delete
)

// Operation describes a single database operation. An entire database can be
// replicated by creating a delta between a source database table and a
// destination database table.
type Operation struct {
	Op    OperationT `json:"op"`
	Table string     `json:"table"`
	Key   []byte     `json:"key"`
	Value []byte     `json:"value,omitempty" binary:"omitempty"`
}

// Replay describes a replay of operations into a database.
type Replay struct {
	Operations []Operation `json:"operations"`
}

type Encoder interface {
	Encode(v any) error
}

type Decoder interface {
	Decode(v any) error
}

var DefaultMaxRestoreChunk = 256 * 1024 * 1024 // Maximum transaction size during restore.

func DumpTables(ctx context.Context, db Database, tables []string, target Encoder) error {
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

func Restore(ctx context.Context, db Database, source Decoder) error {
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
			if totalWritten > DefaultMaxRestoreChunk {
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
