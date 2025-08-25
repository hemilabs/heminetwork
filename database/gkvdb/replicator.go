package gkvdb

import (
	"context"
	"errors"
	"fmt"
)

// Assert required interfaces
var (
	_ Batch       = (*replicatorBatch)(nil)
	_ Database    = (*replicatorDB)(nil)
	_ Iterator    = (*replicatorIterator)(nil)
	_ Range       = (*replicatorRange)(nil)
	_ Transaction = (*replicatorTX)(nil)

	ErrSinkUnavailable = errors.New("sink unavailable")
)

type Policy int

const (
	Lazy Policy = iota
	Direct
)

type ReplicatorConfig struct {
	Policy Policy
}

type replicatorDB struct {
	cfg *ReplicatorConfig

	source Database
	sink   Database
}

func DefaultReplicatorConfig(policy Policy) *ReplicatorConfig {
	return &ReplicatorConfig{Policy: policy}
}

func NewReplicatorDB(cfg *ReplicatorConfig, source, sink Database) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &replicatorDB{
		cfg:    cfg,
		source: source,
		sink:   sink,
	}

	return bdb, nil
}

func (b *replicatorDB) Open(ctx context.Context) error {
	err := b.source.Open(ctx)
	if err != nil {
		return err
	}
	err = b.sink.Open(ctx)
	if err != nil {
		switch b.cfg.Policy {
		case Lazy:
			// If an error occurs, we can proceed, we'll keep a
			// journal. Do let the caller know the sink is
			// unavailable.
			return SinkUnavailableError(fmt.Sprintf("sink unavailable: %v",
				err))
		case Direct:
			// If an error occurs, abort and close source.
			_ = b.source.Close(ctx) // XXX should we log this error?
			return fmt.Errorf("sink open: %w", err)
		}
	}
	return nil
}

func (b *replicatorDB) Close(ctx context.Context) error {
	errSource := b.source.Close(ctx)
	errSink := b.sink.Close(ctx)
	if errSource != nil || errSink != nil {
		return fmt.Errorf("source: %w sink: %w", errSource, errSink)
	}
	return nil
}

func (b *replicatorDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	// If this is a read only transaction just open a source transaction
	// and punish caller if put/del is called.
	source, err := b.source.Begin(ctx, write)
	if err != nil {
		return nil, err
	}
	r := &replicatorTX{
		db:     b,
		source: source,
		write:  write,
	}
	if write {
		// XXX rewrite this
		sink, err := b.sink.Begin(ctx, true)
		if err != nil {
			// overwrite error
			switch b.cfg.Policy {
			case Lazy:
				err = SinkUnavailableError(fmt.Sprintf("sink unavailable: %v",
					err))
			case Direct:
				rberr := source.Rollback(ctx)
				if rberr != nil {
					return nil, fmt.Errorf("source: %w, sink: %w",
						rberr, err)
				}
				return nil, err
			}
		}
		if sink != nil {
			// XXX we are killing previous SinkUnavailableError here
			sinkBatch, err := b.sink.NewBatch(ctx)
			if err != nil {
				// overwrite error
				switch b.cfg.Policy {
				case Lazy:
					err = SinkUnavailableError(fmt.Sprintf("sink unavailable: %v",
						err))
				case Direct:
					rberr := source.Rollback(ctx)
					if rberr != nil {
						return nil, fmt.Errorf("source: %w, sink: %w",
							rberr, err)
					}
					return nil, err
				}
			}
			r.sinkBatch = sinkBatch
		}
		r.sink = sink
		return nil, err
	}
	return r, nil
}

func (b *replicatorDB) Del(ctx context.Context, table string, key []byte) error {
	var err error

	switch b.cfg.Policy {
	case Direct:
		// It get's hairy now. We are going to forward the delete to
		// the sink INSIDE the source transaction. If this is a slow
		// sink performance is going to suck.
		err = b.source.Update(ctx, func(ctx context.Context, tx Transaction) error {
			if err := tx.Del(ctx, table, key); err != nil {
				return err
			}

			if err := b.sink.Del(ctx, table, key); err != nil {
				return fmt.Errorf("sink delete: %w", err)
			}
			return nil
		})

	case Lazy:
		// Store del op in journal.
		err = fmt.Errorf("not yet")
	}

	return err
}

func (b *replicatorDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return b.source.Has(ctx, table, key)
}

func (b *replicatorDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return b.source.Get(ctx, table, key)
}

func (b *replicatorDB) Put(ctx context.Context, table string, key, value []byte) error {
	var err error

	switch b.cfg.Policy {
	case Direct:
		// It get's hairy now. We are going to forward the put to
		// the sink INSIDE the source transaction. If this is a slow
		// sink performance is going to suck.
		err = b.source.Update(ctx, func(ctx context.Context, tx Transaction) error {
			if err := tx.Put(ctx, table, key, value); err != nil {
				return err
			}

			if err := b.sink.Put(ctx, table, key, value); err != nil {
				return fmt.Errorf("sink put: %w", err)
			}
			return nil
		})

	case Lazy:
		// Store put op in journal.
		err = fmt.Errorf("not yet")
	}

	return err
}

func (b *replicatorDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
	tx, err := b.Begin(ctx, write)
	if err != nil {
		return err
	}
	err = callback(ctx, tx)
	if err != nil {
		if cerr := tx.Rollback(ctx); cerr != nil {
			return fmt.Errorf("rollback %w: %w", cerr, err)
		}
		return err
	}
	return tx.Commit(ctx)
}

func (b *replicatorDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, false, callback)
}

func (b *replicatorDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, true, callback)
}

func (b *replicatorDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	it, err := b.source.NewIterator(ctx, table)
	if err != nil {
		return nil, err
	}
	return &replicatorIterator{
		table: table,
		it:    it,
	}, nil
}

func (b *replicatorDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	it, err := b.source.NewRange(ctx, table, start, end)
	if err != nil {
		return nil, err
	}
	return &replicatorRange{
			it: it,
		},
		nil
}

func (b *replicatorDB) NewBatch(ctx context.Context) (Batch, error) {
	source, err := b.source.NewBatch(ctx)
	if err != nil {
		return nil, err
	}
	sink, err := b.sink.NewBatch(ctx)
	if err != nil {
		return nil, fmt.Errorf("sink batch: %w", err)
	}
	return &replicatorBatch{
		source: source,
		sink:   sink,
	}, nil
}

// Transactions

// replicator transactions convert front end ops to a sink batch.

type replicatorTX struct {
	db        *replicatorDB
	source    Transaction
	sink      Transaction
	sinkBatch Batch
	write     bool
}

func (tx *replicatorTX) Del(ctx context.Context, table string, key []byte) error {
	if !tx.write {
		return fmt.Errorf("read only transaction")
	}
	if err := tx.source.Del(ctx, table, key); err != nil {
		return err
	}
	if tx.sinkBatch != nil {
		tx.sinkBatch.Del(ctx, table, key)
	}
	return nil
}

func (tx *replicatorTX) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return tx.source.Has(ctx, table, key)
}

func (tx *replicatorTX) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return tx.source.Get(ctx, table, key)
}

func (tx *replicatorTX) Put(ctx context.Context, table string, key []byte, value []byte) error {
	if !tx.write {
		return fmt.Errorf("read only transaction")
	}
	if err := tx.source.Put(ctx, table, key, value); err != nil {
		return err
	}
	if tx.sinkBatch != nil {
		tx.sinkBatch.Put(ctx, table, key, value)
	}
	return nil
}

func (tx *replicatorTX) Commit(ctx context.Context) error {
	err := tx.source.Commit(ctx)
	if err != nil {
		if tx.sinkBatch != nil {
			tx.sinkBatch.Reset(ctx)
		}
		if tx.sink != nil {
			sinkErr := tx.sink.Rollback(ctx)
			if sinkErr != nil {
				return fmt.Errorf("%w, sink rollback: %w", err, sinkErr)
			}
		}
		return err
	}
	// replay batch
	if tx.sinkBatch != nil {
		if tx.sink == nil {
			return SinkUnavailableError(fmt.Sprintf("sink unavailable: %v",
				"commit"))
		}
		// XXX this is shitty, create a replay journal if sink fails
		err = tx.sink.Write(ctx, tx.sinkBatch)
		if err != nil {
			err = fmt.Errorf("sink write: %w", err)
			switch tx.db.cfg.Policy {
			case Direct:
				return err
			case Lazy:
			}
		}
		return err
	}
	return nil
}

func (tx *replicatorTX) Rollback(ctx context.Context) error {
	if tx.sinkBatch != nil {
		tx.sinkBatch.Reset(ctx)
	}
	var sinkError error
	if tx.sink != nil {
		sinkError = tx.sink.Rollback(ctx)
	}
	err := tx.source.Rollback(ctx)
	if err != nil {
		if sinkError != nil {
			return fmt.Errorf("%w, sink: %w", err, sinkError)
		}
		return err
	}
	return nil
}

func (tx *replicatorTX) Write(ctx context.Context, b Batch) error {
	err := tx.source.Write(ctx, b)
	if err != nil {
		return err
	}
	if tx.sink != nil {
		if err := tx.sink.Write(ctx, b); err != nil {
			return fmt.Errorf("sink write: %w", err)
		}
	}
	return nil
}

// Iterations
type replicatorIterator struct {
	table string
	it    Iterator
}

func (ni *replicatorIterator) First(ctx context.Context) bool {
	return ni.it.First(ctx)
}

func (ni *replicatorIterator) Last(ctx context.Context) bool {
	return ni.it.Last(ctx)
}

func (ni *replicatorIterator) Next(ctx context.Context) bool {
	return ni.it.Next(ctx)
}

func (ni *replicatorIterator) Seek(ctx context.Context, key []byte) bool {
	return ni.it.Seek(ctx, key)
}

func (ni *replicatorIterator) Key(ctx context.Context) []byte {
	return ni.it.Key(ctx)
}

func (ni *replicatorIterator) Value(ctx context.Context) []byte {
	return ni.it.Value(ctx)
}

func (ni *replicatorIterator) Close(ctx context.Context) {
	ni.it.Close(ctx)
}

// Ranges
type replicatorRange struct {
	it Range
}

func (nr *replicatorRange) First(ctx context.Context) bool {
	return nr.it.First(ctx)
}

func (nr *replicatorRange) Last(ctx context.Context) bool {
	return nr.it.Last(ctx)
}

func (nr *replicatorRange) Next(ctx context.Context) bool {
	return nr.it.Next(ctx)
}

func (nr *replicatorRange) Key(ctx context.Context) []byte {
	return nr.it.Key(ctx)
}

func (nr *replicatorRange) Value(ctx context.Context) []byte {
	return nr.it.Value(ctx)
}

func (nr *replicatorRange) Close(ctx context.Context) {
	nr.it.Close(ctx)
}

// Batches
// type op int
//
// const (
//
//	opPut = iota
//	opDel
//
// )
//
//	type journal struct {
//		op    op
//		table string
//		key   []byte
//		value []byte
//	}
type replicatorBatch struct {
	source Batch
	sink   Batch
}

func (rb *replicatorBatch) Del(ctx context.Context, table string, key []byte) {
	rb.source.Del(ctx, table, key)
	rb.sink.Del(ctx, table, key)
}

func (rb *replicatorBatch) Put(ctx context.Context, table string, key, value []byte) {
	rb.source.Put(ctx, table, key, value)
	rb.sink.Put(ctx, table, key, value)
}

func (rb *replicatorBatch) Reset(ctx context.Context) {
	rb.source.Reset(ctx)
	rb.sink.Reset(ctx)
}
