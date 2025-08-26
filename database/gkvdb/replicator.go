package gkvdb

import (
	"container/list"
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

// designates how to replay a journal entry
type opT uint8

const (
	opPut opT = iota
	opDel
)

type journalOp struct {
	op    opT
	table string // XXX maybe make a const pointer?
	key   []byte
	value []byte
}

type journal struct {
	ctx  context.Context       // external wait
	done func(context.Context) // external completion

	ops *list.List
}

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
	sinkC  chan *journal
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
		sinkC:  make(chan *journal, 1024),
	}

	return bdb, nil
}

func (b *replicatorDB) sinkHandler(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case j := <-b.sinkC:
			_ = j
			// XXX actually commit journal
			j.done(ctx)
		}
	}
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
			err = SinkUnavailableError(fmt.Sprintf("sink unavailable: %v",
				err))
		case Direct:
			// If an error occurs, abort and close source.
			cerr := b.source.Close(ctx)
			if cerr != nil {
				return fmt.Errorf("source: %w, sink open: %w", cerr, err)
			}
			return fmt.Errorf("sink open: %w", err)
		}
	}

	go b.sinkHandler(ctx)

	return err
}

func (b *replicatorDB) Close(ctx context.Context) error {
	errSource := b.source.Close(ctx)
	errSink := b.sink.Close(ctx)
	if errSource != nil || errSink != nil {
		return fmt.Errorf("source: %w sink: %w", errSource, errSink)
	}
	return nil
}

func copySlice(value []byte) []byte {
	if value != nil {
		return append([]byte{}, value...)
	}
	return nil
}

func journalKey(op opT, key []byte) []byte {
	// XXX think more about this, make it so we can stream this to disk
	// XXX Do the whole journal+table+key in this function
	return append([]byte{'j', 'o', 'u', 'r', uint8(op)}, key...)
}

func newJournal(pctx context.Context, sync bool) *journal {
	ctx, cancel := context.WithCancel(pctx) // XXX make sure cancel is called
	done := func(context.Context) {}
	if sync {
		done = func(_ context.Context) { cancel() }
	}
	return &journal{
		ctx:  ctx, // For caller to wait on
		done: done,
		ops:  list.New(),
	}
}

func singleJournal(ctx context.Context, sync bool, op opT, table string, key, value []byte) *journal {
	j := newJournal(ctx, sync)
	j.ops.PushBack(&journalOp{
		op:    op,
		table: table,
		key:   journalKey(op, key),
		value: copySlice(value),
	})
	return j
}

func (b *replicatorDB) journal(pctx context.Context, j *journal) error {
	select {
	case <-j.ctx.Done():
		return j.ctx.Err() // Catches pctx and j cancel
	case b.sinkC <- j:
	}

	// If this is a slow sink performance is going to suck.
	// XXX this should be in the journal
	switch b.cfg.Policy {
	case Direct:
		select {
		case <-j.ctx.Done():
			// Catches pctx and j cancel
			return nil
		}
	case Lazy:
		j.done(pctx) // Don't leak contexts
	}
	return nil
}

func (b *replicatorDB) Del(pctx context.Context, table string, key []byte) error {
	err := b.source.Update(pctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Del(ctx, table, key); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Send to journal
	j := singleJournal(pctx, b.cfg.Policy == Direct, opDel, table, key, nil)
	return b.journal(pctx, j)
}

func (b *replicatorDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	return b.source.Has(ctx, table, key)
}

func (b *replicatorDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	return b.source.Get(ctx, table, key)
}

func (b *replicatorDB) Put(pctx context.Context, table string, key, value []byte) error {
	err := b.source.Update(pctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Put(ctx, table, key, value); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	// Send to journal
	j := singleJournal(pctx, b.cfg.Policy == Direct, opPut, table, key, value)
	return b.journal(pctx, j)
}

func (b *replicatorDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	// If this is a read only transaction just open a source transaction
	// and punish caller if put/del is called.
	source, err := b.source.Begin(ctx, write)
	if err != nil {
		return nil, err
	}
	return &replicatorTX{
		db:     b,
		source: source,
		write:  write,
		ops:    list.New(),
	}, nil
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
	sourceBatch, err := b.source.NewBatch(ctx)
	if err != nil {
		return nil, err
	}
	return &replicatorBatch{
		sourceBatch: sourceBatch,
		ops:         list.New(),
	}, nil
}

// Transactions

// replicator transactions convert front end ops to a sink batch.

type replicatorTX struct {
	db     *replicatorDB
	source Transaction
	sink   Transaction
	write  bool
	ops    *list.List
}

func (tx *replicatorTX) Del(ctx context.Context, table string, key []byte) error {
	if !tx.write {
		return fmt.Errorf("read only transaction")
	}
	if err := tx.source.Del(ctx, table, key); err != nil {
		return err
	}
	tx.ops.PushBack(&journalOp{
		op:    opDel,
		table: table,
		key:   journalKey(opDel, key),
		value: nil,
	})
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
	tx.ops.PushBack(&journalOp{
		op:    opPut,
		table: table,
		key:   journalKey(opPut, key),
		value: copySlice(value),
	})
	return nil
}

func (tx *replicatorTX) Commit(ctx context.Context) error {
	err := tx.source.Commit(ctx)
	if err != nil {
		return err
	}
	// replay batch
	j := newJournal(ctx, tx.db.cfg.Policy == Direct)
	j.ops = tx.ops
	return tx.db.journal(ctx, j)
}

func (tx *replicatorTX) Rollback(ctx context.Context) error {
	tx.ops.Init() // Clear tx ops list
	err := tx.source.Rollback(ctx)
	if err != nil {
		return err
	}
	return nil
}

func (tx *replicatorTX) Write(ctx context.Context, b Batch) error {
	err := tx.source.Write(ctx, b.(*replicatorBatch).sourceBatch)
	if err != nil {
		return err
	}

	// replay batch
	j := newJournal(ctx, tx.db.cfg.Policy == Direct)
	j.ops = b.(*replicatorBatch).ops

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
type replicatorBatch struct {
	sourceBatch Batch
	ops         *list.List
}

func (rb *replicatorBatch) Del(ctx context.Context, table string, key []byte) {
	rb.sourceBatch.Del(ctx, table, key)
	rb.ops.PushBack(&journalOp{
		op:    opDel,
		table: table,
		key:   journalKey(opDel, key),
		value: nil,
	})
}

func (rb *replicatorBatch) Put(ctx context.Context, table string, key, value []byte) {
	rb.sourceBatch.Put(ctx, table, key, value)
	rb.ops.PushBack(&journalOp{
		op:    opPut,
		table: table,
		key:   journalKey(opDel, key),
		value: copySlice(value),
	})
}

func (rb *replicatorBatch) Reset(ctx context.Context) {
	rb.sourceBatch.Reset(ctx)
	rb.ops.Init()
}
