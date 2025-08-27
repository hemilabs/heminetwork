package gkvdb

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	kbin "github.com/kelindar/binary"
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

// journalOp is an internal journal operation. It represents and individual
// operation that can be replayed into a database.
//
// XXX we currently copy key/val. that may be too expensive and may need caller
// control. In a worst case scenario we end up copying the key 3 times.
// 1. On the initial call where it lives in the list
// 2. On creation of the journal key, which must happen late
// 3. Possibly when sent into the sink
type journalOp struct {
	Op    opT
	Table string // XXX maybe make a const pointer?
	Key   []byte
	Value []byte `binary:"omitempty"`
}

func encodeJournalKey(id uint64) (k [8]byte) {
	binary.BigEndian.PutUint64(k[0:], id)
	return
}

func decodeJournalKey(k [8]byte) (id uint64) {
	id = binary.BigEndian.Uint64(k[0:])
	return
}

type journal struct {
	ctx  context.Context       // external wait
	done func(context.Context) // external completion

	ops *list.List
}

// lastSequenceID keeps the data on both ends synced. If it doesn't exist the
// database really needs to be completly copied to the sink.
var lastSequenceID = []byte("lastsequenceid")

// newJournalID atomically generates a new journal ID.
func newJournalID(ctx context.Context, db Database) (uint64, error) {
	// XXX @antonio add tests for this please; including rolled back tx' so
	// that we see gaps.
	var newID uint64
	return newID, db.Update(ctx, func(ctx context.Context, tx Transaction) error {
		x, err := tx.Get(ctx, "", lastSequenceID)
		if err != nil {
			// If key does not exist return 0 and store it the db.
			if errors.Is(err, ErrKeyNotFound) {
				var id [8]byte
				err := tx.Put(ctx, "", lastSequenceID, id[:])
				if err != nil {
					return err
				}
				newID = 0
				return nil
			}
			return err
		}

		// update new id
		newID = binary.BigEndian.Uint64(x)
		newID++
		var id [8]byte
		binary.BigEndian.PutUint64(id[:], newID)
		err = tx.Put(ctx, "", lastSequenceID, id[:])
		if err != nil {
			return err
		}
		return nil
	})
}

type Policy int

const (
	Lazy Policy = iota
	Direct
)

type ReplicatorConfig struct {
	Home   string // Journal home, maybe use an nvme on a separate mount point.
	Policy Policy
}

type replicatorDB struct {
	cfg *ReplicatorConfig

	source   Database // source
	sink     Database // sink
	jdb      Database // journal, for now only support leveldb
	sinkC    chan *journal
	journalC chan struct{}
}

func DefaultReplicatorConfig(home string, policy Policy) *ReplicatorConfig {
	return &ReplicatorConfig{
		Home:   home,
		Policy: policy,
	}
}

func NewReplicatorDB(cfg *ReplicatorConfig, source, sink Database) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	if cfg.Home == "" {
		return nil, fmt.Errorf("must provide journal home")
	}
	bdb := &replicatorDB{
		cfg:      cfg,
		source:   source,
		sink:     sink,
		sinkC:    make(chan *journal, 1024),
		journalC: make(chan struct{}, 1), // depth of one to always go around
	}

	// Setup journal.
	// XXX add version to journal database
	var err error
	bdb.jdb, err = NewLevelDB(DefaultLevelConfig(cfg.Home, []string{""}))
	if err != nil {
		return nil, err
	}
	return bdb, nil
}

func (b *replicatorDB) commitJournal(ctx context.Context, id uint64, j *journal) error {
	// Stream ops into value of of journal
	// XXX verify key does not exist!
	var value bytes.Buffer
	encoder := kbin.NewEncoder(&value)
	for j.ops.Len() > 0 {
		e := j.ops.Remove(j.ops.Front())
		err := encoder.Encode(e)
		if err != nil {
			return fmt.Errorf("encoder: %w", err)
		}
	}
	j.ops.Init()
	key := encodeJournalKey(id)
	return b.jdb.Put(ctx, "", key[:], value.Bytes())
}

func (b *replicatorDB) processJournal(ctx context.Context, id uint64) error {
	// Lift journal of disk and commit it into sink
	key := encodeJournalKey(id)
	value, err := b.jdb.Get(ctx, "", key[:])
	if err != nil {
		return err
	}

	jb, err := b.jdb.NewBatch(ctx)
	if err != nil {
		return err
	}
	defer func() { jb.Reset(ctx) }()

	decoder := kbin.NewDecoder(bytes.NewBuffer(value))
	for i := 0; ; i++ {
		jop := journalOp{}
		err := decoder.Decode(&jop)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return err
		}
		switch jop.Op {
		case opDel:
			jb.Del(ctx, jop.Table, jop.Key)
		case opPut:
			jb.Put(ctx, jop.Table, jop.Key, jop.Value)
		}
	}

	// Commit batch
	err = b.sink.Update(ctx, func(ctx context.Context, tx Transaction) error {
		return tx.Write(ctx, jb)
	})
	if err != nil {
		return err
	}
	// Delete journal
	return b.jdb.Del(ctx, "", key[:])
}

func (b *replicatorDB) journalHandler(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-b.journalC:
		}

		// Process as many journals as possible
		ir, err := b.jdb.NewRange(ctx, "", nil, nil)
		if err != nil {
			panic(err)
		}
		for ir.Next(ctx) {
			// Do things
			fmt.Printf("ir.Key %x\n", ir.Key(ctx))
		}
		ir.Close(ctx)
	}
}

func (b *replicatorDB) sinkHandler(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case j := <-b.sinkC:
			// Commit journal
			id, err := newJournalID(ctx, b.jdb)
			if err != nil {
				panic(err)
			}
			err = b.commitJournal(ctx, id, j)
			if err != nil {
				panic(err)
			}

			// Tell caller we are done if we are lazy.
			switch b.cfg.Policy {
			case Direct:
				err := b.processJournal(ctx, id)
				if err != nil {
					panic(err)
				}
			case Lazy:
				// Lazy Process journal
				select {
				case <-ctx.Done():
					return ctx.Err()
				case b.journalC <- struct{}{}:
				default:
				}
			}

			j.done(ctx) // Mark journal done

		}
	}
}

func (b *replicatorDB) Open(ctx context.Context) error {
	// XXX add proper unwind here

	// journal
	err := b.jdb.Open(ctx)
	if err != nil {
		return err
	}

	// source
	err = b.source.Open(ctx)
	if err != nil {
		return err
	}

	// sink
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
			// XXX this is shit, rewrite
			// If an error occurs, abort and close source.
			jerr := b.jdb.Close(ctx)
			if jerr != nil {
				panic(jerr)
			}
			cerr := b.source.Close(ctx)
			if cerr != nil {
				return fmt.Errorf("source: %w, sink open: %w", cerr, err)
			}
			return fmt.Errorf("sink open: %w", err)
		}
	}

	go b.sinkHandler(ctx)
	go b.journalHandler(ctx)

	return err
}

func (b *replicatorDB) Close(ctx context.Context) error {
	errSource := b.source.Close(ctx)
	errSink := b.sink.Close(ctx)
	errJournal := b.jdb.Close(ctx)
	if errSource != nil || errSink != nil || errJournal != nil {
		return fmt.Errorf("source: %w sink: %w journal: %w",
			errSource, errSink, errJournal)
	}
	return nil
}

func copySlice(value []byte) []byte {
	if value != nil {
		return append([]byte{}, value...)
	}
	return nil
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
		Op:    op,
		Table: table,
		Key:   copySlice(key),
		Value: copySlice(value),
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
	switch b.cfg.Policy {
	case Direct:
		select {
		case <-j.ctx.Done():
			// Catches pctx and j cancel
			return nil
		}
	case Lazy:
		j.done(pctx) // Don't leak contexts, in case done was not called.
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
		Op:    opDel,
		Table: table,
		Key:   copySlice(key),
		Value: nil,
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
		Op:    opPut,
		Table: table,
		Key:   copySlice(key),
		Value: copySlice(value),
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

	// append batch to tx ops
	tx.ops.PushBackList(b.(*replicatorBatch).ops)

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
		Op:    opDel,
		Table: table,
		Key:   copySlice(key),
		Value: nil,
	})
}

func (rb *replicatorBatch) Put(ctx context.Context, table string, key, value []byte) {
	rb.sourceBatch.Put(ctx, table, key, value)
	rb.ops.PushBack(&journalOp{
		Op:    opPut,
		Table: table,
		Key:   copySlice(key),
		Value: copySlice(value),
	})
}

func (rb *replicatorBatch) Reset(ctx context.Context) {
	rb.sourceBatch.Reset(ctx)
	rb.ops.Init()
}
