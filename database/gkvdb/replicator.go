package gkvdb

import (
	"bytes"
	"container/list"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	kbin "github.com/kelindar/binary"
)

const (
	defaultRetryTimeout = 2 * time.Second
	maxRetryDelay       = 15 * time.Second
)

type SinkUnavailableError struct {
	e error
}

func (sue SinkUnavailableError) Error() string {
	return fmt.Sprintf("sink unavailable: %v", sue.e)
}

func (sue SinkUnavailableError) Is(target error) bool {
	_, ok := target.(SinkUnavailableError)
	return ok
}

// Assert required interfaces
var (
	_ Batch       = (*replicatorBatch)(nil)
	_ Database    = (*replicatorDB)(nil)
	_ Iterator    = (*replicatorIterator)(nil)
	_ Range       = (*replicatorRange)(nil)
	_ Transaction = (*replicatorTX)(nil)

	ErrSinkUnavailable SinkUnavailableError
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

	source Database // source
	sink   Database // sink
	jdb    Database // journal, for now only support leveldb

	sinkC     chan struct{}
	closeSink context.CancelFunc
	wg        sync.WaitGroup
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
		cfg:    cfg,
		source: source,
		sink:   sink,
		sinkC:  make(chan struct{}, 1), // Can be aborted
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

func (b *replicatorDB) putJournal(ctx context.Context, id uint64, j *journal) error {
	// XXX verify key does not exist!
	//
	// Stream ops into value of journal
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

// commitJournal drops the provided journal onto disk. This function must
// complete and cannot be canceled.
func (b *replicatorDB) commitJournal(pctx context.Context, j *journal) error {
	// We do not use the parent context unless we are in lazy mode. This is
	// to prevent a premature exit that would result in dataloss at the
	// target.
	ctx := context.Background()

	id, err := newJournalID(ctx, b.jdb)
	if err != nil {
		return err
	}
	err = b.putJournal(ctx, id, j)
	if err != nil {
		return err
	}

	if b.cfg.Policy == Direct {
		// XXX we should have a light weight function here since there
		// is no point in decoding the journal again. Do this here for
		// now to verify the code but this is running much slower than
		// it should.
		return b.processJournal(ctx, id)
	} else {
		// Sink journal lazily
		select {
		case <-pctx.Done():
			return pctx.Err()
		case b.sinkC <- struct{}{}:
		default:
		}
	}

	return nil
}

func (b *replicatorDB) replayJournal(ctx context.Context, key []byte, value []byte) error {
	jb, err := b.sink.NewBatch(ctx)
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
	return b.jdb.Del(ctx, "", key)
}

func (b *replicatorDB) processJournal(ctx context.Context, id uint64) error {
	// Lift journal of disk and commit it into sink
	key := encodeJournalKey(id)
	value, err := b.jdb.Get(ctx, "", key[:])
	if err != nil {
		return err
	}
	return b.replayJournal(ctx, key[:], value[:])
}

// sinkJournals reads all uncommitted journals and commits them into the
// destination.
func (b *replicatorDB) sinkJournals(ctx context.Context) error {
	// Process as many journals as possible.
	ir, err := b.jdb.NewRange(ctx, "", nil, nil)
	if err != nil {
		// Caller may want to ignore database closed, we will just
		// replay on restart
		log.Errorf("process journals: %v", err)
		return err
	}
	for ir.Next(ctx) {
		// Do things
		key := ir.Key(ctx)
		if bytes.Equal(key, lastSequenceID) {
			continue
		}
		err = b.replayJournal(ctx, key[:], ir.Value(ctx))
		if err != nil {
			return err
		}
	}
	ir.Close(ctx)

	return err
}

func (b *replicatorDB) flushed(ctx context.Context) bool {
	it, err := b.jdb.NewIterator(ctx, "")
	if err != nil {
		panic(err) // XXX should we return true or false instead?
	}
	for it.Next(ctx) {
		if bytes.Equal(it.Key(ctx), lastSequenceID) {
			continue
		}
		return false
	}
	return true
}

func (b *replicatorDB) closed(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return true
	default:
	}
	return false
}

func (b *replicatorDB) sinkHandler(ctx context.Context) error {
	log.Tracef("sinkHandler")
	defer log.Tracef("sinkHandler exit")

	// When context is canceled try to sink the journals.

	defer b.wg.Done()
	var goingDown bool
	printError := true
	for {
		select {
		case <-ctx.Done():
			goingDown = true
		case <-b.sinkC:
		}

		err := b.sinkJournals(ctx)
		if err != nil {
			if printError {
				// Only print first error
				log.Errorf("sink handler: %v", err)
				printError = false
			}
		} else {
			printError = true
		}

		if goingDown {
			log.Infof("Journals replayed, exiting.")
			return nil
		}
	}
}

func (b *replicatorDB) Open(pctx context.Context) error {
	log.Tracef("Open")
	defer log.Tracef("Open exit")

	var errs []error

	// journal
	err := b.jdb.Open(pctx)
	if err != nil {
		return err
	}

	// source
	err = b.source.Open(pctx)
	if err != nil {
		goto journal
	}

	// sink
	err = b.sink.Open(pctx)
	if err != nil {
		switch b.cfg.Policy {
		case Direct:
			goto source
		case Lazy:
			err = SinkUnavailableError{e: err}
		}
	}

	switch b.cfg.Policy {
	case Direct:
		// Do nothing on close sink
		b.closeSink = func() {}

		// Process missed journal entries before returning.
		err := b.sinkJournals(pctx)
		if err != nil {
			return err
		}
	case Lazy:
		// Context to cancel sink
		sctx, scancel := context.WithCancel(pctx)
		b.closeSink = scancel

		b.wg.Add(1)
		go func() {
			if err := b.sinkHandler(sctx); err != nil {
				log.Errorf("sink: %v", err)
			}
		}()

		// poke sinkHandler to replay journals that weren't replicated.
		b.sinkC <- struct{}{}
	}

	return err

	// unwind
journal:
	err = b.jdb.Close(pctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("journal: %w", err))
	}
source:
	err = b.source.Close(pctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("source: %w", err))
	}

	return errors.Join(errs...)
}

func (b *replicatorDB) Close(ctx context.Context) error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	b.closeSink()
	b.wg.Wait()

	var errs []error
	err := b.source.Close(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("source: %w", err))
	}
	err = b.sink.Close(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("sink: %w", err))
	}
	err = b.jdb.Close(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("journal: %w", err))
	}
	return errors.Join(errs...)
}

func copySlice(value []byte) []byte {
	if value != nil {
		return append([]byte{}, value...)
	}
	return nil
}

func (b *replicatorDB) Del(ctx context.Context, table string, key []byte) error {
	if b.closed(ctx) {
		return ErrDBClosed
	}

	err := b.source.Update(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Del(ctx, table, key); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	j := &journal{ops: new(list.List)}
	j.ops.PushFront(&journalOp{
		Op:    opDel,
		Table: table,
		Key:   key,
	})
	err = b.commitJournal(ctx, j)
	if err != nil {
		panic(err)
	}

	// XXX lazy here
	return nil
}

func (b *replicatorDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if b.closed(ctx) {
		return false, ErrDBClosed
	}

	return b.source.Has(ctx, table, key)
}

func (b *replicatorDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if b.closed(ctx) {
		return nil, ErrDBClosed
	}

	return b.source.Get(ctx, table, key)
}

func (b *replicatorDB) Put(ctx context.Context, table string, key, value []byte) error {
	if b.closed(ctx) {
		return ErrDBClosed
	}

	err := b.source.Update(ctx, func(ctx context.Context, tx Transaction) error {
		if err := tx.Put(ctx, table, key, value); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return err
	}

	j := &journal{ops: new(list.List)}
	j.ops.PushFront(&journalOp{
		Op:    opPut,
		Table: table,
		Key:   key,
		Value: value,
	})
	err = b.commitJournal(ctx, j)
	if err != nil {
		return SinkUnavailableError{e: err}
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
	if tx.db.closed(ctx) {
		return ErrDBClosed
	}

	err := tx.source.Commit(ctx)
	if err != nil {
		return err
	}
	err = tx.db.commitJournal(ctx, &journal{ops: tx.ops})
	if err != nil {
		panic(err)
	}
	return nil
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
