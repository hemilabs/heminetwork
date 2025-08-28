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

	kbin "github.com/kelindar/binary"
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
	ctx  context.Context       // external wait
	done func(context.Context) // external completion
	err  error                 // error occurred prior to completion

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

	source          Database // source
	sink            Database // sink
	jdb             Database // journal, for now only support leveldb
	journalC        chan *journal
	sinkC           chan string
	handlersFlusher sync.WaitGroup
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
		journalC: make(chan *journal, 1024), // MUST BE FLUSHED PRIOR TO EXIT
		sinkC:    make(chan string, 1),      // Can be aborted
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
	// Stream ops into value of journal
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

// this is very racy, use with caution.
func (b *replicatorDB) flushed(ctx context.Context) bool {
	if len(b.journalC) != 0 {
		return false
	}
	it, err := b.jdb.NewIterator(ctx, "")
	if err != nil {
		panic(err)
	}
	for it.Next(ctx) {
		if bytes.Equal(it.Key(ctx), lastSequenceID) {
			continue
		}
		return false
	}
	// Make sure nothing came in, this function really is best effort.
	if len(b.journalC) != 0 {
		return false
	}
	return true
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

func (b *replicatorDB) processJournal(pctx context.Context, id uint64) error {
	// XXX This sucks. We should shutdown the journal handler when
	// being shutdown. We do MUST wait for the sink to drain.
	ctx := context.TODO()
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
		err := b.replayJournal(ctx, key[:], ir.Value(ctx))
		if err != nil {
			// XXX this is going to be way too loud when we have an
			// actual persistent failure.
			log.Errorf("could not replay journal: %v", err)
			break
		}
	}
	ir.Close(ctx)

	return err
}

func (b *replicatorDB) sinkHandler(ctx context.Context) error {
	log.Tracef("sinkHandler")
	defer log.Tracef("sinkHandler exit")

	// XXX this needs some more thought. In direct mode we should flush
	// journals. In lazy mode we can exist whenever since the journal can
	// be replayed later. Allthough it is good form to at least try to
	// flush the journals.
	//
	// The terminal sentinel is crap and needs to be rethought.

	defer b.handlersFlusher.Done()
	var goingDown bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case cmd := <-b.sinkC:
			// Prevent going down if cmd != ""
			if cmd == "" {
			} else {
				log.Infof("Going down, finish replaying journals on target.")
				goingDown = true
			}
		}

		err := b.sinkJournals(ctx)
		if err != nil {
			log.Errorf("journal handler: %v", err)
			return err // XXX no one listens to these
		}

		if goingDown {
			log.Infof("Journals replayed, exiting.")
			return nil
		}
	}
}

func (b *replicatorDB) journalHandler(pctx context.Context) error {
	log.Tracef("journalHandler")
	defer log.Tracef("journalHandler exit")

	defer b.handlersFlusher.Done()
	for {
		var j *journal
		select {
		case <-pctx.Done():
			return pctx.Err()
		case j = <-b.journalC:
			if j == nil {
				// XXX we must really make sure
				// there is nothing else in the channel!
				if len(b.journalC) != 0 {
					panic("FIX THIS SHIT")
				}
				return nil
			}
		}

		// don't use parent context since we MUST sink the journal
		// entry prior to exit.
		ctx := context.TODO() // XXX this needs thinking

		// Commit journal.
		//
		// Think about these panics, but there is inherent data loss
		// when this happens. The only way to recover is a full
		// database reconciliation.
		id, err := newJournalID(ctx, b.jdb)
		if err != nil {
			panic(err)
		}
		err = b.commitJournal(ctx, id, j)
		if err != nil {
			panic(err)
		}

		// Tell caller we are done if we are in lazy mode.
		switch b.cfg.Policy {
		case Direct:
			err := b.processJournal(ctx, id)
			if err != nil {
				j.err = SinkUnavailableError{e: err}
			}
		case Lazy:
			// Sink journal
			select {
			case <-ctx.Done():
				return ctx.Err()
			case b.sinkC <- "":
			default:
			}
		}

		j.done(ctx) // Mark journal done
	}
}

func (b *replicatorDB) Open(ctx context.Context) error {
	log.Tracef("Open")
	defer log.Tracef("Open exit")

	var errs []error

	// journal
	err := b.jdb.Open(ctx)
	if err != nil {
		return err
	}

	// source
	err = b.source.Open(ctx)
	if err != nil {
		goto journal
	}

	// sink
	err = b.sink.Open(ctx)
	if err != nil {
		switch b.cfg.Policy {
		case Direct:
			goto source
		case Lazy:
			err = SinkUnavailableError{e: err}
		}
	}

	b.handlersFlusher.Add(1)
	go func() {
		err := b.journalHandler(ctx)
		if err != nil {
			log.Errorf("journal: %v", err)
		}
	}()

	b.handlersFlusher.Add(1)
	go func() {
		err := b.sinkHandler(ctx)
		if err != nil {
			log.Errorf("sink: %v", err)
		}
	}()

	switch b.cfg.Policy {
	case Direct:
		// Process missed journal entries before returning.
		err := b.sinkJournals(ctx)
		if err != nil {
			return err
		}
	case Lazy:
		// poke sinkHandler to replay journals that weren't replicated.
		b.sinkC <- ""
	}

	return err

	// unwind
journal:
	err = b.jdb.Close(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("journal: %w", err))
	}
source:
	err = b.source.Close(ctx)
	if err != nil {
		errs = append(errs, fmt.Errorf("source: %w", err))
	}

	return errors.Join(errs...)
}

func (b *replicatorDB) Close(ctx context.Context) error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	// We must not allow close until the journal has been flushed.
	//
	// XXX this channel mess kinda sucks, rethink
	// XXX at the very least we must prevent database commands from
	// generating more flushing pressure.
	b.journalC <- nil // nil is sentinel value for going down
	b.sinkC <- "going down"
	b.handlersFlusher.Wait()
	if len(b.journalC) != 0 {
		panic("journal not flushed")
	}

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

func newJournal(pctx context.Context, sync bool) *journal {
	// This is a bit awkward but if we are in direct mode derive a new
	// context that we cancel once a command is complete. In lazy mode just
	// use the parent context.
	j := &journal{
		ctx:  pctx, // For caller to wait on
		done: func(context.Context) {},
		ops:  list.New(),
	}
	if sync {
		ctx, cancel := context.WithCancel(pctx) // Make sure done is called
		j.ctx = ctx
		j.done = func(_ context.Context) { cancel() }
	}
	return j
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
	case b.journalC <- j:
	}

	// If this is a slow sink performance is going to suck.
	switch b.cfg.Policy {
	case Direct:
		//nolint:staticcheck // fuck you dumb ass linter
		select {
		case <-j.ctx.Done():
			// Catches pctx and j cancel
			return j.err
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
	// journal tx
	// XXX we must makre sure this journal makes it; not sure that's the
	// case now. Add test for this.
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
