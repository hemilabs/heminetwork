// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package gkvdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const internalDB = "mydatabase"

// Assert required interfaces
var (
	_ Batch       = (*mongoBatch)(nil)
	_ Database    = (*mongoDB)(nil)
	_ Iterator    = (*mongoIterator)(nil)
	_ Range       = (*mongoRange)(nil)
	_ Transaction = (*mongoTX)(nil)
)

type mongoKV struct {
	Key   []byte `bson:"key"`
	Value []byte `bson:"value"`
}

type MongoConfig struct {
	URI    string
	Tables []string
}

func DefaultMongoConfig(URI string, tables []string) *MongoConfig {
	return &MongoConfig{
		URI:    URI,
		Tables: tables,
	}
}

type mongoDB struct {
	db     *mongo.Client
	cfg    *MongoConfig
	tables map[string]struct{}
}

func NewMongoDB(cfg *MongoConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &mongoDB{
		cfg:    cfg,
		tables: make(map[string]struct{}, len(cfg.Tables)),
	}
	for _, v := range cfg.Tables {
		if _, ok := bdb.tables[v]; ok {
			return nil, ErrDuplicateTable
		}
		bdb.tables[v] = struct{}{}
	}
	return bdb, nil
}

func (b *mongoDB) Open(ctx context.Context) error {
	if b.db != nil {
		return nil // XXX return already open?
	}

	client, err := mongo.Connect(options.Client().
		ApplyURI(b.cfg.URI))
	if err != nil {
		return err
	}
	b.db = client
	if true {
		// XXX don't do this
		for _, table := range b.cfg.Tables {
			co := client.Database(internalDB).Collection(table)
			err := co.Drop(ctx)
			if err != nil {
				return fmt.Errorf("could not drop table: %v", table)
			}
		}
	}
	// Must create the collections first to prevent Write Conflicts if we
	// concurrently try to write to a collection that doesn't yet exist
	for table := range b.tables {
		err := b.db.Database(internalDB).CreateCollection(ctx, table)
		if err != nil {
			return fmt.Errorf("error creating table %v: %w", table, err)
		}
	}
	return nil
}

func (b *mongoDB) Close(ctx context.Context) error {
	err := b.db.Disconnect(ctx)
	if err != nil {
		return err
	}
	b.db = nil
	return nil
}

func (b *mongoDB) Del(ctx context.Context, table string, key []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	co := b.db.Database(internalDB).Collection(table)
	rv, err := co.DeleteOne(ctx, bson.D{{Key: "key", Value: key}})
	_ = rv
	// log.Infof("Del: %v", spew.Sdump(rv))
	return err
}

func (b *mongoDB) Has(ctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := b.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	co := b.db.Database(internalDB).Collection(table)
	count, err := co.CountDocuments(ctx, bson.M{"key": key})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	return true, nil
}

func (b *mongoDB) Get(ctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	var result mongoKV
	co := b.db.Database(internalDB).Collection(table)
	err := co.FindOne(ctx, bson.M{"key": key}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	// log.Infof("%v", spew.Sdump(result))
	return result.Value, nil
}

func (b *mongoDB) Put(pctx context.Context, table string, key, value []byte) error {
	if _, ok := b.tables[table]; !ok {
		return ErrTableNotFound
	}
	opts := options.UpdateOne().SetUpsert(true)
	update := bson.D{{Key: "$set", Value: bson.D{{Key: "value", Value: value}}}}
	filter := bson.D{{Key: "key", Value: key}}
	co := b.db.Database(internalDB).Collection(table)
	_, err := co.UpdateOne(pctx, filter, update, opts)
	return err
}

func (b *mongoDB) Begin(ctx context.Context, write bool) (Transaction, error) {
	txnOpts := options.Transaction()
	sessOpts := options.Session()
	session, err := b.db.StartSession(sessOpts)
	if err != nil {
		return nil, err
	}
	if err := session.StartTransaction(txnOpts); err != nil {
		session.EndSession(ctx)
		return nil, err
	}
	return &mongoTX{
		db: b,
		s:  session,
	}, nil
}

func (b *mongoDB) execute(ctx context.Context, write bool, callback func(ctx context.Context, tx Transaction) error) error {
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

func (b *mongoDB) View(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, false, callback)
}

func (b *mongoDB) Update(ctx context.Context, callback func(ctx context.Context, tx Transaction) error) error {
	return b.execute(ctx, true, callback)
}

func (b *mongoDB) NewIterator(ctx context.Context, table string) (Iterator, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	co := b.db.Database(internalDB).Collection(table)
	cursor, err := co.Find(ctx, bson.D{})
	if err != nil {
		return nil, err
	}
	return &mongoIterator{
		co: co,
		it: cursor,
	}, nil
}

func (b *mongoDB) NewRange(ctx context.Context, table string, start, end []byte) (Range, error) {
	if _, ok := b.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	co := b.db.Database(internalDB).Collection(table)
	cursor, err := co.Find(ctx,
		bson.D{
			{Key: "key", Value: bson.M{
				"$gte": start,
				"$lte": end,
			}},
		})
	if err != nil {
		return nil, err
	}
	return &mongoRange{
		co:    co,
		it:    cursor,
		start: start,
		end:   end,
	}, nil
}

func (b *mongoDB) NewBatch(ctx context.Context) (Batch, error) {
	return &mongoBatch{
		wm: make([]mongo.ClientBulkWrite, 0),
	}, nil
}

func (b *mongoDB) DumpTable(ctx context.Context, table string, target io.Writer) error {
	return ErrNotSuported
}

func (b *mongoDB) RestoreTable(ctx context.Context, table string, source io.Reader) error {
	return ErrNotSuported
}

// Transactions
type mongoTX struct {
	db *mongoDB
	s  *mongo.Session
}

func (tx *mongoTX) Del(pctx context.Context, table string, key []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	sctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err := mongo.WithSession(sctx, tx.s, func(ctx context.Context) error {
		co := tx.db.db.Database(internalDB).Collection(table)
		_, serr := co.DeleteOne(ctx, bson.D{{Key: "key", Value: key}})
		return serr
	})
	return err
}

func (tx *mongoTX) Has(pctx context.Context, table string, key []byte) (bool, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return false, ErrTableNotFound
	}
	sctx, cancel := context.WithCancel(pctx)
	defer cancel()

	var count int64
	err := mongo.WithSession(sctx, tx.s, func(ctx context.Context) error {
		co := tx.db.db.Database(internalDB).Collection(table)
		c, serr := co.CountDocuments(ctx, bson.M{"key": key})
		count = c
		return serr
	})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	return true, nil
}

func (tx *mongoTX) Get(pctx context.Context, table string, key []byte) ([]byte, error) {
	if _, ok := tx.db.tables[table]; !ok {
		return nil, ErrTableNotFound
	}
	sctx, cancel := context.WithCancel(pctx)
	defer cancel()

	var result mongoKV
	err := mongo.WithSession(sctx, tx.s, func(ctx context.Context) error {
		co := tx.db.db.Database(internalDB).Collection(table)
		serr := co.FindOne(ctx, bson.M{"key": key}).Decode(&result)
		if errors.Is(serr, mongo.ErrNoDocuments) {
			return ErrKeyNotFound
		}
		return serr
	})
	return result.Value, err
}

func (tx *mongoTX) Put(pctx context.Context, table string, key []byte, value []byte) error {
	if _, ok := tx.db.tables[table]; !ok {
		return ErrTableNotFound
	}
	sctx, cancel := context.WithCancel(pctx)
	defer cancel()

	err := mongo.WithSession(sctx, tx.s, func(ctx context.Context) error {
		opts := options.UpdateOne().SetUpsert(true)
		update := bson.D{{Key: "$set", Value: bson.D{{Key: "value", Value: value}}}}
		filter := bson.D{{Key: "key", Value: key}}
		co := tx.db.db.Database(internalDB).Collection(table)
		_, serr := co.UpdateOne(ctx, filter, update, opts)
		return serr
	})
	return err
}

func (tx *mongoTX) Commit(ctx context.Context) error {
	defer func() {
		tx.s.EndSession(ctx)
	}()
	return tx.s.CommitTransaction(ctx)
}

func (tx *mongoTX) Rollback(ctx context.Context) error {
	tx.s.EndSession(ctx)
	return nil
}

func (tx *mongoTX) Write(pctx context.Context, b Batch) error {
	sctx, cancel := context.WithCancel(pctx)
	defer cancel()

	mb, ok := b.(*mongoBatch)
	if !ok {
		return fmt.Errorf("expected batch type mongoBatch, got %T", b)
	}
	err := mongo.WithSession(sctx, tx.s, func(ctx context.Context) error {
		_, err := tx.db.db.BulkWrite(ctx, mb.wm)
		return err
	})
	return err
}

// Iterations
// XXX check if setting of cursor batch size is needed
// for large amounts of documents
type mongoIterator struct {
	co *mongo.Collection
	it *mongo.Cursor
}

func (ni *mongoIterator) First(ctx context.Context) bool {
	it, err := ni.co.Find(ctx, bson.D{})
	if err != nil {
		log.Errorf(err.Error())
		return false
	}
	if err := ni.it.Close(ctx); err != nil {
		log.Errorf(err.Error())
	}
	ni.it = it
	return ni.Next(ctx)
}

func (ni *mongoIterator) Last(ctx context.Context) bool {
	fopt := options.Find().SetSort(bson.D{{Key: "$natural", Value: -1}}).
		SetLimit(1)
	it, err := ni.co.Find(ctx, bson.D{}, fopt)
	if err != nil {
		log.Errorf(err.Error())
		return false
	}
	if err := ni.it.Close(ctx); err != nil {
		log.Errorf(err.Error())
	}
	ni.it = it
	return ni.Next(ctx)
}

func (ni *mongoIterator) Next(ctx context.Context) bool {
	return ni.it.Next(ctx)
}

func (ni *mongoIterator) Seek(ctx context.Context, key []byte) bool {
	it, err := ni.co.Find(ctx, bson.D{{Key: "key", Value: bson.M{
		"$gte": key,
	}}})
	if err != nil {
		log.Errorf(err.Error())
		return false
	}
	if err := ni.it.Close(ctx); err != nil {
		log.Errorf(err.Error())
	}
	ni.it = it
	return ni.Next(ctx)
}

func (ni *mongoIterator) Key(_ context.Context) []byte {
	var result mongoKV
	if err := ni.it.Decode(&result); err != nil {
		log.Errorf("failed to decode into KV pair: %v", ni.it.Current)
		return nil
	}
	return result.Key
}

func (ni *mongoIterator) Value(_ context.Context) []byte {
	var result mongoKV
	if err := ni.it.Decode(&result); err != nil {
		log.Errorf("failed to decode into KV pair: %v", ni.it.Current)
		return nil
	}
	return result.Value
}

func (ni *mongoIterator) Close(ctx context.Context) {
	if err := ni.it.Close(ctx); err != nil {
		log.Errorf("failed to close cursor: %v", err)
	}
}

// Ranges
type mongoRange struct {
	co    *mongo.Collection
	it    *mongo.Cursor
	start []byte
	end   []byte
}

func (nr *mongoRange) First(ctx context.Context) bool {
	it, err := nr.co.Find(ctx, bson.D{
		{Key: "key", Value: bson.M{
			"$gte": nr.start,
			"$lte": nr.end,
		}},
	})
	if err != nil {
		log.Errorf(err.Error())
		return false
	}
	if err := nr.it.Close(ctx); err != nil {
		log.Errorf(err.Error())
	}
	nr.it = it
	return nr.Next(ctx)
}

func (nr *mongoRange) Last(ctx context.Context) bool {
	fopt := options.Find().SetSort(bson.D{{Key: "$natural", Value: -1}}).
		SetLimit(1)
	it, err := nr.co.Find(ctx, bson.D{
		{Key: "key", Value: bson.M{
			"$gte": nr.start,
			"$lte": nr.end,
		}},
	}, fopt)
	if err != nil {
		log.Errorf(err.Error())
		return false
	}
	if err := nr.it.Close(ctx); err != nil {
		log.Errorf(err.Error())
	}
	nr.it = it
	return nr.Next(ctx)
}

func (nr *mongoRange) Next(ctx context.Context) bool {
	return nr.it.Next(ctx)
}

func (nr *mongoRange) Key(ctx context.Context) []byte {
	var result mongoKV
	if err := nr.it.Decode(&result); err != nil {
		log.Errorf("failed to decode into KV pair: %v", nr.it.Current)
		return nil
	}
	return result.Key
}

func (nr *mongoRange) Value(ctx context.Context) []byte {
	var result mongoKV
	if err := nr.it.Decode(&result); err != nil {
		log.Errorf("failed to decode into KV pair: %v", nr.it.Current)
		return nil
	}
	return result.Value
}

func (nr *mongoRange) Close(ctx context.Context) {
	if err := nr.it.Close(ctx); err != nil {
		log.Errorf("failed to close cursor: %v", err)
	}
}

// Batches

type mongoBatch struct {
	wm []mongo.ClientBulkWrite
}

func (nb *mongoBatch) Del(ctx context.Context, table string, key []byte) {
	m := mongo.NewClientDeleteOneModel().SetFilter(bson.D{{Key: "key", Value: key}})
	cbw := mongo.ClientBulkWrite{
		Database:   internalDB,
		Collection: table,
		Model:      m,
	}
	nb.wm = append(nb.wm, cbw)
}

func (nb *mongoBatch) Put(ctx context.Context, table string, key, value []byte) {
	m := mongo.NewClientUpdateOneModel().SetFilter(bson.D{{Key: "key", Value: key}}).SetUpsert(true).
		SetUpdate(bson.D{{Key: "$set", Value: bson.D{{Key: "value", Value: value}}}})
	cbw := mongo.ClientBulkWrite{
		Database:   internalDB,
		Collection: table,
		Model:      m,
	}
	nb.wm = append(nb.wm, cbw)
}

func (nb *mongoBatch) Reset(ctx context.Context) {
	nb.wm = make([]mongo.ClientBulkWrite, 0)
}
