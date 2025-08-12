package db

import (
	"context"
	"errors"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

var _ Database = (*mongoDB)(nil)

type mongoKV struct {
	ID    []byte `bson:"_id"`
	Value []byte `bson:"value"`
}

type MongoConfig struct {
	URI string
}

func DefaultMongoConfig(URI string) *MongoConfig {
	return &MongoConfig{
		URI: URI,
	}
}

type mongoDB struct {
	db *mongo.Client
	co *mongo.Collection

	cfg *MongoConfig
}

func NewMongoDB(cfg *MongoConfig) (Database, error) {
	if cfg == nil {
		return nil, ErrInvalidConfig
	}
	bdb := &mongoDB{
		cfg: cfg,
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
	b.co = client.Database("mydatabase").Collection("mycollection")
	// XXX drop mycollection
	return b.co.Drop(ctx) // XXX don't do this
}

func (b *mongoDB) Close(ctx context.Context) error {
	err := b.db.Disconnect(ctx)
	if err != nil {
		return err
	}
	b.db = nil
	return nil
}

func (b *mongoDB) Del(ctx context.Context, key []byte) error {
	rv, err := b.co.DeleteOne(ctx, bson.D{
		{"_id", key},
	})
	_ = rv
	// log.Infof("Del: %v", spew.Sdump(rv))
	return err
}

func (b *mongoDB) Has(ctx context.Context, key []byte) (bool, error) {
	count, err := b.co.CountDocuments(ctx, bson.M{
		"_id": key,
	})
	if err != nil {
		return false, err
	}
	if count == 0 {
		return false, nil
	}
	return true, nil
}

func (b *mongoDB) Get(ctx context.Context, key []byte) ([]byte, error) {
	var result mongoKV
	err := b.co.FindOne(ctx, bson.M{
		"_id": key,
	}).Decode(&result)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrKeyNotFound
		}
		return nil, err
	}
	// log.Infof("%v", spew.Sdump(result))
	return result.Value, nil
}

func (b *mongoDB) Put(pctx context.Context, key, value []byte) error {
	opts := options.UpdateOne().SetUpsert(true)
	update := bson.D{{"$set", bson.D{{"value", value}}}}
	_, err := b.co.UpdateByID(pctx, key, update, opts)
	if err != nil {
		return err
	}
	return nil

	// pctx = context.TODO() // XXX
	//txnOpts := options.Transaction().SetReadConcern(readconcern.Majority())
	//opts := options.Session().SetDefaultTransactionOptions(txnOpts)
	//sess, err := b.db.StartSession(opts)
	//if err != nil {
	//	return err
	//}
	//defer sess.EndSession(pctx)

	// filter := bson.M{"_id": key}
	// update := bson.M{"$set": mongoKV{ID: key, Value: value}}

	//txnOpts.SetReadPreference(readpref.PrimaryPreferred())
	//result, err := sess.WithTransaction(pctx, func(ctx context.Context) (interface{}, error) {
	//	opts := options.UpdateOne().SetUpsert(true)
	//	result, err := b.co.UpdateOne(ctx, filter, update, opts)
	//	if err != nil {
	//		return nil, err
	//	}
	//	if result.MatchedCount != 0 {
	//		log.Infof("replace: %v %v", spew.Sdump(key), spew.Sdump(value))
	//		return result, nil
	//	}
	//	if result.UpsertedCount != 0 {
	//		log.Infof("inserted a new document with ID %v %v\n", spew.Sdump(result.UpsertedID), spew.Sdump(value))
	//	}
	//	// log.Infof("new %v", result)
	//	return result, nil
	//}, txnOpts)
	//spew.Dump(result)

	// return err
}
