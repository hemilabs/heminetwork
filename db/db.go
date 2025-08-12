package db

import (
	"context"
	"errors"

	"github.com/juju/loggo"
)

type Database interface {
	Open(context.Context) error
	Close(context.Context) error

	Del(context.Context, []byte) error
	Has(context.Context, []byte) (bool, error)
	Get(context.Context, []byte) ([]byte, error)
	Put(context.Context, []byte, []byte) error
}

var (
	ErrKeyNotFound   = errors.New("key not found")
	ErrInvalidConfig = errors.New("invalid config")
)

const logLevel = "INFO"

var log = loggo.GetLogger("db")

func init() {
	if err := loggo.ConfigureLoggers(logLevel); err != nil {
		panic(err)
	}
}
