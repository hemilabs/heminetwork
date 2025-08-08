package db

import (
	"context"
	"errors"
)

type Database interface {
	Open(context.Context) error
	Close(context.Context) error

	Has(context.Context, []byte) (bool, error)
	Get(context.Context, []byte) ([]byte, error)
	Put(context.Context, []byte, []byte) error
}

var ErrInvalidConfig = errors.New("invalid config")
