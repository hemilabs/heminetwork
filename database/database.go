// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package database

import (
	"fmt"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

type Database interface {
	Close() error // Close database
}

type NotFoundError string

func (nfe NotFoundError) Error() string {
	return string(nfe)
}

func (nfe NotFoundError) Is(target error) bool {
	_, ok := target.(NotFoundError)
	return ok
}

type BlockNotFoundError struct {
	chainhash.Hash
}

func (bnfe BlockNotFoundError) Error() string {
	return fmt.Sprintf("block not found: %v", bnfe.Hash)
}

func (bnfe BlockNotFoundError) Is(target error) bool {
	_, ok := target.(BlockNotFoundError)
	return ok
}

type DuplicateError string

func (de DuplicateError) Error() string {
	return string(de)
}

func (de DuplicateError) Is(target error) bool {
	_, ok := target.(DuplicateError)
	return ok
}

var (
	ErrDuplicate     = DuplicateError("duplicate")
	ErrNotFound      = NotFoundError("not found")
	ErrBlockNotFound BlockNotFoundError
)
