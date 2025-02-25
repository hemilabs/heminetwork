// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package database

import (
	"errors"
	"fmt"
	"testing"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
)

func TestErrors(t *testing.T) {
	hash, err := chainhash.NewHashFromStr("000000000000098faa89ab34c3ec0e6e037698e3e54c8d1bbb9dcfe0054a8e7a")
	if err != nil {
		t.Fatal(err)
	}
	err = BlockNotFoundError{*hash}
	if !errors.Is(err, ErrBlockNotFound) {
		t.Fatalf("expected block not found, got %T", err)
	}
	err = fmt.Errorf("wrap %w", err)
	if !errors.Is(err, ErrBlockNotFound) {
		t.Fatalf("expected wrapped block not found, got %T", err)
	}
	var e BlockNotFoundError
	if !errors.As(err, &e) {
		t.Fatalf("expected wrapped block not found, got %T %v", err, err)
	}
	block := e.Hash
	t.Logf("%v", block)
	err = errors.New("moo")
	if errors.Is(err, ErrBlockNotFound) {
		t.Fatalf("did not expected block not found, got %T", err)
	}
}
