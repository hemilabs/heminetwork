// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

// Package testutil provides utilities for testing helper functions.

package testutil

import (
	"testing"
)

func TestBytes32(t *testing.T) {
	result := Bytes32("test")
	if len(result) != 32 {
		t.Errorf("Bytes32() returned slice of length %d, want 32", len(result))
	}
	if string(result[:4]) != "test" {
		t.Errorf("Bytes32() prefix = %s, want 'test'", string(result[:4]))
	}
}

func TestHeader80(t *testing.T) {
	result := Header80("header")
	if len(result) != 80 {
		t.Errorf("Header80() returned slice of length %d, want 80", len(result))
	}
	if string(result[:6]) != "header" {
		t.Errorf("Header80() prefix = %s, want 'header'", string(result[:6]))
	}
}

func TestBytes32Array(t *testing.T) {
	input := []byte("test")
	result := Bytes32Array(input)
	if len(result) != 32 {
		t.Errorf("Bytes32Array() returned array of length %d, want 32", len(result))
	}
	if string(result[:4]) != "test" {
		t.Errorf("Bytes32Array() prefix = %s, want 'test'", string(result[:4]))
	}
}

func TestDecodeHex(t *testing.T) {
	result := DecodeHex("48656c6c6f") // "Hello" in hex
	expected := []byte("Hello")
	if string(result) != string(expected) {
		t.Errorf("DecodeHex() = %s, want %s", string(result), string(expected))
	}
}

func TestDecodeTxID(t *testing.T) {
	// Test with a valid 32-byte hex string
	hexStr := "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
	result := DecodeTxID(hexStr)
	if len(result) != 32 {
		t.Errorf("DecodeTxID() returned array of length %d, want 32", len(result))
	}
}

func TestCreateRandomBytes(t *testing.T) {
	result := CreateRandomBytes(16)
	if len(result) != 16 {
		t.Errorf("CreateRandomBytes() returned slice of length %d, want 16", len(result))
	}
}

func TestCreateRandomHash(t *testing.T) {
	result := CreateRandomHash()
	if len(result) != 32 {
		t.Errorf("CreateRandomHash() returned slice of length %d, want 32", len(result))
	}
}

func TestCreateRandomHeader(t *testing.T) {
	result := CreateRandomHeader()
	if len(result) != 80 {
		t.Errorf("CreateRandomHeader() returned slice of length %d, want 80", len(result))
	}
}
