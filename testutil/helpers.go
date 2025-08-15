package testutil

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/rand"
	"slices"
	"strings"
)

func FillOutBytes(prefix string, size int) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(prefix)
	if size > len(prefix) {
		buffer.WriteString(strings.Repeat("_", size-len(prefix)))
	}
	return buffer.Bytes()
}

// FillOutBytesWith0s creates a byte slice of specified size with the given prefix
// and fills the remaining space with zero bytes.
// Parameters:
//   - prefix: string to use as the prefix
//   - size: total size of the resulting byte slice
//
// Returns a byte slice of length 'size' with prefix followed by zero bytes.
func FillOutBytesWith0s(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, 0)
	}

	return result
}

// RandomBytes generates a slice of random bytes of the specified size
// Parameters:
//   - size: the size of the byte slice to generate
//
// Returns a byte slice of random bytes
func RandomBytes(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(rand.Intn(256))
	}
	return b
}

// Bytes32 creates a 32-byte slice filled with a prefix and underscores
// This is commonly used in tests for creating hash-like byte arrays
// Parameters:
//   - prefix: string to use as the prefix
//
// Returns a 32-byte slice
func Bytes32(prefix string) []byte {
	return FillOutBytes(prefix, 32)
}

// Header80 creates an 80-byte slice filled with a prefix and underscores
// This is commonly used in tests for creating Bitcoin block header-like byte arrays
// Parameters:
//   - prefix: string to use as the prefix
//
// Returns an 80-byte slice
func Header80(prefix string) []byte {
	return FillOutBytes(prefix, 80)
}

// Bytes32Array creates a [32]byte array from a byte slice
// This is commonly used in tests for converting byte slices to fixed-size arrays
// Parameters:
//   - data: byte slice to convert
//
// Returns a [32]byte array
func Bytes32Array(data []byte) [32]byte {
	var result [32]byte
	copy(result[:], data)
	return result
}

// DecodeHex decodes a hex string to bytes
// This is commonly used in tests for converting hex strings to byte slices
// Parameters:
//   - s: hex string to decode
//
// Returns decoded bytes, panics on error
func DecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// DecodeTxID decodes a hex string to a [32]byte txid
// This is commonly used in tests for converting hex txid strings to fixed-size arrays
// Parameters:
//   - s: hex string to decode
//
// Returns decoded [32]byte txid, panics on error
func DecodeTxID(s string) [32]byte {
	b := DecodeHex(s)
	if len(b) != 32 {
		panic(fmt.Errorf("invalid txid: %s", s))
	}

	// Convert from display order to natural order
	slices.Reverse(b)
	return [32]byte(b)
}

// CreateRandomBytes creates a slice of random bytes of the specified size
// This is commonly used in tests for creating random test data
// Parameters:
//   - size: the size of the byte slice to generate
//
// Returns a slice of random bytes
func CreateRandomBytes(size int) []byte {
	b := make([]byte, size)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return b
}

// CreateRandomHash creates a random 32-byte hash
// This is commonly used in tests for creating random hash values
// Returns a random 32-byte slice
func CreateRandomHash() []byte {
	return CreateRandomBytes(32)
}

// CreateRandomHeader creates a random 80-byte header
// This is commonly used in tests for creating random Bitcoin block headers
// Returns a random 80-byte slice
func CreateRandomHeader() []byte {
	return CreateRandomBytes(80)
}
