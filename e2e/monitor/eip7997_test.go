package main

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
)

// eip7997Factory is the deterministic CREATE2 factory predeployed by EIP-7997.
var eip7997Factory = common.HexToAddress("0x4e59b44847b379578588920cA78FbF26c0B4956C")

// EIP7997_FactoryCreate2 checks for EIP-7997 (deterministic factory
// predeploy): calling the factory with salt || initcode must deploy the
// initcode's result at the CREATE2 address.
func EIP7997_FactoryCreate2(t *testing.T, key *ecdsa.PrivateKey) {
	h := newHarness(t, key)

	// A unique salt, so parallel and repeated runs never collide.
	salt := crypto.Keccak256Hash(h.from.Bytes(),
		[]byte(fmt.Sprint(time.Now().UnixNano())))

	// Deploys a 1 byte runtime (0x00).
	initcode := []byte{
		0x60, 0x01, // PUSH1 1
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN
	}
	expected := crypto.CreateAddress2(eip7997Factory, salt, crypto.Keccak256(initcode))

	receipt := h.send(&eip7997Factory, append(salt.Bytes(), initcode...), 1_000_000)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("call to CREATE2 factory failed (tx %s)", receipt.TxHash)
	}

	code, err := h.client.CodeAt(h.ctx, expected, nil)
	if err != nil {
		t.Fatalf("fetching code: %v", err)
	}
	if !bytes.Equal(code, []byte{0x00}) {
		t.Fatalf("code at %s = %x, want 00", expected, code)
	}
}
