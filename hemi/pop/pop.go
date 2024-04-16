// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package pop

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/hemilabs/heminetwork/hemi"

	"github.com/btcsuite/btcd/txscript"
	dcrsecp256k1 "github.com/decred/dcrd/dcrec/secp256k1/v4"
)

var magic = []byte("HEMI")

type MinerAddress [20]byte

func MinerAddressFromString(address string) (*MinerAddress, error) {
	b, err := hex.DecodeString(address)
	if err != nil {
		return nil, fmt.Errorf("invalid miner address: %w", err)
	}

	var ma MinerAddress
	if len(b) != len(ma) {
		return nil, fmt.Errorf("invalid miner address length (%d != %d)", len(b), len(ma))
	}
	copy(ma[:], b)

	return &ma, nil
}

// XXX does this belong here? this feels more hemi-y.

// TransactionL2 rename to Transaction and fixup this code
type TransactionL2 struct {
	L2Keystone *hemi.L2KeystoneAbrev
}

// Serialize serializes a PoP transaction to its byte representation.
func (tx *TransactionL2) Serialize() []byte {
	khb := tx.L2Keystone.Serialize()

	var b []byte
	b = append(b, magic...)
	b = append(b, khb[:]...)

	return b
}

// EncodeToOpReturn produces the pay to script necessary to publish this
// PoP transaction on Bitcoin using OP_RETURN.
func (tx *TransactionL2) EncodeToOpReturn() ([]byte, error) {
	txb := tx.Serialize()

	tsb := txscript.NewScriptBuilder()
	tsb.AddOp(txscript.OP_RETURN)
	tsb.AddData(txb)

	return tsb.Script()
}

// ParseTransactionFromOpReturn attempts to parse the given data
// as an OP_RETURN encoded PoP transaction.
func ParseTransactionL2FromOpReturn(script []byte) (*TransactionL2, error) {
	txst := txscript.MakeScriptTokenizer(0, script)
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	if txst.Opcode() != txscript.OP_RETURN {
		return nil, fmt.Errorf("not a PoP transaction, found: 0x%X", txst.Opcode())
	}
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	data := txst.Data()
	if len(data) < 5 {
		return nil, fmt.Errorf("not a PoP transaction, found len %d", len(data))
	}
	if !bytes.Equal(data[0:4], magic) {
		return nil, errors.New("not a PoP transaction")
	}
	ksh, err := hemi.NewL2KeystoneAbrevFromBytes(data[4:])
	if err != nil {
		return nil, fmt.Errorf("parse keystone header: %w", err)
	}
	return &TransactionL2{L2Keystone: ksh}, nil
}

// XXX delete Transaction
type Transaction struct {
	Keystone *hemi.Header
}

// Serialize serializes a PoP transaction to its byte representation.
func (tx *Transaction) Serialize() []byte {
	khb := tx.Keystone.Serialize()

	var b []byte
	b = append(b, magic...)
	b = append(b, khb[:]...)

	return b
}

// EncodeToOpReturn produces the pay to script necessary to publish this
// PoP transaction on Bitcoin using OP_RETURN.
func (tx *Transaction) EncodeToOpReturn() ([]byte, error) {
	txb := tx.Serialize()

	tsb := txscript.NewScriptBuilder()
	tsb.AddOp(txscript.OP_RETURN)
	tsb.AddData(txb)

	return tsb.Script()
}

// ParseTransactionFromOpReturn attempts to parse the given data
// as an OP_RETURN encoded PoP transaction.
func ParseTransactionFromOpReturn(script []byte) (*Transaction, error) {
	txst := txscript.MakeScriptTokenizer(0, script)
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	if txst.Opcode() != txscript.OP_RETURN {
		return nil, errors.New("not a PoP transaction")
	}
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	data := txst.Data()
	if len(data) < 4 {
		return nil, errors.New("not a PoP transaction")
	}
	if !bytes.Equal(data[0:4], magic) {
		return nil, errors.New("not a PoP transaction")
	}
	ksh, err := hemi.NewHeaderFromBytes(data[4:])
	if err != nil {
		return nil, fmt.Errorf("parse keystone header: %w", err)
	}
	return &Transaction{Keystone: ksh}, nil
}

func ParsePublicKeyFromSignatureScript(script []byte) ([]byte, error) {
	var err error
	txst := txscript.MakeScriptTokenizer(0, script)
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	if txst.Opcode() != txscript.OP_DATA_72 && txst.Opcode() != txscript.OP_DATA_71 {
		return nil, fmt.Errorf("not a signature , found: 0x%X", txst.Opcode())
	}
	if !txst.Next() {
		return nil, errors.New("parse script")
	}
	data := txst.Data()
	if len(data) != 33 {
		return nil, fmt.Errorf("not a PoP transaction, found len %d", len(data))
	}

	publicKey, err := dcrsecp256k1.ParsePubKey(data)
	if err != nil {
		return nil, err
	}
	return publicKey.SerializeUncompressed(), nil
}
