// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package hemi

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/database/bfgd"
)

const (
	HeaderVersion1       = 1
	HeaderSize           = 73 // XXX rename
	KeystoneHeaderPeriod = 25 // XXX debate and set

	OldHeaderSize = 65

	HEMIBase = 1000000000000000000
)

var log = loggo.GetLogger("hemi")

type RawHeader [HeaderSize]byte

// XXX Header should be renamed to L2KeystoneAbrev
type Header struct {
	Version            uint8    // 0:1
	BlockNumber        uint32   // 1:5
	ParentEPHash       [12]byte // 5:17
	PrevKeystoneEPHash [12]byte // 17:29
	StateRoot          [32]byte // 29:61
	EPHash             [12]byte // 61:73
}

type L2BTCFinality struct {
	L2Keystone       L2Keystone    `json:"l2_keystone"`
	BTCPubHeight     int64         `json:"btc_pub_height"`
	BTCPubHeaderHash api.ByteSlice `json:"btc_pub_header_hash"`
	BTCFinality      int32         `json:"btc_finality"`
}

func L2BTCFinalityFromBfgd(l2BtcFinality *bfgd.L2BTCFinality, currentBTCHeight uint32, effectiveHeight uint32) (*L2BTCFinality, error) {
	if effectiveHeight > currentBTCHeight {
		return nil, fmt.Errorf("effective height greater than btc height (%d > %d)", effectiveHeight, currentBTCHeight)
	}

	fin := int64(-9)
	if effectiveHeight > 0 {
		fin = int64(currentBTCHeight) - int64(effectiveHeight) - 9 + 1
	}

	// set a reasonable upper bound so we can safely convert to int32
	if fin > 100 {
		fin = 100
	}

	return &L2BTCFinality{
		L2Keystone: L2Keystone{
			Version:            uint8(l2BtcFinality.L2Keystone.Version),
			L1BlockNumber:      l2BtcFinality.L2Keystone.L1BlockNumber,
			L2BlockNumber:      l2BtcFinality.L2Keystone.L2BlockNumber,
			ParentEPHash:       api.ByteSlice(l2BtcFinality.L2Keystone.ParentEPHash),
			PrevKeystoneEPHash: api.ByteSlice(l2BtcFinality.L2Keystone.PrevKeystoneEPHash),
			StateRoot:          api.ByteSlice(l2BtcFinality.L2Keystone.StateRoot),
			EPHash:             api.ByteSlice(l2BtcFinality.L2Keystone.EPHash),
		},
		BTCPubHeight:     l2BtcFinality.BTCPubHeight,
		BTCPubHeaderHash: api.ByteSlice(l2BtcFinality.BTCPubHeaderHash),
		BTCFinality:      int32(fin),
	}, nil
}

func (h *Header) Dump(w io.Writer) {
	fmt.Fprintf(w, "===========================\n")
	fmt.Fprintf(w, "Version                   : %v\n", h.Version)
	fmt.Fprintf(w, "Block Number              : %v\n", h.BlockNumber)
	fmt.Fprintf(w, "Parent EP Hash            : %x\n", h.ParentEPHash)
	fmt.Fprintf(w, "Previous Keystone EP Hash : %x\n", h.PrevKeystoneEPHash)
	fmt.Fprintf(w, "State Root                : %x\n", h.StateRoot)
	fmt.Fprintf(w, "EP Hash                   : %x\n", h.EPHash)
	fmt.Fprintf(w, "===========================\n")
}

func (h *Header) Hash() []byte {
	b := h.Serialize()
	return chainhash.DoubleHashB(b[:])
}

func (h *Header) Serialize() RawHeader {
	var rh RawHeader
	rh[0] = h.Version
	binary.BigEndian.PutUint32(rh[1:5], h.BlockNumber)
	copy(rh[5:], h.ParentEPHash[:])
	copy(rh[17:], h.PrevKeystoneEPHash[:])
	copy(rh[29:], h.StateRoot[:])
	copy(rh[61:], h.EPHash[:])
	return rh
}

func Genesis() *Header {
	return &Header{Version: HeaderVersion1}
}

func NewHeaderFromBytes(b []byte) (*Header, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("invalid header length (%d)", len(b))
	}
	h := &Header{
		Version: b[0],
	}
	switch h.Version {
	case HeaderVersion1:
		if len(b) != HeaderSize {
			return nil, fmt.Errorf("invalid header length (%d)", len(b))
		}
		h.BlockNumber = binary.BigEndian.Uint32(b[1:5])
		copy(h.ParentEPHash[:], b[5:17])
		copy(h.PrevKeystoneEPHash[:], b[17:29])
		copy(h.StateRoot[:], b[29:61])
		copy(h.EPHash[:], b[61:73])
	default:
		return nil, fmt.Errorf("unsuported version: %v", h.Version)
	}
	return h, nil
}

// L2KeystoneVersion designates hwta version of the L2 keystone we are using.
const (
	L2KeystoneAbrevVersion uint8 = 1
	L2KeystoneAbrevSize          = 76
)

// L2Keystone is the wire format of a keystone that is shared among several
// daemons.
type L2Keystone struct {
	Version            uint8         `json:"version"`
	L1BlockNumber      uint32        `json:"l1_block_number"`
	L2BlockNumber      uint32        `json:"l2_block_number"`
	ParentEPHash       api.ByteSlice `json:"parent_ep_hash"`
	PrevKeystoneEPHash api.ByteSlice `json:"prev_ep_keystone_hash"`
	StateRoot          api.ByteSlice `json:"state_root"`
	EPHash             api.ByteSlice `json:"ep_hash"`
}

// L2KeystoneAbrev is the abbreviated format of an L2Keystone. It simply clips
// various hashes to a shorter version.
type L2KeystoneAbrev struct {
	Version            uint8    // [0:1]
	L1BlockNumber      uint32   // [1:5]
	L2BlockNumber      uint32   // [5:9]
	ParentEPHash       [11]byte // [9:20]
	PrevKeystoneEPHash [12]byte // [20:32]
	StateRoot          [32]byte // [32:64]
	EPHash             [12]byte // [64:76]
}

func (a *L2KeystoneAbrev) Dump(w io.Writer) {
	fmt.Fprintf(w, "===========================\n")
	fmt.Fprintf(w, "Version                   : %v\n", a.Version)
	fmt.Fprintf(w, "L1 Block Number           : %v\n", a.L1BlockNumber)
	fmt.Fprintf(w, "L2 Block Number           : %x\n", a.L2BlockNumber)
	fmt.Fprintf(w, "Parent EP hash            : %x\n", a.ParentEPHash)
	fmt.Fprintf(w, "Previous keystone EP Hash : %x\n", a.PrevKeystoneEPHash)
	fmt.Fprintf(w, "State Root                : %x\n", a.StateRoot)
	fmt.Fprintf(w, "EP Hash                   : %x\n", a.EPHash)
	fmt.Fprintf(w, "===========================\n")
}

type RawAbreviatedL2Keystone [L2KeystoneAbrevSize]byte

func (a *L2KeystoneAbrev) Serialize() RawAbreviatedL2Keystone {
	var r RawAbreviatedL2Keystone
	r[0] = a.Version
	binary.BigEndian.PutUint32(r[1:5], a.L1BlockNumber)
	binary.BigEndian.PutUint32(r[5:9], a.L2BlockNumber)
	copy(r[9:], a.ParentEPHash[:])
	copy(r[20:], a.PrevKeystoneEPHash[:])
	copy(r[32:], a.StateRoot[:])
	copy(r[64:], a.EPHash[:])
	return r
}

func L2KeystoneAbrevDeserialize(r RawAbreviatedL2Keystone) *L2KeystoneAbrev {
	a := L2KeystoneAbrev{}

	a.Version = r[0]
	a.L1BlockNumber = binary.BigEndian.Uint32(r[1:5])
	a.L2BlockNumber = binary.BigEndian.Uint32(r[5:9])
	a.ParentEPHash = [11]byte(r[9:20])
	a.PrevKeystoneEPHash = [12]byte(r[20:32])
	a.StateRoot = [32]byte(r[32:64])
	a.EPHash = [12]byte(r[64:76])

	return &a
}

func (a *L2KeystoneAbrev) Hash() []byte {
	b := a.Serialize()
	return chainhash.DoubleHashB(b[:])
}

func HashSerializedL2KeystoneAbrev(s []byte) []byte {
	return chainhash.DoubleHashB(s)
}

func L2KeystoneAbbreviate(l2ks L2Keystone) *L2KeystoneAbrev {
	a := &L2KeystoneAbrev{
		Version:       l2ks.Version,
		L1BlockNumber: l2ks.L1BlockNumber,
		L2BlockNumber: l2ks.L2BlockNumber,
	}
	copy(a.ParentEPHash[:], l2ks.ParentEPHash)
	copy(a.PrevKeystoneEPHash[:], l2ks.PrevKeystoneEPHash)
	copy(a.StateRoot[:], l2ks.StateRoot)
	copy(a.EPHash[:], l2ks.EPHash)

	return a
}

func NewL2KeystoneAbrevFromBytes(b []byte) (*L2KeystoneAbrev, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("invalid length (%d)", len(b))
	}
	ka := &L2KeystoneAbrev{
		Version: b[0],
	}
	switch ka.Version {
	case L2KeystoneAbrevVersion:
		if len(b) != L2KeystoneAbrevSize {
			return nil, fmt.Errorf("invalid keystone sbrev length (%d)",
				len(b))
		}
		ka.L1BlockNumber = binary.BigEndian.Uint32(b[1:5])
		ka.L2BlockNumber = binary.BigEndian.Uint32(b[5:9])
		copy(ka.ParentEPHash[:], b[9:20])
		copy(ka.PrevKeystoneEPHash[:], b[20:32])
		copy(ka.StateRoot[:], b[32:64])
		copy(ka.EPHash[:], b[64:76])
	default:
		return nil, fmt.Errorf("unsuported version: %v", ka.Version)
	}
	return ka, nil
}
