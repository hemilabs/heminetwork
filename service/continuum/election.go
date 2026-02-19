// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"sort"

	"github.com/hemilabs/x/tss-lib/v2/tss"
)

// Elect performs a deterministic pseudorandom committee election from
// the set of candidate peers.  The seed provides shared entropy (e.g.
// block hash); all nodes using the same seed and peer set produce the
// same result.  The first element of the returned slice is the
// coordinator.
//
// Algorithm: sort candidates lexicographically, then partial
// Fisher-Yates shuffle seeded by SHA256(seed || counter).  Counter is
// a single byte (max committee size 256, sufficient for any realistic
// committee).
//
// Modulo bias: uint64 % n for n=100 gives bias ~5.4e-18.  Negligible
// for any realistic peer set.
func Elect(seed []byte, peers []Identity, committee int) ([]Identity, error) {
	if committee < 1 {
		return nil, errors.New("committee size must be >= 1")
	}
	if committee > len(peers) {
		return nil, fmt.Errorf("committee size %d exceeds peer count %d",
			committee, len(peers))
	}
	if committee > 256 {
		return nil, errors.New("committee size cannot exceed 256")
	}

	// Sort lexicographically for determinism.
	sorted := make([]Identity, len(peers))
	copy(sorted, peers)
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i][:], sorted[j][:]) < 0
	})

	// Partial Fisher-Yates: select `committee` entries.
	for i := 0; i < committee; i++ {
		h := sha256.New()
		h.Write(seed)
		h.Write([]byte{byte(i)})
		hash := h.Sum(nil)

		r := binary.BigEndian.Uint64(hash[:8])
		remaining := uint64(len(sorted) - i)
		j := i + int(r%remaining)
		sorted[i], sorted[j] = sorted[j], sorted[i]
	}

	result := make([]Identity, committee)
	copy(result, sorted[:committee])
	return result, nil
}

// IdentitiesToPartyIDs converts a slice of continuum Identities to
// tss-lib UnSortedPartyIDs.  Each PartyID uses the hex identity as
// both Id and Moniker, with the raw identity bytes as the Key.
func IdentitiesToPartyIDs(ids []Identity) tss.UnSortedPartyIDs {
	pids := make(tss.UnSortedPartyIDs, len(ids))
	for i, id := range ids {
		pids[i] = tss.NewPartyID(
			id.String(),
			id.String(),
			new(big.Int).SetBytes(id[:]),
		)
	}
	return pids
}
