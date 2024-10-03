// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"net"
	"sync"
)

const (
	maxPeersGood = 1 << 13
	maxPeersBad  = 1 << 13
)

// PeerManager keeps track of the available peers and their quality.
type PeerManager struct {
	peersMtx    sync.RWMutex
	good        map[string]struct{}
	bad         map[string]struct{}
	goodSeenMax int // keep track of max good peers seen to prevent early purge
}

// NewPeerManager returns a new peer manager.
func NewPeerManager(seeds []string) *PeerManager {
	return &PeerManager{
		good: make(map[string]struct{}, maxPeersGood),
		bad:  make(map[string]struct{}, maxPeersBad),
	}
}

// Stats returns peer statistics.
func (pm *PeerManager) Stats() (int, int) {
	log.Tracef("PeersStats")
	defer log.Tracef("PeersStats exit")

	pm.peersMtx.RLock()
	defer pm.peersMtx.RUnlock()
	return len(pm.good), len(pm.bad)
}

// PeersInsert adds known peers.
func (pm *PeerManager) HandleAddr(peers []string) error {
	log.Tracef("HandleAddr %v", len(peers))

	pm.peersMtx.Lock()
	for _, addr := range peers {
		if _, ok := pm.bad[addr]; ok {
			// Skip bad peers.
			continue
		}
		pm.good[addr] = struct{}{}
	}
	log.Debugf("PeersInsert exit %v good %v bad %v",
		len(peers), len(pm.good), len(pm.bad))
	pm.peersMtx.Unlock()

	return nil
}

// Bad marks the peer as bad.
func (pm *PeerManager) Bad(address string) error {
	log.Tracef("Bad")
	defer log.Tracef("Bad exit")

	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	pm.peersMtx.Lock()

	// Remove peer from good.
	delete(pm.good, address)
	// Mark peer as bad.
	pm.bad[address] = struct{}{}

	// Crude hammer to reset good/bad state of peers

	// XXX goodSeenMax should be a connection test; not a threshold.
	// Another reason to move all peer stuff into the manager.
	pm.goodSeenMax = max(pm.goodSeenMax, len(pm.good))
	if pm.goodSeenMax > minPeersRequired && len(pm.good) < minPeersRequired {
		// Kill all peers to force caller to reseed. This happens when
		// network is down for a while and all peers are moved into
		// bad map.
		clear(pm.good)
		clear(pm.bad)
		pm.good = make(map[string]struct{}, 8192)
		pm.bad = make(map[string]struct{}, 8192)
		pm.goodSeenMax = 0
		log.Debugf("peer cache purged")
	}
	log.Debugf("Bad exit good %v bad %v", len(pm.good), len(pm.bad))
	pm.peersMtx.Unlock()

	return nil
}

func (pm *PeerManager) PeersRandom(count int) ([]string, error) {
	log.Tracef("PeersRandom %v", count)

	i := 0
	peers := make([]string, 0, count)

	pm.peersMtx.RLock()
	for k := range pm.good {
		peers = append(peers, k)
		i++
		if i >= count {
			break
		}
	}
	log.Debugf("PeersRandom exit %v (good %v bad %v)",
		len(peers), len(pm.good), len(pm.bad))
	pm.peersMtx.RUnlock()

	return peers, nil
}
