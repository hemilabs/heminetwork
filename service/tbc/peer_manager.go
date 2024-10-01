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
	peersGood   map[string]struct{}
	peersBad    map[string]struct{}
	goodSeenMax int // keep track of max good peers seen to prevent early purge
}

// newPeerManager returns a new peer manager.
func newPeerManager() *PeerManager {
	return &PeerManager{
		peersGood: make(map[string]struct{}, maxPeersGood),
		peersBad:  make(map[string]struct{}, maxPeersBad),
	}
}

// Stats returns peer statistics.
func (pm *PeerManager) Stats() (int, int) {
	log.Tracef("PeersStats")
	defer log.Tracef("PeersStats exit")

	pm.peersMtx.RLock()
	defer pm.peersMtx.RUnlock()
	return len(pm.peersGood), len(pm.peersBad)
}

// PeersInsert adds known peers.
func (pm *PeerManager) PeersInsert(peers []string) error {
	log.Tracef("PeersInsert")
	defer log.Tracef("PeersInsert exit")

	pm.peersMtx.Lock()
	for _, addr := range peers {
		if _, ok := pm.peersBad[addr]; ok {
			// Skip bad peers.
			continue
		}
		pm.peersGood[addr] = struct{}{}
	}
	allGoodPeers := len(pm.peersGood)
	allBadPeers := len(pm.peersBad)
	pm.peersMtx.Unlock()

	log.Debugf("PeersInsert exit %v good %v bad %v",
		len(peers), allGoodPeers, allBadPeers)

	return nil
}

// PeerDelete marks the peer as bad.
// XXX this function only returns nil!?
func (pm *PeerManager) PeerDelete(address string) error {
	log.Tracef("PeerDelete")
	defer log.Tracef("PeerDelete exit")

	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	pm.peersMtx.Lock()

	// Remove peer from good.
	delete(pm.peersGood, address)
	// Mark peer as bad.
	pm.peersBad[address] = struct{}{}

	// Crude hammer to reset good/bad state of peers

	// XXX goodSeenMax should be a connection test; not a threshold.
	// Another reason to move all peer stuff into the manager.
	pm.goodSeenMax = max(pm.goodSeenMax, len(pm.peersGood))
	if pm.goodSeenMax > minPeersRequired && len(pm.peersGood) < minPeersRequired {
		// Kill all peers to force caller to reseed. This happens when
		// network is down for a while and all peers are moved into
		// bad map.
		clear(pm.peersGood)
		clear(pm.peersBad)
		pm.peersGood = make(map[string]struct{}, 8192)
		pm.peersBad = make(map[string]struct{}, 8192)
		pm.goodSeenMax = 0
		log.Debugf("peer cache purged")
	}

	allGoodPeers := len(pm.peersGood)
	allBadPeers := len(pm.peersBad)

	pm.peersMtx.Unlock()

	log.Debugf("PeerDelete exit good %v bad %v", allGoodPeers, allBadPeers)

	return nil
}

func (pm *PeerManager) PeersRandom(count int) ([]string, error) {
	log.Tracef("PeersRandom")

	i := 0
	peers := make([]string, 0, count)

	pm.peersMtx.RLock()
	allGoodPeers := len(pm.peersGood)
	allBadPeers := len(pm.peersBad)
	for k := range pm.peersGood {
		peers = append(peers, k)
		i++
		if i >= count {
			break
		}
	}
	pm.peersMtx.RUnlock()

	log.Debugf("PeersRandom exit %v (good %v bad %v)", len(peers),
		allGoodPeers, allBadPeers)

	return peers, nil
}
