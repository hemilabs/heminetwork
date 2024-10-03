// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
)

const (
	maxPeersGood = 1024
	maxPeersBad  = 1024
)

var (
	testnet3Seeds = []string{
		"testnet-seed.bitcoin.jonasschnelli.ch:18333",
		"seed.tbtc.petertodd.org:18333",
		"seed.testnet.bitcoin.sprovoost.nl:18333",
		"testnet-seed.bluematt.me:18333",
	}
	mainnetSeeds = []string{
		"seed.bitcoin.sipa.be:8333",
		"dnsseed.bluematt.me:8333",
		"dnsseed.bitcoin.dashjr.org:8333",
		"seed.bitcoinstats.com:8333",
		"seed.bitnodes.io:8333",
		"seed.bitcoin.jonasschnelli.ch:8333",
	}
)

// PeerManager keeps track of the available peers and their quality.
type PeerManager struct {
	mtx sync.RWMutex

	net wire.BitcoinNet // bitcoin network to connect to

	want int // number of peers we want to be connected to

	dnsSeeds []string // hard coded dns seeds
	seeds    []string // seeds obtained from DNS

	peers map[string]*peer // connected peers
	good  map[string]struct{}
	bad   map[string]struct{}
}

// NewPeerManager returns a new peer manager.
func NewPeerManager(net wire.BitcoinNet, want int) (*PeerManager, error) {
	if want == 0 {
		return nil, errors.New("peers wanted must not be 0")
	}

	var dnsSeeds []string
	switch net {
	case wire.MainNet:
		dnsSeeds = mainnetSeeds
	case wire.TestNet3:
		dnsSeeds = testnet3Seeds
	case wire.TestNet:
	default:
		return nil, fmt.Errorf("invalid network: %v", net)
	}

	return &PeerManager{
		net:      net,
		want:     want,
		dnsSeeds: dnsSeeds,
		good:     make(map[string]struct{}, maxPeersGood),
		bad:      make(map[string]struct{}, maxPeersBad),
		peers:    make(map[string]*peer, want),
	}, nil
}

func (pm *PeerManager) String() string {
	pm.mtx.RLock()
	defer pm.mtx.RUnlock()

	return fmt.Sprintf("connected %v good %v bad %v",
		len(pm.peers), len(pm.good), len(pm.bad))
}

func (pm *PeerManager) seed(pctx context.Context) error {
	log.Tracef("seed")
	defer log.Tracef("seed exit")

	// Seed
	resolver := &net.Resolver{}
	ctx, cancel := context.WithTimeout(pctx, 15*time.Second)
	defer cancel()

	errorsSeen := 0
	for _, v := range pm.dnsSeeds {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			log.Errorf("Failed to parse host/port: %v", err)
			errorsSeen++
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			log.Errorf("lookup: %v", err)
			errorsSeen++
			continue
		}

		for _, ip := range ips {
			address := net.JoinHostPort(ip.String(), port)
			pm.seeds = append(pm.seeds, address)
		}
	}

	if len(pm.seeds) == 0 {
		return errors.New("could not dns seed")
	}

	return nil
}

// Stats returns peer statistics.
func (pm *PeerManager) Stats() (int, int, int) {
	log.Tracef("PeersStats")
	defer log.Tracef("PeersStats exit")

	pm.mtx.RLock()
	defer pm.mtx.RUnlock()
	return len(pm.peers), len(pm.good), len(pm.bad)
}

func (pm *PeerManager) handleAddr(peers []string) {
	for _, addr := range peers {
		_, _, err := net.SplitHostPort(addr)
		if err != nil {
			continue
		}
		if _, ok := pm.peers[addr]; ok {
			// Skip connected peers.
			continue
		}
		if _, ok := pm.bad[addr]; ok {
			// Skip bad peers.
			continue
		}
		pm.good[addr] = struct{}{}
	}
	log.Debugf("HandleAddr exit %v good %v bad %v",
		len(peers), len(pm.good), len(pm.bad))
}

// HandleAddr adds peers to good list.
func (pm *PeerManager) HandleAddr(peers []string) {
	log.Tracef("HandleAddr %v", len(peers))

	pm.mtx.Lock()
	defer pm.mtx.Unlock()
	pm.handleAddr(peers)
}

// Good adds peer good list.
func (pm *PeerManager) Good(address string) error {
	log.Tracef("Good")
	defer log.Tracef("Good exit")

	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	pm.mtx.Lock()
	defer pm.mtx.Unlock()

	// If peer is connected don't add it to good list
	if _, ok := pm.peers[address]; ok {
		return fmt.Errorf("peer active: %v", address)
	}

	// Remove peer from bad.
	delete(pm.bad, address)
	// Add peer to good.
	pm.good[address] = struct{}{}

	log.Debugf("Good exit peers %v good %v bad %v",
		len(pm.peers), len(pm.good), len(pm.bad))

	return nil
}

func (pm *PeerManager) Connected(p *peer) {
	log.Tracef("Connected")
	defer log.Tracef("Connected exit")

	address := p.String()

	pm.mtx.Lock()
	defer pm.mtx.Unlock()

	// If peer is connected, ignore it
	if _, ok := pm.peers[address]; !ok {
		pm.peers[address] = p
	}
	delete(pm.bad, address)
	delete(pm.good, address)

	log.Debugf("Connected exit peers %v good %v bad %v",
		len(pm.peers), len(pm.good), len(pm.bad))
}

// Bad marks the peer as bad.
func (pm *PeerManager) Bad(address string) error {
	log.Tracef("Bad")
	defer log.Tracef("Bad exit")

	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	pm.mtx.Lock()

	// If peer is connected, disconnect it and mark it bad
	if p, ok := pm.peers[address]; ok {
		if p != nil {
			p.close()
		}
		delete(pm.peers, address)
	}

	// Remove peer from good.
	delete(pm.good, address)
	// Mark peer as bad.
	pm.bad[address] = struct{}{}

	log.Debugf("Bad exit peers %v good %v bad %v",
		len(pm.peers), len(pm.good), len(pm.bad))

	pm.mtx.Unlock()

	return nil
}

func (pm *PeerManager) Random() (*peer, error) {
	log.Tracef("Random")
	defer log.Tracef("Random exit")

	pm.mtx.RLock()
	pm.mtx.RUnlock()
	for _, p := range pm.peers {
		if p.isConnected() {
			return p, nil
		}
	}

	return nil, errors.New("no peers")
}

func (pm *PeerManager) RandomConnect(ctx context.Context) (*peer, error) {
	log.Tracef("RandomConnect")
	defer log.Tracef("RandomConnect")

	// Block until a connect slot opens up
	for {
		log.Debugf("peer manager: %v", pm)
		address := ""
		pm.mtx.Lock()

		// XXX add reset caluse
		//if len(pm.peers) < pm.want {
		//	// Check to see if we are out of good peers
		//	if len(pm.peers) == 0 && len(pm.good) == 0 && len(pm.bad) > 0 {
		//		log.Infof("RESET, needs flag")
		//		clear(pm.good)
		//		clear(pm.bad)
		//		pm.handleAddr(pm.seeds)
		//	}
		//	for k := range pm.good {
		//		address = k
		//		delete(pm.good, k)
		//	}
		//}
		for k := range pm.good {
			address = k
			continue
		}
		pm.mtx.Unlock()

		if len(address) > 0 {
			// connect peer
			p, err := NewPeer(pm.net, address)
			if err != nil {
				// XXX can't happen, remove error case from NewPeer
				log.Errorf("%v", err)
				continue
			}
			err = p.connect(ctx)
			if err != nil {
				pm.Bad(address)
				continue
			}
			pm.Connected(p)
			return p, nil
		}

		// Block but do timeout to see if something was reaped
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(3 * time.Second):
		}
	}
	// NewPeer(pm.net, address)
	return nil, errors.New("nope")
}

func (pm *PeerManager) Run(ctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run")

	log.Infof("Starting DNS seeder")
	minW := 5
	maxW := 59
	for {
		err := pm.seed(ctx)
		if err != nil {
			log.Debugf("seed: %v", err)
		} else {
			break
		}

		holdOff := time.Duration(minW+rand.IntN(maxW-minW)) * time.Second
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(holdOff):
		}
	}
	pm.HandleAddr(pm.seeds) // Add all seeds to good list
	log.Infof("DNS seeding complete")

	log.Infof("Starting peer manager")
	defer log.Infof("Peer manager stopped")

	select {
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}
