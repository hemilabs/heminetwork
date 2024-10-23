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

	ErrReset            = errors.New("reset")
	ErrNoAddresses      = errors.New("no addresses")
	ErrDNSSeed          = errors.New("could not dns seed")
	ErrNoConnectedPeers = errors.New("no connected peers")
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

	peersC chan *peer // blocking channel for RandomConnect
	slotsC chan int
}

// NewPeerManager returns a new peer manager.
func NewPeerManager(net wire.BitcoinNet, seeds []string, want int) (*PeerManager, error) {
	if want < 1 {
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
		seeds:    seeds,
		good:     make(map[string]struct{}, maxPeersGood),
		bad:      make(map[string]struct{}, maxPeersBad),
		peers:    make(map[string]*peer, want),
		peersC:   make(chan *peer, 0),
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

	for _, v := range pm.dnsSeeds {
		host, port, err := net.SplitHostPort(v)
		if err != nil {
			log.Errorf("Failed to parse host/port: %v", err)
			continue
		}
		ips, err := resolver.LookupIP(ctx, "ip", host)
		if err != nil {
			log.Errorf("lookup: %v", err)
			continue
		}

		for _, ip := range ips {
			address := net.JoinHostPort(ip.String(), port)
			pm.seeds = append(pm.seeds, address)
		}
	}

	if len(pm.seeds) == 0 {
		return ErrDNSSeed
	}

	return nil
}

// Stats returns peer statistics.
func (pm *PeerManager) Stats() (int, int, int) {
	log.Tracef("Stats")
	defer log.Tracef("Stats exit")

	pm.mtx.RLock()
	defer pm.mtx.RUnlock()
	return len(pm.peers), len(pm.good), len(pm.bad)
}

// handleAddr adds peers to the good list if they do not exist in the connected
// and bad list.
// Note that this function requires the mutex to be held.
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

// Good adds peer to good list if it does not exist in connected and good list already.
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
	if _, ok := pm.good[address]; ok {
		return fmt.Errorf("peer good: %v", address)
	}

	// Remove peer from bad.
	delete(pm.bad, address)
	// Add peer to good.
	pm.good[address] = struct{}{}

	log.Debugf("Good exit peers %v good %v bad %v",
		len(pm.peers), len(pm.good), len(pm.bad))

	return nil
}

// Bad marks the peer as bad.
func (pm *PeerManager) Bad(ctx context.Context, address string) error {
	log.Tracef("Bad %v", address)
	defer log.Tracef("Bad exit")

	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}

	pm.mtx.Lock()

	// If peer is connected, disconnect it and mark it bad
	if p, ok := pm.peers[address]; ok {
		if p != nil {
			// if we don't have a peer we are going to starve the slots
			log.Debugf("got address without peer: %v", address)
			p.close()
			go func() {
				// Run outside of mutex
				select {
				case <-ctx.Done():
				case pm.slotsC <- p.Id():
				}
			}()
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

// Random returns a random connected peer.
func (pm *PeerManager) Random() (*peer, error) {
	log.Tracef("Random")
	defer log.Tracef("Random exit")

	pm.mtx.RLock()
	defer pm.mtx.RUnlock()

	for _, p := range pm.peers {
		if p.isConnected() {
			return p, nil
		}
	}

	return nil, ErrNoConnectedPeers
}

// All runs a call back on all connected peers.
func (pm *PeerManager) All(ctx context.Context, f func(ctx context.Context, p *peer)) {
	log.Tracef("All")
	defer log.Tracef("All")

	pm.mtx.RLock()
	defer pm.mtx.RUnlock()
	for _, p := range pm.peers {
		if !p.isConnected() {
			continue
		}
		go f(ctx, p)
	}
}

func (pm *PeerManager) AllBlock(ctx context.Context, f func(ctx context.Context, p *peer)) {
	log.Tracef("AllBlock")
	defer log.Tracef("AllBlock")

	var wgAll sync.WaitGroup

	pm.mtx.RLock()
	for _, p := range pm.peers {
		if !p.isConnected() {
			continue
		}
		wgAll.Add(1)
		go func() {
			defer wgAll.Done()
			f(ctx, p)
		}()
	}
	pm.mtx.RUnlock()

	log.Infof("AllBlock waiting")
	wgAll.Wait()
}

// RandomConnect blocks until there is a peer ready to use.
func (pm *PeerManager) RandomConnect(ctx context.Context) (*peer, error) {
	log.Tracef("RandomConnect")
	defer log.Tracef("RandomConnect")

	// Block until a connect slot opens up
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case p := <-pm.peersC:
		return p, nil
	}
}

func (pm *PeerManager) randomPeer(ctx context.Context, slot int) (*peer, error) {
	pm.mtx.Lock()
	defer pm.mtx.Unlock()

	// Reset caluse
	// log.Infof("good %v bad %v seeds %v", len(pm.good), len(pm.bad), len(pm.seeds))
	if len(pm.good) < len(pm.seeds) && len(pm.bad) >= len(pm.seeds) {
		// Return an error to make the caller aware that we have reset
		// back to seeds.
		clear(pm.bad)
		pm.handleAddr(pm.seeds)
		return nil, ErrReset
	}
	for k := range pm.good {
		if _, ok := pm.peers[k]; ok {
			// Address is in use
			log.Debugf("address already on peers list: %v", k)
			continue
		}
		if _, ok := pm.bad[k]; ok {
			// Should not happen but let's make sure we aren't
			// reusing an address.
			log.Errorf("found addres on bad list: %v", k)
			continue
		}

		// Remove from good list and add to bad list. Thus active peers
		// are len(bad)-len(peers)
		delete(pm.good, k)
		pm.bad[k] = struct{}{}

		return NewPeer(pm.net, slot, k)
	}
	return nil, ErrNoAddresses
}

func (pm *PeerManager) connect(ctx context.Context, p *peer) error {
	log.Tracef("connect: %v %v", p.Id(), p)
	defer log.Tracef("connect exit: %v %v", p.Id(), p)

	if err := p.connect(ctx); err != nil {
		return fmt.Errorf("new peer: %v", err)
	}

	pm.mtx.Lock()
	if _, ok := pm.peers[p.String()]; ok {
		// This race does indeed happen because Good can add this.
		p.close() // close new peer and don't add it
		log.Errorf("peer already connected: %v", p)
		pm.mtx.Unlock()
		return fmt.Errorf("peer already connected: %v", p)
	}
	pm.peers[p.String()] = p
	pm.mtx.Unlock()

	pm.peersC <- p // block

	return nil
}

func (pm *PeerManager) connectSlot(ctx context.Context, p *peer) {
	if err := pm.connect(ctx, p); err != nil {
		// log.Errorf("%v", err)
		pm.slotsC <- p.Id() // give slot back
		return
	}
}

func (pm *PeerManager) Run(ctx context.Context) error {
	log.Tracef("Run")
	defer log.Tracef("Run")

	if len(pm.seeds) == 0 {
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
		log.Infof("DNS seeding complete")
	}
	pm.HandleAddr(pm.seeds) // Add all seeds to good list

	log.Infof("Starting peer manager")
	defer log.Infof("Peer manager stopped")

	// Start connecting "want" number of peers.
	pm.slotsC = make(chan int, pm.want)
	for i := 0; i < pm.want; i++ {
		pm.slotsC <- i
	}
	for {
		select {
		case slot := <-pm.slotsC:
			p, err := pm.randomPeer(ctx, slot)
			if err != nil {
				// basically no addresses, hold-off
				<-time.After(7 * time.Second)
				pm.slotsC <- slot // give the slot back
				continue
			}
			go pm.connectSlot(ctx, p)

		case <-ctx.Done():
			log.Infof("exit")
			return ctx.Err()
		}
	}
}
