package memory

import (
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"

	"github.com/hemilabs/heminetwork/bitcoin/wallet/zuul"
)

type memory struct {
	mtx    sync.Mutex
	params *chaincfg.Params
	keys   map[string]*zuul.NamedKey
}

var _ zuul.Zuul = (*memory)(nil)

func MemoryNew(params *chaincfg.Params) (zuul.Zuul, error) {
	m := &memory{
		params: params,
		keys:   make(map[string]*zuul.NamedKey, 10),
	}
	return m, nil
}

func (m *memory) Put(nk *zuul.NamedKey) error {
	// Generate address for lookup
	addr, err := nk.PrivateKey.Address(m.params)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.keys[addr.String()]; ok {
		return zuul.ErrKeyExists
	}
	m.keys[addr.String()] = nk
	return nil
}

func (m *memory) Get(addr btcutil.Address) (*zuul.NamedKey, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, zuul.ErrKeyDoesntExist
	}
	return nk, nil
}

func (m *memory) Purge(addr btcutil.Address) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return zuul.ErrKeyDoesntExist
	}
	delete(m.keys, addr.String())
	nk.PrivateKey.Zero()
	nk.PrivateKey = nil
	return nil
}

func (m *memory) LookupByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, false, zuul.ErrKeyDoesntExist
	}
	priv, err := nk.PrivateKey.ECPrivKey()
	if err != nil {
		return nil, false, err
	}
	return priv, true, nil
}
