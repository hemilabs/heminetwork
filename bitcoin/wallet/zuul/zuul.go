package zuul

import (
	"errors"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
)

// Zuul, a minion of the god known as Gozer, was worshiped as a demigod by the
// Sumerians, Mesopotamians and Hittites in 6000 BC.

var (
	ErrKeyExists      = errors.New("key exists")
	ErrKeyDoesntExist = errors.New("key does not exist")
)

type NamedKey struct {
	Name string // User defined name

	// Derivation path
	Account uint
	Child   uint
	HD      bool

	PrivateKey *hdkeychain.ExtendedKey
}

type Zuul interface {
	Put(nk *NamedKey) error
	Get(addr btcutil.Address) (*NamedKey, error)
	Purge(addr btcutil.Address) error
	LookupByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) // signing lookup
}
