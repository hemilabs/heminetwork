package bitcoin

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip39"
)

func zero(s []byte) {
	for k := range s {
		s[k] ^= s[k]
	}
}

type Wallet struct {
	mtx sync.Mutex

	params *chaincfg.Params

	// secret information
	master *hdkeychain.ExtendedKey
}

func WalletNew(params *chaincfg.Params) (*Wallet, error) {
	w := &Wallet{
		params: params,
	}
	return w, nil
}

func (w *Wallet) Lock() error {
	if w.master == nil {
		return errors.New("wallet already locked")
	}

	w.mtx.Lock()
	w.master.Zero()
	w.master = nil
	w.mtx.Unlock()

	return nil
}

// Secret unlocks the wallet by deriving a seed from the provided secret.
// Supports xprv, hex encoded seed and mnemonic.
func (w *Wallet) Unlock(secret string) error {
	w.mtx.Lock()
	defer w.mtx.Unlock()
	if w.master != nil {
		return fmt.Errorf("wallet already unlocked")
	}

	switch {
	case strings.HasPrefix(secret, "0x"):
		secret = secret[2:]
	case strings.HasPrefix(secret, "xpub"):
		return fmt.Errorf("not an extended private key")
	case strings.HasPrefix(secret, "xprv"):
		var err error
		w.master, err = hdkeychain.NewKeyFromString(secret)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try hex first, if this works it's a seed
	seed, err := hex.DecodeString(secret)
	if err == nil {
		// we got a seed
		w.master, err = hdkeychain.NewMaster(seed, w.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try mnemonic
	seed, err = bip39.NewSeedWithErrorChecking(secret, "")
	if err == nil {
		// we got a seed
		w.master, err = hdkeychain.NewMaster(seed, w.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	return err
}

func (w *Wallet) DeriveHD(account, extended uint32) (*btcutil.AddressPubKeyHash, *hdkeychain.ExtendedKey, error) {
	if w.master == nil {
		return nil, nil, errors.New("wallet locked")
	}

	// Derive extended key for hardened account 0: m/0'
	acct, err := w.master.Derive(hdkeychain.HardenedKeyStart + account)
	if err != nil {
		return nil, nil, err
	}

	// Derive extended key for external hardened account 0 m/0'/0'
	ek, err := acct.Derive(hdkeychain.HardenedKeyStart + extended)
	if err != nil {
		return nil, nil, err
	}

	// Generate address
	addr, err := ek.Address(w.params)
	if err != nil {
		return nil, nil, err
	}

	// Generate pubkey
	pub, err := ek.Neuter()
	if err != nil {
		return nil, nil, err
	}

	return addr, pub, nil
}

func Compressed(pub *hdkeychain.ExtendedKey) ([]byte, error) {
	ecpub, err := pub.ECPubKey()
	if err != nil {
		return nil, err
	}
	return ecpub.SerializeCompressed(), nil
}
