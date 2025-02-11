package vinzclortho

// Vinz Clortho, a minion of the god known as Gozer, was worshiped as a demigod
// by the Sumerians, Mesopotamians and Hittites in 6000 BC.
import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip39"
)

type VinzClortho struct {
	mtx sync.Mutex

	params *chaincfg.Params

	// secret information
	master *hdkeychain.ExtendedKey
}

func VinzClorthoNew(params *chaincfg.Params) (*VinzClortho, error) {
	vc := &VinzClortho{
		params: params,
	}
	return vc, nil
}

func (vc *VinzClortho) Lock() error {
	if vc.master == nil {
		return errors.New("wallet already locked")
	}

	vc.mtx.Lock()
	vc.master.Zero()
	vc.master = nil
	vc.mtx.Unlock()

	return nil
}

// Secret unlocks the wallet by deriving a seed from the provided secret.
// Supports xprv, hex encoded seed and mnemonic.
func (vc *VinzClortho) Unlock(secret string) error {
	vc.mtx.Lock()
	defer vc.mtx.Unlock()
	if vc.master != nil {
		return fmt.Errorf("wallet already unlocked")
	}

	switch {
	case strings.HasPrefix(secret, "0x"):
		secret = secret[2:]
	case strings.HasPrefix(secret, "xpub"):
		return fmt.Errorf("not an extended private key")
	case strings.HasPrefix(secret, "xprv"):
		var err error
		vc.master, err = hdkeychain.NewKeyFromString(secret)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try hex first, if this works it's a seed
	seed, err := hex.DecodeString(secret)
	if err == nil {
		// we got a seed
		vc.master, err = hdkeychain.NewMaster(seed, vc.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	// try mnemonic
	seed, err = bip39.NewSeedWithErrorChecking(secret, "")
	if err == nil {
		// we got a seed
		vc.master, err = hdkeychain.NewMaster(seed, vc.params)
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		return nil
	}

	return err
}

// derive derives the public extended key and address from the account and
// child using BIP32 derivation. When offset is greater or equal to
// hdkeychain.HardenedKeyStart it returns a hardened address.
//
// Hardened addresses require the private key to derive public keys whereas a
// regular address can derive public keys without.
//
// This function uses the same paths as used in bitcoin core and electrum.
func (vc *VinzClortho) derive(account, child, offset uint32) (*hdkeychain.ExtendedKey, error) {
	if vc.master == nil {
		return nil, errors.New("wallet locked")
	}

	// Derive child key for (hardened) account.
	// E.g. hardened account 0: m/0'
	acct, err := vc.master.Derive(offset + account)
	if err != nil {
		return nil, err
	}

	// Derive child key for external (hardened) account.
	// E.g. hardened account 0 external 0 -> m/0'/0'
	ek, err := acct.Derive(offset + child)
	if err != nil {
		return nil, err
	}

	return ek, nil
}

// DeriveHD derives a hardened extended public key and address.
// E.g. account 1 child 4 m/1'/4'
func (vc *VinzClortho) DeriveHD(account, child uint32) (*hdkeychain.ExtendedKey, error) {
	return vc.derive(account, child, hdkeychain.HardenedKeyStart)
}

// DeriveHD derives an extended public key and address.
// E.g. account 0 child 1 m/0/1
func (vc *VinzClortho) Derive(account, child uint32) (*hdkeychain.ExtendedKey, error) {
	return vc.derive(account, child, 0)
}

// AddressAndPublicFromExtended returns the public bits from a private extended
// key.
func AddressAndPublicFromExtended(params *chaincfg.Params, ek *hdkeychain.ExtendedKey) (btcutil.Address, *hdkeychain.ExtendedKey, error) {
	// Generate address
	addr, err := ek.Address(params)
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

// Compresses converts an extended key to the compressed public key representation.
func Compressed(pub *hdkeychain.ExtendedKey) ([]byte, error) {
	ecpub, err := pub.ECPubKey()
	if err != nil {
		return nil, err
	}
	return ecpub.SerializeCompressed(), nil
}

// ScriptFromPubKeyHash creates a spend script for the specified address.
func ScriptFromPubKeyHash(pkh btcutil.Address) ([]byte, error) {
	payToScript, err := txscript.PayToAddrScript(pkh)
	if err != nil {
		return nil, err
	}
	return payToScript, nil
}

// ScriptHashFromScript returns the script hash of the provided script. Note
// that this is a simple sha256 wrapped in a chainhash.Hash.
func ScriptHashFromScript(pkscript []byte) chainhash.Hash {
	return chainhash.Hash(sha256.Sum256(pkscript))
}
