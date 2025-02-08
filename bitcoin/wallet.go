package bitcoin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/mempool"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/btcwallet/wallet/txsizes"
	"github.com/tyler-smith/go-bip39"

	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/cmd/btctool/httpclient"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/pop"
)

var (
	bsMainnetURL  = "https://blockstream.info/api"
	bsTestne3tURL = "https://blockstream.info/testnet/api"
)

type FeeEstimate struct {
	Blocks      uint
	SatsPerByte float64
}

type Bitcoin interface {
	FeeEstimates(ctx context.Context) ([]FeeEstimate, error)
	UtxosByAddress(ctx context.Context, addr btcutil.Address) ([]*tbcapi.UTXO, error)
}

type blockstream struct {
	url string
}

func (bs *blockstream) FeeEstimates(ctx context.Context) ([]FeeEstimate, error) {
	u := fmt.Sprintf("%v/fee-estimates", bs.url)
	feeEstimates, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	fm := make(map[uint]float64, len(u))
	err = json.Unmarshal(feeEstimates, &fm)
	if err != nil {
		return nil, err
	}

	frv := make([]FeeEstimate, 0, len(fm))
	for k, v := range fm {
		frv = append(frv, FeeEstimate{Blocks: k, SatsPerByte: v})
	}

	return frv, nil
}

func (bs *blockstream) UtxosByAddress(ctx context.Context, addr btcutil.Address) ([]*tbcapi.UTXO, error) {
	u := fmt.Sprintf("%v/address/%v/utxo", bs.url, addr)
	utxos, err := httpclient.Request(ctx, "GET", u, nil)
	if err != nil {
		return nil, fmt.Errorf("request: %w", err)
	}

	type statusJSON struct {
		Confirmed   bool           `json:"confirmed"`
		BlockHeight uint64         `json:"block_height"`
		BlockHash   chainhash.Hash `json:"block_hash"`
		BlockTime   int64          `json:"block_time"`
	}
	type utxosJSON struct {
		TxId   chainhash.Hash `json:"txid"`
		Vout   uint32         `json:"vout"`
		Value  btcutil.Amount `json:"value"`
		Status statusJSON     `json:"status"`
	}
	var uj []utxosJSON
	err = json.Unmarshal(utxos, &uj)
	if err != nil {
		return nil, err
	}

	urv := make([]*tbcapi.UTXO, 0, len(uj))
	for _, v := range uj {
		if !v.Status.Confirmed {
			continue
		}
		urv = append(urv, &tbcapi.UTXO{
			TxId:     v.TxId,
			OutIndex: v.Vout,
			Value:    v.Value,
		})
	}
	return urv, nil
}

func BlockstreamNew(params *chaincfg.Params) (Bitcoin, error) {
	bs := &blockstream{}
	switch params {
	case &chaincfg.MainNetParams:
		bs.url = bsMainnetURL
	case &chaincfg.TestNet3Params:
		bs.url = bsTestne3tURL
	default:
		return nil, errors.New("invalid net")
	}
	return bs, nil
}

var _ Bitcoin = (*blockstream)(nil)

func BalanceFromUtxos(utxos []*tbcapi.UTXO) btcutil.Amount {
	var amount btcutil.Amount
	for k := range utxos {
		amount += btcutil.Amount(utxos[k].Value)
	}
	return amount
}

var (
	ErrExists      = errors.New("key exists")
	ErrDoesntExist = errors.New("key does not exist")
)

type NamedKey struct {
	Name string // User defined name

	// Derivation path
	Account uint
	Child   uint
	HD      bool

	PrivateKey *hdkeychain.ExtendedKey
}

type KeyStore interface {
	Put(nk *NamedKey) error
	Get(addr btcutil.Address) (*NamedKey, error)
	Purge(addr btcutil.Address) error
	LookupByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) // signing lookup
}

type memoryKeyStore struct {
	mtx    sync.Mutex
	params *chaincfg.Params
	keys   map[string]*NamedKey
}

func memoryKeyStoreNew(params *chaincfg.Params) (KeyStore, error) {
	mks := &memoryKeyStore{
		params: params,
		keys:   make(map[string]*NamedKey, 10),
	}
	return mks, nil
}

func (m *memoryKeyStore) Put(nk *NamedKey) error {
	// Generate address for lookup
	addr, err := nk.PrivateKey.Address(m.params)
	if err != nil {
		return err
	}

	m.mtx.Lock()
	defer m.mtx.Unlock()

	if _, ok := m.keys[addr.String()]; ok {
		return ErrExists
	}
	m.keys[addr.String()] = nk
	return nil
}

func (m *memoryKeyStore) Get(addr btcutil.Address) (*NamedKey, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, ErrDoesntExist
	}
	return nk, nil
}

func (m *memoryKeyStore) Purge(addr btcutil.Address) error {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return ErrDoesntExist
	}
	delete(m.keys, addr.String())
	nk.PrivateKey.Zero()
	nk.PrivateKey = nil
	return nil
}

func (m *memoryKeyStore) LookupByAddr(addr btcutil.Address) (*btcec.PrivateKey, bool, error) {
	m.mtx.Lock()
	defer m.mtx.Unlock()

	nk, ok := m.keys[addr.String()]
	if !ok {
		return nil, false, ErrDoesntExist
	}
	priv, err := nk.PrivateKey.ECPrivKey()
	if err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

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

// derive derives the public extended key and address from the account and
// child using BIP32 derivation. When offset is greater or equal to
// hdkeychain.HardenedKeyStart it returns a hardened address.
//
// Hardened addresses require the private key to derive public keys whereas a
// regular address can derive public keys without.
//
// This function uses the same paths as used in bitcoin core and electrum.
func (w *Wallet) derive(account, child, offset uint32) (*hdkeychain.ExtendedKey, error) {
	if w.master == nil {
		return nil, errors.New("wallet locked")
	}

	// Derive child key for (hardened) account.
	// E.g. hardened account 0: m/0'
	acct, err := w.master.Derive(offset + account)
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
func (w *Wallet) DeriveHD(account, child uint32) (*hdkeychain.ExtendedKey, error) {
	return w.derive(account, child, hdkeychain.HardenedKeyStart)
}

// DeriveHD derives an extended public key and address.
// E.g. account 0 child 1 m/0/1
func (w *Wallet) Derive(account, child uint32) (*hdkeychain.ExtendedKey, error) {
	return w.derive(account, child, 0)
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

// UtxoPickerSingle is a simple utxo picker that returns a random utxo from the
// provided list that has a larger value of amount + fee.
func UtxoPickerSingle(amount, fee btcutil.Amount, utxos []*tbcapi.UTXO) (*tbcapi.UTXO, error) {
	// poor mans random list
	us := make(map[int]struct{}, len(utxos))
	for k := range utxos {
		us[k] = struct{}{}
	}

	// find large enough utxo
	total := amount + fee
	for k := range us {
		if utxos[k].Value < total {
			continue
		}

		return utxos[k], nil
	}

	return nil, errors.New("no suitable utxo found")
}

func FeeByConfirmations(blocks uint, feeEstimates []FeeEstimate) (*FeeEstimate, error) {
	if len(feeEstimates) == 0 {
		return nil, errors.New("no estimates")
	}

	// We should probably add a variance check but for now be exact.
	for _, v := range feeEstimates {
		if v.Blocks == blocks {
			return &v, nil
		}
	}

	return nil, errors.New("no suitable fee estimate")
}

func PoPTransactionCreate(l2keystone *hemi.L2Keystone, locktime uint32, satsPerByte btcutil.Amount, utxos []*tbcapi.UTXO, script []byte) (*wire.MsgTx, map[string][]byte, error) {
	// Create OP_RETURN
	aks := hemi.L2KeystoneAbbreviate(*l2keystone)
	popTx := pop.TransactionL2{L2Keystone: aks}
	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		return nil, nil, fmt.Errorf("encode pop transaction: %w", err)
	}
	popTxOut := wire.NewTxOut(0, popTxOpReturn)

	// Calculate fee for 1 input and assume there is change
	txSize := txsizes.EstimateSerializeSize(1, []*wire.TxOut{popTxOut}, true)
	fee := btcutil.Amount(txSize) * satsPerByte

	// Find utxo that is big enough for entire transaction
	utxo, err := UtxoPickerSingle(0, fee, utxos) // no amount, just fees
	if err != nil {
		return nil, nil, err
	}

	// Assemble transaction
	tx := wire.NewMsgTx(2) // Latest supported version
	tx.LockTime = locktime
	outpoint := wire.NewOutPoint(&utxo.TxId, utxo.OutIndex)
	tx.AddTxIn(wire.NewTxIn(outpoint, script, nil))

	// Return previous outs to caller so that they can be signed
	prevOuts := map[string][]byte{outpoint.String(): script}

	// Change
	change := utxo.Value - fee
	changeTxOut := wire.NewTxOut(int64(change), script)
	if !mempool.IsDust(changeTxOut, mempool.DefaultMinRelayTxFee) {
		tx.AddTxOut(changeTxOut)
	}

	// OP_RETURN
	tx.AddTxOut(wire.NewTxOut(0, popTxOpReturn))

	return tx, prevOuts, nil
}

func TransactionSign(params *chaincfg.Params, ks KeyStore, tx *wire.MsgTx, prevOuts map[string][]byte) error {
	for i, txIn := range tx.TxIn {
		prevPkScript, ok := prevOuts[txIn.PreviousOutPoint.String()]
		if !ok {
			return fmt.Errorf("previous out not found: %v",
				txIn.PreviousOutPoint)
		}
		sigScript, err := txscript.SignTxOutput(params, tx, i,
			prevPkScript, txscript.SigHashAll,
			txscript.KeyClosure(ks.LookupByAddr), nil, nil)
		if err != nil {
			return err
		}
		tx.TxIn[i].SignatureScript = sigScript
	}

	return nil
}
