// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrumx

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"
	"github.com/sethvargo/go-retry"

	"github.com/hemilabs/heminetwork/bitcoin"
)

// https://electrumx.readthedocs.io/en/latest/protocol-basics.html

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      uint64          `json:"id"`
}

// NewJSONRPCRequest creates a new JSONRPCRequest.
func NewJSONRPCRequest(id uint64, method string, params any) (*JSONRPCRequest, error) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		ID:      id,
	}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("marshal params: %w", err)
		}
		req.Params = b
	}
	return req, nil
}

type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	Error   *JSONRPCError   `json:"error,omitempty"`
	Result  json.RawMessage `json:"result"`
	ID      uint64          `json:"id"`
}

func NewJSONRPCError(code int, msg string) *JSONRPCError {
	return &JSONRPCError{Code: code, Message: msg}
}

type RPCError string

func (e RPCError) Error() string {
	return string(e)
}

type BlockNotOnDiskError struct {
	err error
}

func NewBlockNotOnDiskError(err error) BlockNotOnDiskError {
	return BlockNotOnDiskError{err: err}
}

func (e BlockNotOnDiskError) Error() string {
	return e.err.Error()
}

func (e BlockNotOnDiskError) Is(target error) bool {
	_, ok := target.(BlockNotOnDiskError)
	return ok
}

func (e BlockNotOnDiskError) Unwrap() error {
	return e.err
}

type NoTxAtPositionError struct {
	err error
}

func NewNoTxAtPositionError(err error) NoTxAtPositionError {
	return NoTxAtPositionError{err: err}
}

func (e NoTxAtPositionError) Error() string {
	return e.err.Error()
}

func (e NoTxAtPositionError) Is(target error) bool {
	_, ok := target.(NoTxAtPositionError)
	return ok
}

func (e NoTxAtPositionError) Unwrap() error {
	return e
}

var (
	ErrBlockNotOnDisk = NewBlockNotOnDiskError(errors.New("block not on disk"))
	ErrNoTxAtPosition = NewNoTxAtPositionError(errors.New("no tx at position"))
)

// Client implements an electrumx JSON RPC client.
type Client struct {
	connPool *connPool
}

var log = loggo.GetLogger("electrumx")

const (
	clientInitialConnections = 2
	clientMaximumConnections = 5
)

// NewClient returns an initialised electrumx client.
func NewClient(address string, initialConns, maxConns int) (*Client, error) {
	c := &Client{}

	// The address may be empty during tests, ignore empty addresses.
	if address != "" {
		pool, err := newConnPool("tcp", address, initialConns, maxConns)
		if err != nil {
			return nil, fmt.Errorf("new connection pool: %w", err)
		}
		c.connPool = pool
	}

	return c, nil
}

func (c *Client) call(ctx context.Context, method string, params, result any) error {
	if c.connPool == nil {
		// connPool may be nil if the address given to NewClient is empty.
		return errors.New("connPool is nil")
	}

	backoff := retry.WithJitter(250*time.Millisecond,
		retry.WithMaxRetries(5, retry.NewExponential(100*time.Millisecond)))
	return retry.Do(ctx, backoff, func(ctx context.Context) error {
		conn, err := c.connPool.acquireConn()
		if err != nil {
			return retry.RetryableError(fmt.Errorf("acquire connection: %w", err))
		}

		if err = conn.call(ctx, method, params, result); err != nil {
			if errors.Is(err, net.ErrClosed) {
				return retry.RetryableError(err)
			}
			c.connPool.freeConn(conn)
			return err
		}

		c.connPool.freeConn(conn)
		return nil
	})
}

// Close closes the client.
func (c *Client) Close() error {
	if c.connPool != nil {
		return c.connPool.Close()
	}
	return nil
}

type Balance struct {
	Confirmed   uint64 `json:"confirmed"`
	Unconfirmed int64  `json:"unconfirmed"`
}

type HeaderNotification struct {
	Height       uint64 `json:"height"`
	BinaryHeader string `json:"hex"`
}

type exUTXO struct {
	Hash   string `json:"tx_hash"`
	Height uint64 `json:"height"`
	Index  uint64 `json:"tx_pos"`
	Value  uint64 `json:"value"`
}

type UTXO struct {
	Hash   []byte
	Height uint64
	Index  uint32
	Value  int64
}

func (c *Client) Balance(ctx context.Context, scriptHash []byte) (*Balance, error) {
	hash, err := btcchainhash.NewHash(scriptHash)
	if err != nil {
		return nil, fmt.Errorf("invalid script hash: %w", err)
	}
	params := struct {
		ScriptHash string `json:"scripthash"`
	}{
		ScriptHash: hash.String(),
	}
	var balance Balance
	if err := c.call(ctx, "blockchain.scripthash.get_balance", &params, &balance); err != nil {
		return nil, err
	}
	return &balance, nil
}

func (c *Client) Broadcast(ctx context.Context, rtx []byte) ([]byte, error) {
	params := struct {
		RawTx string `json:"raw_tx"`
	}{
		RawTx: hex.EncodeToString(rtx),
	}
	var txHashStr string
	if err := c.call(ctx, "blockchain.transaction.broadcast", &params, &txHashStr); err != nil {
		return nil, err
	}
	txHash, err := btcchainhash.NewHashFromStr(txHashStr)
	if err != nil {
		return nil, fmt.Errorf("decode transaction hash: %w", err)
	}
	return txHash[:], nil
}

func (c *Client) Height(ctx context.Context) (uint64, error) {
	// TODO: The way this function is used could be improved.
	//  "blockchain.headers.subscribe" subscribes to receive notifications from
	//  the ElectrumX server, however this function appears to be used for
	//  polling instead, which could be replaced by handling the requests sent
	//  from the ElectrumX server.
	hn := &HeaderNotification{}
	if err := c.call(ctx, "blockchain.headers.subscribe", nil, hn); err != nil {
		return 0, err
	}
	return hn.Height, nil
}

func (c *Client) RawBlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	params := struct {
		Height   uint64 `json:"height"`
		CPHeight uint64 `json:"cp_height"`
	}{
		Height:   height,
		CPHeight: 0,
	}
	var rbhStr string
	if err := c.call(ctx, "blockchain.block.header", &params, &rbhStr); err != nil {
		return nil, fmt.Errorf("get block header: %w", err)
	}
	rbh, err := hex.DecodeString(rbhStr)
	if err != nil {
		return nil, fmt.Errorf("decode raw block header: %w", err)
	}
	return bitcoin.RawBlockHeaderFromSlice(rbh)
}

func (c *Client) RawTransaction(ctx context.Context, txHash []byte) ([]byte, error) {
	hash, err := btcchainhash.NewHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hash: %w", err)
	}
	params := struct {
		TXHash  string `json:"tx_hash"`
		Verbose bool   `json:"verbose"`
	}{
		TXHash:  hash.String(),
		Verbose: false,
	}
	var rtxStr string
	if err := c.call(ctx, "blockchain.transaction.get", &params, &rtxStr); err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}
	rtx, err := hex.DecodeString(rtxStr)
	if err != nil {
		return nil, fmt.Errorf("decode raw transaction: %w", err)
	}
	return rtx, nil
}

func (c *Client) Transaction(ctx context.Context, txHash []byte) ([]byte, error) {
	hash, err := btcchainhash.NewHash(txHash)
	if err != nil {
		return nil, fmt.Errorf("invalid transaction hash: %w", err)
	}
	params := struct {
		TXHash  string `json:"tx_hash"`
		Verbose bool   `json:"verbose"`
	}{
		TXHash:  hash.String(),
		Verbose: true,
	}
	var txJSON json.RawMessage
	if err := c.call(ctx, "blockchain.transaction.get", &params, &txJSON); err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}
	return txJSON, nil
}

func (c *Client) TransactionAtPosition(ctx context.Context, height, index uint64) ([]byte, []string, error) {
	params := struct {
		Height uint64 `json:"height"`
		TXPos  uint64 `json:"tx_pos"`
		Merkle bool   `json:"merkle"`
	}{
		Height: height,
		TXPos:  index,
		Merkle: true,
	}
	result := struct {
		TXHash string   `json:"tx_hash"`
		Merkle []string `json:"merkle"`
	}{}
	if err := c.call(ctx, "blockchain.transaction.id_from_pos", &params, &result); err != nil {
		if strings.HasPrefix(err.Error(), "no tx at position ") {
			return nil, nil, NewNoTxAtPositionError(err)
		} else if strings.HasPrefix(err.Error(), "db error: DBError('block ") && strings.Contains(err.Error(), " not on disk ") {
			return nil, nil, NewBlockNotOnDiskError(err)
		}
		return nil, nil, fmt.Errorf("get transaction from block: %w", err)
	}

	txHash, err := btcchainhash.NewHashFromStr(result.TXHash)
	if err != nil {
		return nil, nil, fmt.Errorf("decode transaction hash: %w", err)
	}

	return txHash[:], result.Merkle, nil
}

func (c *Client) UTXOs(ctx context.Context, scriptHash []byte) ([]*UTXO, error) {
	hash, err := btcchainhash.NewHash(scriptHash)
	if err != nil {
		return nil, fmt.Errorf("invalid script hash: %w", err)
	}
	params := struct {
		ScriptHash string `json:"scripthash"`
	}{
		ScriptHash: hash.String(),
	}
	var eutxos []*exUTXO
	if err := c.call(ctx, "blockchain.scripthash.listunspent", &params, &eutxos); err != nil {
		return nil, err
	}
	var utxos []*UTXO
	for _, eutxo := range eutxos {
		hash, err := btcchainhash.NewHashFromStr(eutxo.Hash)
		if err != nil {
			return nil, fmt.Errorf("decode UTXO hash: %w", err)
		}
		utxos = append(utxos, &UTXO{
			Hash:   hash[:],
			Height: eutxo.Height,
			Index:  uint32(eutxo.Index),
			Value:  int64(eutxo.Value),
		})
	}
	return utxos, nil
}
