// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package electrs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"

	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/juju/loggo"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sethvargo/go-retry"

	"github.com/hemilabs/heminetwork/bitcoin"
)

var log = loggo.GetLogger("electrs")

// Prometheus subsystem name.
const promSubsystem = "electrs"

// https://github.com/romanz/electrs

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
	Error   string          `json:"error,omitempty"`
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

// Client implements an electrs JSON RPC client.
type Client struct {
	connPool *connPool
	metrics  *metrics
}

var (
	defaultInitialConnections = 2
	defaultMaxConnections     = 10
)

type ClientOptions struct {
	// InitialConnections is the number of initial Electrs connections to open
	// and keep in the pool.
	InitialConnections int

	// MaxConnections is the maximum number of Electrs connections to keep in
	// the pool.
	//
	// If adding a connection back to the pool would result in the pool having
	// more connections than this value, the connection will be closed instead
	// of being added to the pool.
	MaxConnections int

	// PromNamespace is the application Prometheus namespace.
	PromNamespace string
}

type metrics struct {
	connsOpen        prometheus.Gauge         // Number of open connections
	connsIdle        prometheus.Gauge         // Number of idle connections
	connsOpened      prometheus.Counter       // Total number of connections opened
	connsClosed      prometheus.Counter       // Total number of connections closed
	rpcCallsTotal    *prometheus.CounterVec   // Total number of RPC calls
	rpcCallsDuration *prometheus.HistogramVec // RPC call durations in seconds
}

func newMetrics(namespace string) *metrics {
	return &metrics{
		connsOpen: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: promSubsystem,
			Name:      "connections_open",
			Help:      "Number of open Electrs connections",
		}),
		connsIdle: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: promSubsystem,
			Name:      "connections_idle",
			Help:      "Number of idle Electrs connections",
		}),
		connsOpened: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: promSubsystem,
			Name:      "connections_opened_total",
			Help:      "Total number of Electrs connections opened",
		}),
		connsClosed: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: promSubsystem,
			Name:      "connections_closed_total",
			Help:      "Total number of Electrs connections closed",
		}),
		rpcCallsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: promSubsystem,
				Name:      "rpc_calls_total",
				Help:      "Total number of Electrs RPC calls",
			},
			[]string{"method"},
		),
		rpcCallsDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Subsystem: promSubsystem,
				Name:      "rpc_calls_duration_seconds",
				Help:      "Electrs RPC call durations in seconds",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"method"},
		),
	}
}

func (m *metrics) collectors() []prometheus.Collector {
	return []prometheus.Collector{
		m.connsOpen,
		m.connsIdle,
		m.connsOpened,
		m.connsClosed,
		m.rpcCallsTotal,
		m.rpcCallsDuration,
	}
}

// NewClient returns an initialised electrs client.
func NewClient(address string, opts *ClientOptions) (*Client, error) {
	if opts == nil {
		opts = new(ClientOptions)
	}
	if opts.InitialConnections == 0 {
		opts.InitialConnections = defaultInitialConnections
	}
	if opts.MaxConnections == 0 {
		opts.MaxConnections = defaultMaxConnections
	}

	c := &Client{
		metrics: newMetrics(opts.PromNamespace),
	}

	// The address may be empty during tests, ignore empty addresses.
	if address != "" {
		pool, err := newConnPool("tcp", address, opts, c.metrics)
		if err != nil {
			return nil, fmt.Errorf("new connection pool: %w", err)
		}
		c.connPool = pool
	}

	return c, nil
}

// Metrics returns Prometheus metric collectors for the client.
func (c *Client) Metrics() []prometheus.Collector {
	return c.metrics.collectors()
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
			if errors.Is(err, net.ErrClosed) || errors.Is(err, syscall.EPIPE) {
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

	params := []any{hash.String()}
	var balance Balance
	if err := c.call(ctx, "blockchain.scripthash.get_balance", &params, &balance); err != nil {
		return nil, err
	}
	return &balance, nil
}

func (c *Client) Broadcast(ctx context.Context, rtx []byte) ([]byte, error) {
	params := []any{hex.EncodeToString(rtx)}
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
	//  the Electrs server, however this function appears to be used for
	//  polling instead, which could be replaced by handling the requests sent
	//  from the Electrs server.
	hn := &HeaderNotification{}
	if err := c.call(ctx, "blockchain.headers.subscribe", nil, hn); err != nil {
		return 0, err
	}

	log.Infof("received height of %d", hn.Height)

	return hn.Height, nil
}

func (c *Client) RawBlockHeader(ctx context.Context, height uint64) (*bitcoin.BlockHeader, error) {
	params := []any{height}
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

	params := []any{hash.String(), false}
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
	params := []any{hash.String(), true}
	var txJSON json.RawMessage
	if err := c.call(ctx, "blockchain.transaction.get", &params, &txJSON); err != nil {
		return nil, fmt.Errorf("get transaction: %w", err)
	}
	return txJSON, nil
}

func (c *Client) TransactionAtPosition(ctx context.Context, height, index uint64) ([]byte, []string, error) {
	result := struct {
		TXHash string   `json:"tx_hash"`
		Merkle []string `json:"merkle"`
	}{}

	params := []any{height, index, true}
	if err := c.call(ctx, "blockchain.transaction.id_from_pos", &params, &result); err != nil {
		if strings.HasPrefix(err.Error(), "No tx in position ") {
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

	params := []any{hash.String()}
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
