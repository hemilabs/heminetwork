// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package protocol

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/juju/loggo"
)

var log = loggo.GetLogger("protocol")

const (
	logLevel           = "protocol=INFO"
	WSConnectTimeout   = 20 * time.Second
	WSHandshakeTimeout = 15 * time.Second
)

const (
	StatusHandshakeErr websocket.StatusCode = 4100 // XXX can we just hijack 4100?
)

type HandshakeError string

func (he HandshakeError) Error() string {
	return string(he)
}

func (he HandshakeError) Is(target error) bool {
	_, ok := target.(HandshakeError)
	return ok
}

var PublicKeyAuthError = websocket.CloseError{
	Code:   StatusHandshakeErr,
	Reason: HandshakeError("invalid public key").Error(),
}

func init() {
	loggo.ConfigureLoggers(logLevel)
}

// random returns a variable number of random bytes.
func random(n int) ([]byte, error) {
	buffer := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, buffer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

var ErrInvalidCommand = errors.New("invalid command")

type Command string

// commandPayload returns the data structure corresponding to the given command.
func commandPayload(cmd Command, api API) (reflect.Type, bool) {
	commands := api.Commands()
	payload, ok := commands[cmd]
	return payload, ok
}

// commandFromPayload returns the command for the given data structure.
func commandFromPayload(payload any, api API) (Command, bool) {
	payloadType := reflect.TypeOf(payload)
	for cmd, cmdPayloadType := range api.Commands() {
		cmdPayloadPtrType := reflect.PointerTo(cmdPayloadType)
		if payloadType == cmdPayloadType || payloadType == cmdPayloadPtrType {
			return cmd, true
		}
	}
	return "", false
}

type API interface {
	Commands() map[Command]reflect.Type
}

func Read(ctx context.Context, c APIConn, api API) (Command, string, interface{}, error) {
	var msg Message
	if err := c.ReadJSON(ctx, &msg); err != nil {
		return "", "", nil, err
	}
	cmdPayload, ok := commandPayload(msg.Header.Command, api)
	if !ok {
		return "", "", nil, ErrInvalidCommand
	}

	payload := reflect.New(cmdPayload).Interface()
	if err := json.Unmarshal(msg.Payload, &payload); err != nil {
		return "", "", nil, ErrInvalidCommand
	}

	return msg.Header.Command, msg.Header.ID, payload, nil
}

// Write encodes and sends a payload over the API connection.
func Write(ctx context.Context, c APIConn, api API, id string, payload interface{}) error {
	cmd, ok := commandFromPayload(payload, api)
	if !ok {
		return fmt.Errorf("command unknown for payload %T", payload)
	}

	msg := &Message{
		Header: Header{Command: cmd, ID: id},
	}

	var err error
	if msg.Payload, err = json.Marshal(payload); err != nil {
		return err
	}

	return c.WriteJSON(ctx, msg)
}

// Authenticator implements authentication between a client and a server.
type Authenticator interface {
	HandshakeClient(ctx context.Context, ac APIConn) error
	HandshakeServer(ctx context.Context, ac APIConn) error
}

type WSConn struct {
	conn *websocket.Conn
}

func (wsc *WSConn) ReadJSON(ctx context.Context, v any) error {
	return wsjson.Read(ctx, wsc.conn, v)
}

func (wsc *WSConn) WriteJSON(ctx context.Context, v any) error {
	return wsjson.Write(ctx, wsc.conn, v)
}

func (wsc *WSConn) Close() error {
	return wsc.conn.Close(websocket.StatusNormalClosure, "")
}

func (wsc *WSConn) CloseStatus(code websocket.StatusCode, reason string) error {
	return wsc.conn.Close(code, reason)
}

func NewWSConn(conn *websocket.Conn) *WSConn {
	return &WSConn{conn: conn}
}

// Header prefixes all websocket commands.
type Header struct {
	Command Command `json:"command"`      // Command to execute
	ID      string  `json:"id,omitempty"` // Command identifier
}

// Message represents a websocket message.
type Message struct {
	Header  Header          `json:"header"`
	Payload json.RawMessage `json:"payload"`
}

// Error is a protocol error type that is used to provide additional error
// information between a server and client.
//
// A unique "trace" string may be embedded, which can be used to trace errors
// between a server and client.
type Error struct {
	Timestamp int64  `json:"timestamp"`
	Trace     string `json:"trace,omitempty"`
	Message   string `json:"message"`
}

// Errorf returns a protocol Error type with an embedded trace.
func Errorf(msg string, args ...interface{}) *Error {
	trace, _ := random(8)
	return &Error{
		Timestamp: time.Now().Unix(),
		Trace:     hex.EncodeToString(trace),
		Message:   fmt.Sprintf(msg, args...),
	}
}

// String pretty prints a protocol error.
func (e Error) String() string {
	if len(e.Trace) == 0 {
		return e.Message
	}
	return fmt.Sprintf("%v [%v:%v]", e.Message, e.Trace, e.Timestamp)
}

func (e Error) Error() string {
	return e.String()
}

// RequestError wraps an error to create a protocol request error.
//
// Request errors are usually something caused by a client, e.g. validation or
// input errors, and therefore should not be logged server-side and do not
// contain an embedded trace.
func RequestError(err error) *Error {
	return &Error{
		Timestamp: time.Now().Unix(),
		Message:   err.Error(),
	}
}

// RequestErrorf creates a new protocol request error.
//
// Request errors are usually something caused by a client, e.g. validation or
// input errors, and therefore should not be logged server-side and do not
// contain an embedded trace.
func RequestErrorf(msg string, args ...any) *Error {
	return &Error{
		Timestamp: time.Now().Unix(),
		Message:   fmt.Sprintf(msg, args...),
	}
}

// InternalError represents an internal application error.
//
// Internal errors are errors that occurred within the application and are not
// caused by a client (e.g. validation or input errors). The actual error
// message should not be sent to clients, as it is internal to the application,
// and may be server-operator specific.
type InternalError struct {
	protocol *Error
	internal error
}

// ProtocolError returns the protocol error representation.
// This error is intended to be sent to clients.
func (ie InternalError) ProtocolError() *Error {
	return ie.protocol
}

// Error satisfies the error interface.
func (ie InternalError) Error() string {
	if ie.internal != nil {
		return fmt.Sprintf("%v [%v:%v]", ie.internal.Error(),
			ie.protocol.Timestamp, ie.protocol.Trace)
	}
	return ie.protocol.String()
}

// Unwrap returns the error wrapped by this internal error.
func (ie InternalError) Unwrap() error {
	return ie.internal
}

// NewInternalError returns an InternalError wrapping the given error.
func NewInternalError(err error) *InternalError {
	return NewInternalErrorf("internal error: %w", err)
}

// NewInternalErrorf returns an InternalError constructed from the passed
// message and arguments.
func NewInternalErrorf(msg string, args ...interface{}) *InternalError {
	return &InternalError{
		protocol: Errorf("internal error"),
		internal: fmt.Errorf(msg, args...),
	}
}

// Ping
type PingRequest struct {
	Timestamp int64 `json:"timestamp"` // Local timestamp
}

// PingResponse
type PingResponse struct {
	OriginTimestamp int64 `json:"origintimestamp"` // Timestamp from origin
	Timestamp       int64 `json:"timestamp"`       // Local timestamp
}

// APIConn provides an API connection.
type APIConn interface {
	ReadJSON(ctx context.Context, v any) error
	WriteJSON(ctx context.Context, v any) error
}

// readResult is the result of a client side read.
type readResult struct {
	cmd     Command
	id      string
	payload interface{}
	err     error
}

// Conn is a client side connection.
type Conn struct {
	sync.RWMutex

	serverURL string
	opts      ConnOptions
	msgID     uint64

	wsc          *websocket.Conn
	wscReadLock  sync.Mutex
	wscWriteLock sync.Mutex

	calls map[string]chan *readResult
}

// ConnOptions are options available for a Conn.
type ConnOptions struct {
	// ReadLimit is the maximum number of bytes to read from the connection.
	// Defaults to defaultConnReadLimit.
	ReadLimit int64

	// Authenticator is the connection authenticator.
	Authenticator Authenticator

	// Headers are the HTTP headers included in the WebSocket handshake request.
	Headers http.Header
}

// defaultConnReadLimit is the default connection read limit.
const defaultConnReadLimit = 512 * (1 << 10) // 512 KiB

// NewConn returns a client side connection object.
func NewConn(urlStr string, opts *ConnOptions) (*Conn, error) {
	log.Tracef("NewConn: %v", urlStr)
	defer log.Tracef("NewConn exit: %v", urlStr)

	u, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	if opts == nil {
		opts = new(ConnOptions)
	}
	if opts.ReadLimit <= 0 {
		opts.ReadLimit = defaultConnReadLimit
	}

	ac := &Conn{
		serverURL: u.String(),
		opts:      *opts,
		calls:     make(map[string]chan *readResult),
		msgID:     1,
	}

	return ac, nil
}

func (ac *Conn) Connect(ctx context.Context) error {
	log.Tracef("Connect")
	defer log.Tracef("Connect exit")

	ac.Lock()
	defer ac.Unlock()
	if ac.wsc != nil {
		return nil
	}

	// Connection and handshake must complete in less than WSConnectTimeout.
	connectCtx, cancel := context.WithTimeout(ctx, WSConnectTimeout)
	defer cancel()

	// XXX Dial does not return a parasable error. This is an issue in the
	// package.
	// Note that we cannot have DialOptions on a WASM websocket
	log.Tracef("Connect: dialing %v", ac.serverURL)
	conn, _, err := websocket.Dial(connectCtx, ac.serverURL, newDialOptions(ac.opts))
	if err != nil {
		return fmt.Errorf("dial server: %w", err)
	}
	conn.SetReadLimit(ac.opts.ReadLimit)
	defer func() {
		if ac.wsc == nil {
			conn.Close(websocket.StatusNormalClosure, "")
		}
	}()

	handshakeCtx, cancel := context.WithTimeout(ctx, WSHandshakeTimeout)
	defer cancel()

	if auth := ac.opts.Authenticator; auth != nil {
		log.Tracef("Connect: handshaking with %v", ac.serverURL)
		if err := auth.HandshakeClient(handshakeCtx, NewWSConn(conn)); err != nil {
			return HandshakeError(fmt.Sprintf("failed to handshake with server: %v", err))
		}
	}

	// done as an API message, and it should be done at the protocol
	// level instead...
	var msg Message
	if err := NewWSConn(conn).ReadJSON(connectCtx, &msg); err != nil {
		var ce websocket.CloseError
		if errors.As(err, &ce) {
			switch ce.Code {
			// case 4000:
			// log.Errorf("Connection rejected - user account not found")
			// return ErrUserAccountNotFound
			default:
				log.Errorf("unknown close error: %v", err)
				return err
			}
		}
		log.Errorf("Connection to %v failed: %v", ac.serverURL, err)
		return err
	}

	log.Debugf("Connection established with %v", ac.serverURL)
	ac.wsc = conn

	return nil
}

// wsConn returns the underlying websocket connection.
func (ac *Conn) wsConn() *websocket.Conn {
	ac.RLock()
	defer ac.RUnlock()
	return ac.wsc
}

// conn (re)connects an existing websocket connection.
func (ac *Conn) conn(ctx context.Context) (*websocket.Conn, error) {
	wsc := ac.wsConn()
	if wsc != nil {
		return wsc, nil
	}
	if err := ac.Connect(ctx); err != nil {
		return nil, err
	}
	return ac.wsConn(), nil
}

// CloseStatus close the connection with the provided StatusCode.
func (ac *Conn) CloseStatus(code websocket.StatusCode, reason string) error {
	ac.Lock()
	defer ac.Unlock()
	if ac.wsc == nil {
		return nil
	}
	err := ac.wsc.Close(code, reason)
	ac.wsc = nil

	return err
}

func (ac *Conn) IsOnline() bool {
	ac.Lock()
	defer ac.Unlock()
	return ac.wsc != nil
}

// Close closes a websocket connection with normal status.
func (ac *Conn) Close() error {
	return ac.CloseStatus(websocket.StatusNormalClosure, "")
}

// ReadJSON returns JSON of the wire and unmarshals it into v.
func (ac *Conn) ReadJSON(ctx context.Context, v any) error {
	conn, err := ac.conn(ctx)
	if err != nil {
		return err
	}
	ac.wscReadLock.Lock()
	defer ac.wscReadLock.Unlock()
	if err := wsjson.Read(ctx, conn, v); err != nil {
		ac.Close()
		return err
	}
	return nil
}

// WriteJSON writes marshals v and writes it to the wire.
func (ac *Conn) WriteJSON(ctx context.Context, v any) error {
	conn, err := ac.conn(ctx)
	if err != nil {
		return err
	}

	ac.wscWriteLock.Lock()
	defer ac.wscWriteLock.Unlock()
	if err := wsjson.Write(ctx, conn, v); err != nil {
		ac.Close()
		return err
	}
	return nil
}

// read calls the underlying Read function and returns the command, id and
// unmarshaled payload.
func (ac *Conn) read(ctx context.Context, api API) (Command, string, interface{}, error) {
	return Read(ctx, ac, api)
}

// nextMsgID returns the next available message identifier. This identifier
// travels as part of the header with the command.
func (ac *Conn) nextMsgID() uint64 {
	ac.Lock()
	defer ac.Unlock()
	msgID := ac.msgID
	ac.msgID++
	if ac.msgID == 0 {
		ac.msgID++
	}
	return msgID
}

// Call is a blocking call that returns the command, id and unmarshaled payload.
func (ac *Conn) Call(ctx context.Context, api API, payload interface{}) (Command, string, interface{}, error) {
	log.Tracef("Call: %T", payload)
	defer log.Tracef("Call exit: %T", payload)

	msgID := fmt.Sprintf("%d", ac.nextMsgID())
	resultCh := make(chan *readResult, 1)

	ac.Lock()
	ac.calls[msgID] = resultCh
	ac.Unlock()

	defer func() {
		ac.Lock()
		delete(ac.calls, msgID)
		ac.Unlock()
	}()

	if err := ac.Write(ctx, api, msgID, payload); err != nil {
		return "", "", nil, err
	}
	var result *readResult
	select {
	case <-ctx.Done():
		return "", "", nil, ctx.Err()
	case result = <-resultCh:
	}

	if result.err == nil && result.payload == nil {
		result.err = errors.New("reply payload is nil")
	}

	return result.cmd, result.id, result.payload, result.err
}

// errorAll fails all outstanding commands in order to shutdown the websocket.
func (ac *Conn) errorAll(err error) {
	ac.RLock()
	defer ac.RUnlock()
	for _, call := range ac.calls {
		rr := &readResult{err: err}
		select {
		case call <- rr:
		default:
		}
	}
}

// Read reads and returns the next command from the API connection.
func (ac *Conn) Read(ctx context.Context, api API) (Command, string, interface{}, error) {
	for {
		cmd, id, payload, err := ac.read(ctx, api)
		if id == "" || err != nil {
			if err != nil {
				ac.errorAll(err)
			}
			return cmd, id, payload, err
		}
		ac.RLock()
		call, ok := ac.calls[id]
		ac.RUnlock()
		if !ok {
			return cmd, id, payload, err
		}
		rr := &readResult{cmd, id, payload, err}
		select {
		case call <- rr:
		default:
		}
	}
}

// Write encodes and sends a payload over the API connection.
func (ac *Conn) Write(ctx context.Context, api API, id string, payload interface{}) error {
	return Write(ctx, ac, api, id, payload)
}
