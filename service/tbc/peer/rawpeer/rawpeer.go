// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawpeer

// Package rawpeer provides low level access to a bitcoin p2p node. It provides
// connect/handshake/disconnect and read/write commands. Most implementations
// should not use this package.

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
	"github.com/juju/loggo"

	"github.com/hemilabs/heminetwork/version"
)

const (
	logLevel = "INFO"
)

var (
	log = loggo.GetLogger("rawpeer")

	ErrHandshakeNotComplete = errors.New("handshake not complete")
)

func init() {
	loggo.ConfigureLoggers(logLevel)
}

// XXX wire could use some contexts,

func writeTimeout(timeout time.Duration, conn net.Conn, msg wire.Message, pver uint32, btcnet wire.BitcoinNet) error {
	conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := wire.WriteMessageWithEncodingN(conn, msg, pver, btcnet,
		wire.LatestEncoding)
	return err
}

func readTimeout(timeout time.Duration, conn net.Conn, pver uint32, btcnet wire.BitcoinNet) (wire.Message, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	_, msg, _, err := wire.ReadMessageWithEncodingN(conn, pver, btcnet,
		wire.LatestEncoding)
	return msg, err
}

type RawPeer struct {
	mtx       sync.RWMutex
	isDialing bool
	conn      net.Conn
	connected time.Time

	address string
	id      int

	protocolVersion uint32
	network         wire.BitcoinNet

	remoteVersion *wire.MsgVersion
	addrV2        bool
}

func New(network wire.BitcoinNet, id int, address string) (*RawPeer, error) {
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", address, err)
	}
	return &RawPeer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
		id:              id,
	}, nil
}

func NewFromConn(conn net.Conn, network wire.BitcoinNet, protocolVersion uint32, id int) (*RawPeer, error) {
	return &RawPeer{
		conn:            conn,
		connected:       time.Now(),
		address:         conn.RemoteAddr().String(),
		protocolVersion: wire.AddrV2Version,
		network:         network,
	}, nil
}

func (r *RawPeer) String() string {
	return r.address
}

func (r *RawPeer) Id() int {
	return r.id
}

func (r *RawPeer) Write(timeout time.Duration, msg wire.Message) error {
	r.mtx.Lock()
	conn := r.conn
	r.mtx.Unlock()
	if conn == nil {
		return fmt.Errorf("write: no conn")
	}

	if timeout == 0 {
		conn.SetWriteDeadline(time.Time{})
	} else {
		conn.SetWriteDeadline(time.Now().Add(timeout))
	}
	// XXX contexts would be nice
	_, err := wire.WriteMessageWithEncodingN(conn, msg, r.protocolVersion,
		r.network, wire.LatestEncoding)
	if err != nil {
		conn.Close()
	}
	return err
}

func (r *RawPeer) Read(timeout time.Duration) (wire.Message, []byte, error) {
	r.mtx.Lock()
	conn := r.conn
	r.mtx.Unlock()
	if conn == nil {
		return nil, nil, fmt.Errorf("read: no conn")
	}

	if timeout == 0 {
		conn.SetReadDeadline(time.Time{})
	} else {
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	// XXX contexts would be nice
	_, msg, buf, err := wire.ReadMessageWithEncodingN(conn, r.protocolVersion,
		r.network, wire.LatestEncoding)
	if err != nil && !errors.Is(err, wire.ErrUnknownMessage) {
		conn.Close()
	}
	return msg, buf, err
}

func (r *RawPeer) handshake(ctx context.Context, conn net.Conn) error {
	log.Tracef("handshake %v -> %v", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Tracef("handshake exit %v -> %v", conn.LocalAddr(), conn.RemoteAddr())

	// 1. send our version
	defaultHandshakeTimeout := 2 * time.Second // This is cumulative.
	us := &wire.NetAddress{Timestamp: time.Now()}
	them := &wire.NetAddress{Timestamp: time.Now()}
	msg := wire.NewMsgVersion(us, them, rand.Uint64(), 0)
	msg.UserAgent = fmt.Sprintf("/%v:%v/", version.Component, version.String())
	msg.ProtocolVersion = int32(wire.AddrV2Version)
	err := writeTimeout(defaultHandshakeTimeout, conn, msg, r.protocolVersion, r.network)
	if err != nil {
		return fmt.Errorf("could not write version message: %w", err)
	}

	// 2. receive version
	rmsg, err := readTimeout(defaultHandshakeTimeout, conn, r.protocolVersion, r.network)
	if err != nil {
		return fmt.Errorf("could not read version message: %w", err)
	}
	v, ok := rmsg.(*wire.MsgVersion)
	if !ok {
		return errors.New("expected version message")
	}
	r.remoteVersion = v

	// 3. ask for v2 addresses, this has to be done before verack despite
	// what the spec says.
	if uint32(v.ProtocolVersion) >= wire.AddrV2Version {
		err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgSendAddrV2(),
			r.protocolVersion, r.network)
		if err != nil {
			return fmt.Errorf("could not send addrv2: %w", err)
		}
	}

	// 4. ask for headers.
	if uint32(v.ProtocolVersion) >= wire.SendHeadersVersion {
		err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgSendHeaders(),
			r.protocolVersion, r.network)
		if err != nil {
			return fmt.Errorf("could not send addrv2: %w", err)
		}
	}

	// 5. send verack
	err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgVerAck(), r.protocolVersion, r.network)
	if err != nil {
		return fmt.Errorf("could not send verack: %w", err)
	}

	expire := time.Now().Add(defaultHandshakeTimeout)
	for {
		if time.Now().After(expire) {
			return fmt.Errorf("timeout")
		}
		msg, err := readTimeout(defaultHandshakeTimeout, conn, r.protocolVersion, r.network)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}

		switch msg.(type) {
		case *wire.MsgVerAck:
			log.Debugf("handshake: %v %v %v %v",
				r, v.UserAgent, v.ProtocolVersion, v.LastBlock)
			return nil
		case *wire.MsgSendAddrV2:
			r.addrV2 = true
		default:
			return fmt.Errorf("unexpected message type: %T", msg)
		}
	}
}

func (r *RawPeer) Connect(ctx context.Context) error {
	log.Tracef("Connect %v", r.address) // not locked but ok
	defer log.Tracef("Connect exit %v", r.address)

	r.mtx.Lock()
	if r.isDialing {
		r.mtx.Unlock()
		return fmt.Errorf("already dialing %v", r.address)
	}
	if r.conn != nil {
		r.mtx.Unlock()
		return fmt.Errorf("already open %v", r.address)
	}
	r.isDialing = true
	r.mtx.Unlock()

	d := net.Dialer{
		Deadline: time.Now().Add(5 * time.Second),
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     7 * time.Second,
			Interval: 7 * time.Second,
			Count:    2,
		},
	}

	log.Debugf("dialing %s", r.address)
	conn, err := d.DialContext(ctx, "tcp", r.address)
	if err != nil {
		return fmt.Errorf("dial %v: %w", r.address, err)
	}

	err = r.handshake(ctx, conn)
	if err != nil {
		return fmt.Errorf("handshake %v: %w", r.address, err)
	}

	r.mtx.Lock()
	r.conn = conn
	r.isDialing = false
	r.connected = time.Now()
	r.mtx.Unlock()

	return nil
}

func (r *RawPeer) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

	r.mtx.Lock()
	conn := r.conn
	r.conn = nil
	r.isDialing = true // mark not connected
	r.mtx.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return net.ErrClosed
}

func (r *RawPeer) IsConnected() bool {
	log.Tracef("IsConnected")
	defer log.Tracef("IsConnected exit")

	r.mtx.Lock()
	defer r.mtx.Unlock()
	return !r.isDialing
}

func (r *RawPeer) HasService(f wire.ServiceFlag) bool {
	log.Tracef("HasService 0x%0x", f)
	defer log.Tracef("HasService exit 0x%0x", f)

	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.remoteVersion == nil {
		return false
	}
	return r.remoteVersion.HasService(f)
}

func (r *RawPeer) RemoteVersion() (*wire.MsgVersion, error) {
	r.mtx.Lock()
	defer r.mtx.Unlock()
	if r.remoteVersion == nil {
		return nil, ErrHandshakeNotComplete
	}
	version := *r.remoteVersion
	return &version, nil
}
