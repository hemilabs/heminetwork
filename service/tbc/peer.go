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

	"github.com/hemilabs/heminetwork/version"
)

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

type peer struct {
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

func NewPeer(network wire.BitcoinNet, id int, address string) (*peer, error) {
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", address, err)
	}
	return &peer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
		id:              id,
	}, nil
}

func (p *peer) String() string {
	return p.address
}

func (p *peer) Id() int {
	return p.id
}

func (p *peer) write(timeout time.Duration, msg wire.Message) error {
	p.mtx.Lock()
	conn := p.conn
	p.mtx.Unlock()
	if conn == nil {
		return fmt.Errorf("write: no conn")
	}

	conn.SetWriteDeadline(time.Now().Add(timeout))
	// XXX contexts would be nice
	_, err := wire.WriteMessageWithEncodingN(conn, msg, p.protocolVersion,
		p.network, wire.LatestEncoding)
	if err != nil {
		conn.Close()
	}
	return err
}

func (p *peer) read(timeout time.Duration) (wire.Message, []byte, error) {
	p.mtx.Lock()
	conn := p.conn
	p.mtx.Unlock()
	if conn == nil {
		return nil, nil, fmt.Errorf("read: no conn")
	}

	if timeout == 0 {
		conn.SetReadDeadline(time.Time{}) // never timeout on reads
	} else {
		conn.SetReadDeadline(time.Now().Add(timeout))
	}
	// XXX contexts would be nice
	_, msg, buf, err := wire.ReadMessageWithEncodingN(conn, p.protocolVersion,
		p.network, wire.LatestEncoding)
	if err != nil && !errors.Is(err, wire.ErrUnknownMessage) {
		conn.Close()
	}
	return msg, buf, err
}

func (p *peer) handshake(ctx context.Context, conn net.Conn) error {
	log.Tracef("handshake %v -> %v", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Tracef("handshake exit %v -> %v", conn.LocalAddr(), conn.RemoteAddr())

	// 1. send our version
	defaultHandshakeTimeout := 2 * time.Second // This is cumulative.
	us := &wire.NetAddress{Timestamp: time.Now()}
	them := &wire.NetAddress{Timestamp: time.Now()}
	msg := wire.NewMsgVersion(us, them, rand.Uint64(), 0)
	msg.UserAgent = fmt.Sprintf("/%v:%v/", version.Component, version.String())
	err := writeTimeout(defaultHandshakeTimeout, conn, msg, p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not write version message: %w", err)
	}

	// 2. receive version
	rmsg, err := readTimeout(defaultHandshakeTimeout, conn, p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not read version message: %w", err)
	}
	v, ok := rmsg.(*wire.MsgVersion)
	if !ok {
		return errors.New("expected version message")
	}
	p.remoteVersion = v

	// 3. ask for v2 addresses, this has to be done before verack despite
	// what the spec says.
	if v.ProtocolVersion >= 70016 {
		err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgSendAddrV2(), p.protocolVersion, p.network)
		if err != nil {
			return fmt.Errorf("could not send addrv2: %w", err)
		}
	}

	// 4. send verack
	err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgVerAck(), p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not send verack: %w", err)
	}

	expire := time.Now().Add(defaultHandshakeTimeout)
	for {
		if time.Now().After(expire) {
			return fmt.Errorf("timeout")
		}
		msg, err := readTimeout(defaultHandshakeTimeout, conn, p.protocolVersion, p.network)
		if errors.Is(err, wire.ErrUnknownMessage) {
			continue
		} else if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}

		switch msg.(type) {
		case *wire.MsgVerAck:
			log.Debugf("handshake: %v %v %v %v",
				p, v.UserAgent, v.ProtocolVersion, v.LastBlock)
			return nil
		case *wire.MsgSendAddrV2:
			p.addrV2 = true
		default:
			return fmt.Errorf("unexpected message type: %T", msg)
		}
	}
}

func (p *peer) connect(ctx context.Context) error {
	log.Tracef("connect %v", p.address) // not locked but ok
	defer log.Tracef("connect exit %v", p.address)

	p.mtx.Lock()
	if p.isDialing {
		p.mtx.Unlock()
		return fmt.Errorf("already dialing %v", p.address)
	}
	if p.conn != nil {
		p.mtx.Unlock()
		return fmt.Errorf("already open %v", p.address)
	}
	p.isDialing = true
	p.mtx.Unlock()

	d := net.Dialer{
		Deadline: time.Now().Add(5 * time.Second),
		KeepAliveConfig: net.KeepAliveConfig{
			Enable:   true,
			Idle:     7 * time.Second,
			Interval: 7 * time.Second,
			Count:    2,
		},
	}

	log.Debugf("dialing %s", p.address)
	conn, err := d.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return fmt.Errorf("dial %v: %w", p.address, err)
	}

	err = p.handshake(ctx, conn)
	if err != nil {
		return fmt.Errorf("handshake %v: %w", p.address, err)
	}

	p.mtx.Lock()
	p.conn = conn
	p.isDialing = false
	p.connected = time.Now()
	p.mtx.Unlock()

	return nil
}

func (p *peer) close() error {
	log.Tracef("close")
	defer log.Tracef("close exit")

	p.mtx.Lock()
	conn := p.conn
	p.conn = nil
	p.isDialing = true // mark not connected
	p.mtx.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return net.ErrClosed
}

func (p *peer) isConnected() bool {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	return !p.isDialing
}
