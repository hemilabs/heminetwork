// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/wire"
)

// XXX wire could use some contexts

func write(conn net.Conn, msg wire.Message, pver uint32, btcnet wire.BitcoinNet) error {
	_, err := wire.WriteMessageWithEncodingN(conn, msg, pver, btcnet,
		wire.LatestEncoding)
	return err
}

func read(conn net.Conn, pver uint32, btcnet wire.BitcoinNet) (wire.Message, error) {
	_, msg, _, err := wire.ReadMessageWithEncodingN(conn, pver, btcnet,
		wire.LatestEncoding)
	return msg, err
}

type peer struct {
	mtx       sync.RWMutex
	isDialing bool
	conn      net.Conn

	address string

	protocolVersion uint32
	network         wire.BitcoinNet

	remoteVersion *wire.MsgVersion
	addrV2        bool
}

func NewPeer(network wire.BitcoinNet, address string) (*peer, error) {
	// XXX parse address and return failure if it's wrong
	return &peer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
	}, nil
}

func (p *peer) String() string {
	return p.address
}

func (p *peer) write(msg wire.Message) error {
	_, err := wire.WriteMessageWithEncodingN(p.conn, msg, p.protocolVersion,
		p.network, wire.LatestEncoding)
	return err
}

func (p *peer) read() (wire.Message, error) {
	_, msg, _, err := wire.ReadMessageWithEncodingN(p.conn, p.protocolVersion,
		p.network, wire.LatestEncoding)
	return msg, err
}

func (p *peer) handshake(ctx context.Context, conn net.Conn) error {
	log.Tracef("handshake %v -> %v", conn.LocalAddr(), conn.RemoteAddr())
	defer log.Tracef("handshake exit %v -> %v", conn.LocalAddr(), conn.RemoteAddr())

	// 1. send our version
	// 2. receive version
	// 3. send sendaddrv2
	// 4. send verack
	// 5. receive sendaddrv2, verack or ignore

	us := &wire.NetAddress{Timestamp: time.Now()}
	them := &wire.NetAddress{Timestamp: time.Now()}
	msg := wire.NewMsgVersion(us, them, uint64(rand.Int63()), 0)
	err := write(conn, msg, p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not write version message: %w", err)
	}

	// 2. receive version
	rmsg, err := read(conn, p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not read version message: %w", err)
	}
	v, ok := rmsg.(*wire.MsgVersion)
	if !ok {
		return fmt.Errorf("expected version message")
	}
	p.remoteVersion = v

	// 3. send sendaddrv2
	if v.ProtocolVersion >= 70016 {
		err = write(conn, wire.NewMsgSendAddrV2(), p.protocolVersion, p.network)
		if err != nil {
			return fmt.Errorf("could not send sendaddrv2: %w", err)
		}
	}

	// XXX send sendheaders?

	// 4. send verack
	err = write(conn, wire.NewMsgVerAck(), p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not send verack: %w", err)
	}

	for count := 0; count < 3; count++ {
		msg, err := read(conn, p.protocolVersion, p.network)
		if err == wire.ErrUnknownMessage {
			continue
		} else if err != nil {
			return fmt.Errorf("handshake read: %w", err)
		}

		switch msg.(type) {
		case *wire.MsgVerAck:
			return nil
		case *wire.MsgSendAddrV2:
			p.addrV2 = true
			continue
		default:
			return fmt.Errorf("unexpected message type: %T", msg)
		}
	}

	return fmt.Errorf("handshake failed")
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
		KeepAlive: 9 * time.Second,
	}
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
	p.mtx.Unlock()

	return nil
}

func (p *peer) close() error {
	log.Tracef("close")
	defer log.Tracef("close exit")

	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.conn != nil {
		return p.conn.Close()
	}
	return fmt.Errorf("already closed")
}
