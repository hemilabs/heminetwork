// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package peer

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
	log = loggo.GetLogger("peer")

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

type Peer struct {
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

func New(network wire.BitcoinNet, id int, address string) (*Peer, error) {
	_, _, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("%v: %w", address, err)
	}
	return &Peer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
		id:              id,
	}, nil
}

func NewFromConn(conn net.Conn, network wire.BitcoinNet, protocolVersion uint32, id int) (*Peer, error) {
	return &Peer{
		conn:            conn,
		connected:       time.Now(),
		address:         conn.RemoteAddr().String(),
		protocolVersion: wire.AddrV2Version,
		network:         network,
	}, nil
}

func (p *Peer) String() string {
	return p.address
}

func (p *Peer) Id() int {
	return p.id
}

func (p *Peer) Write(timeout time.Duration, msg wire.Message) error {
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

func (p *Peer) Read(timeout time.Duration) (wire.Message, []byte, error) {
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

func (p *Peer) handshake(ctx context.Context, conn net.Conn) error {
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
	if uint32(v.ProtocolVersion) >= wire.AddrV2Version {
		err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgSendAddrV2(),
			p.protocolVersion, p.network)
		if err != nil {
			return fmt.Errorf("could not send addrv2: %w", err)
		}
	}

	// 4. ask for headers.
	if uint32(v.ProtocolVersion) >= wire.SendHeadersVersion {
		err = writeTimeout(defaultHandshakeTimeout, conn, wire.NewMsgSendHeaders(),
			p.protocolVersion, p.network)
		if err != nil {
			return fmt.Errorf("could not send addrv2: %w", err)
		}
	}

	// 5. send verack
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

func (p *Peer) Connect(ctx context.Context) error {
	log.Tracef("Connect %v", p.address) // not locked but ok
	defer log.Tracef("Connect exit %v", p.address)

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

func (p *Peer) Close() error {
	log.Tracef("Close")
	defer log.Tracef("Close exit")

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

func (p *Peer) IsConnected() bool {
	log.Tracef("IsConnected")
	defer log.Tracef("IsConnected exit")

	p.mtx.Lock()
	defer p.mtx.Unlock()
	return !p.isDialing
}

func (p *Peer) HasService(f wire.ServiceFlag) bool {
	log.Tracef("HasService 0x%0x", f)
	defer log.Tracef("HasService exit 0x%0x", f)

	p.mtx.Lock()
	defer p.mtx.Unlock()

	return p.remoteVersion.HasService(f)
}

func (p *Peer) RemoteVersion() (*wire.MsgVersion, error) {
	p.mtx.Lock()
	defer p.mtx.Unlock()
	if p.remoteVersion == nil {
		return nil, ErrHandshakeNotComplete
	}
	version := *p.remoteVersion
	return &version, nil
}
