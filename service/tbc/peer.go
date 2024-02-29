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

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/hemilabs/heminetwork/database/tbcd"
)

/// XXX wire could use some contexts

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
	return &peer{
		protocolVersion: wire.ProtocolVersion,
		network:         network,
		address:         address,
	}, nil
}

func (p *peer) connect(ctx context.Context) error {
	log.Tracef("connect")
	defer log.Tracef("connect exit")

	p.mtx.Lock()
	if p.isDialing {
		p.mtx.Unlock()
		return fmt.Errorf("already dialing")
	}
	if p.conn != nil {
		p.mtx.Unlock()
		return fmt.Errorf("already open")
	}
	p.isDialing = true
	p.mtx.Unlock()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", p.address)
	if err != nil {
		return err
	}

	err = p.handshake(ctx, conn)
	if err != nil {
		return err
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
		defer func() { p.conn = nil }()
		return p.conn.Close()
	}
	return fmt.Errorf("already closed")
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
		return fmt.Errorf("could not write version message: %v", err)
	}

	// 2. receive version
	rmsg, err := read(conn, p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not read version message: %v", err)
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
			return fmt.Errorf("could not send sendaddrv2: %v", err)
		}
	}

	// 4. send verack
	err = write(conn, wire.NewMsgVerAck(), p.protocolVersion, p.network)
	if err != nil {
		return fmt.Errorf("could not send verack: %v", err)
	}

	for count := 0; count < 3; count++ {
		msg, err := read(conn, p.protocolVersion, p.network)
		if err == wire.ErrUnknownMessage {
			continue
		} else if err != nil {
			return err
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

func handlePing(p *peer, msg *wire.MsgPing) {
	log.Tracef("handlePing")
	defer log.Tracef("handlePing exit")

	pong := wire.NewMsgPong(msg.Nonce)
	err := p.write(pong)
	if err != nil {
		fmt.Printf("could not write pong message: %v", err)
		return
	}
	log.Debugf("handlePing: pong %v", pong.Nonce)
}

func downloadBlock(p *peer, height int, hash chainhash.Hash) error {
	log.Tracef("downloadBlock")
	defer log.Tracef("downloadBlock exit")

	log.Debugf("downloadBlock at %v: %v", height, hash)

	getData := wire.NewMsgGetData()
	getData.InvList = append(getData.InvList,
		&wire.InvVect{
			Type: wire.InvTypeBlock,
			Hash: hash,
		})
	err := p.write(getData)
	if err != nil {
		return fmt.Errorf("could not write get block message: %v", err)
	}

	return nil
}

func (s *Server) handleInvBlock(p *peer, msg *wire.MsgInv) {
}

func (s *Server) handleInv(ctx context.Context, p *peer, msg *wire.MsgInv) {
	log.Tracef("handleInv")
	defer log.Tracef("handleInv exit")

	log.Debugf("handleInv: %v", len(msg.InvList))

	// XXX fix height
	blocks := make([]tbcd.BtcHashHeight, 0, len(msg.InvList))
	for k := range msg.InvList {
		switch msg.InvList[k].Type {
		case wire.InvTypeBlock:
			log.Tracef("handleInv block: height %v hash %v",
				k+1, msg.InvList[k].Hash)
			//err := downloadBlock(p, k+1, msg.InvList[k].Hash)
			//if err != nil {
			//	log.Errorf("download block at %v: %v", k+1, err)
			//}
			blocks = append(blocks, tbcd.BtcHashHeight{
				Hash:   msg.InvList[k].Hash[:], // XXX this is wireformat
				Height: uint64(k + 1),
			})
		default:
			log.Tracef("handleInv: skipping inv type %v", msg.InvList[k].Type)
		}
	}

	if len(blocks) > 0 {
		err := s.db.BtcHashHeightInsert(ctx, blocks)
		if err != nil {
			log.Errorf("BtcHashHeightInsert: %v", err)
		}
	}
}

func handleBlock(p *peer, msg *wire.MsgBlock) {
	log.Tracef("handleBlock")
	defer log.Tracef("handleBlock exit")

	log.Debugf("handleBlock: %v txs %v\n", msg.Header.BlockHash(),
		len(msg.Transactions))
}
