// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package rawpeer

import (
	"context"
	"errors"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/phayes/freeport"
)

func GetFreePort() string {
	port, err := freeport.GetFreePort()
	if err != nil {
		panic(err)
	}
	return strconv.Itoa(port)
}

func mockPeerServer(ctx context.Context, id int, listener net.Listener, msgCh chan string) error {
	conn, err := listener.Accept()
	if err != nil {
		return err
	}
	defer conn.Close()

	p, err := NewFromConn(conn, wire.TestNet3, wire.AddrV2Version, id)
	if err != nil {
		return err
	}

	var rmsg wire.Message
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			rmsg, _, err = p.Read(0)
			if err != nil {
				return err
			}
			msgCh <- rmsg.Command()
		}
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	msgCh := make(chan string)

	port := GetFreePort()

	listener, err := net.Listen("tcp", ":"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		err := mockPeerServer(ctx, 2, listener, msgCh)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, io.EOF) {
			panic(err)
		}
	}()

	conn, err := net.Dial("tcp", "localhost:"+port)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p1, err := NewFromConn(conn, wire.TestNet3, wire.AddrV2Version, 1)
	if err != nil {
		t.Fatal(err)
	}

	if err := p1.Write(0, wire.NewMsgPing(1)); err != nil {
		panic(err)
	}

	const (
		writeNum = 2
		writeCount = 100	
	)

	fakeCh := chainhash.Hash{}
	for k := range writerNum {
		go func() {
			for range WriteCount {
				bh := wire.NewBlockHeader(int32(k), &fakeCh, &fakeCh, uint32(k), uint32(k))
				mva := wire.NewMsgHeaders()
				mva.AddBlockHeader(bh)
				if err := p1.Write(0, mva); err != nil {
					panic(err)
				}
			}
		}()
	}

	expectedCmds := map[string]int{
		wire.CmdPing:    1,
		wire.CmdHeaders: writerNum * WriteCount,
	}

	for {
		select {
		case s := <-msgCh:
			t.Logf("received response from server: %v", s)
			expectedCmds[s]--
		case <-ctx.Done():
			if ctx.Err() != nil {
				t.Fatal(ctx.Err())
			}
		}
		remaining := false
		for k, v := range expectedCmds {
			if v != 0 {
				t.Logf("%v '%v' commands left", v, k)
				remaining = true
			}
		}
		if !remaining {
			break
		}
	}

}
