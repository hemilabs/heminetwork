// Copyright (c) 2024 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package peer

//func TestPeerConnect(t *testing.T) {
//	loggo.ConfigureLoggers("TRACE")
//
//	ctx, cancel := context.WithCancel(context.TODO())
//	defer cancel()
//
//	var wg sync.WaitGroup
//
//	//addr:="66.248.205.174:18333"
//	addr := "192.168.101.152:18333"
//	p, err := NewPeer(wire.TestNet3, 1, addr)
//	if err != nil {
//		t.Fatal(err)
//	}
//	err = p.connectNoHandshake(ctx)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// send version
//	defaultHandshakeTimeout := 5 * time.Second
//	us := &wire.NetAddress{Timestamp: time.Now()}
//	them := &wire.NetAddress{Timestamp: time.Now()}
//	msg := wire.NewMsgVersion(us, them, rand.Uint64(), 0)
//	msg.UserAgent = fmt.Sprintf("/%v:%v/", version.Component, version.String())
//	err = p.write(defaultHandshakeTimeout, msg)
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	err = p.write(defaultHandshakeTimeout, wire.NewMsgSendHeaders())
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	err = p.write(defaultHandshakeTimeout, wire.NewMsgSendAddrV2())
//	if err != nil {
//		t.Fatal(err)
//	}
//
//	// 2024-11-06T11:50:21Z [net] sending wtxidrelay (0 bytes) peer=1
//
//	// receive version
//
//	// sendheaders
//
//	// Send verack
//
//	for {
//		rmsg, _, err := p.Read(defaultHandshakeTimeout)
//		if errors.Is(err, wire.ErrUnknownMessage) {
//			t.Log("unknown")
//			continue
//		} else if err != nil {
//			t.Fatal(err)
//		}
//		switch m := rmsg.(type) {
//		case *wire.MsgVersion:
//			err = p.write(defaultHandshakeTimeout, wire.NewMsgVerAck())
//			if err != nil {
//				t.Fatal(err)
//			}
//			t.Logf("replied ver ack")
//
//		case *wire.MsgPing:
//			err = p.write(defaultHandshakeTimeout, wire.NewMsgPong(m.Nonce))
//			if err != nil {
//				t.Fatal(err)
//			}
//			t.Logf("replied pong")
//
//		case *wire.MsgInv:
//		default:
//			t.Log(spew.Sdump(rmsg))
//		}
//	}
//
//	select {
//	case <-time.After(5 * time.Second):
//		t.Log("timeout")
//
//		//case err := <-errC:
//		//	if err != nil {
//		//		t.Fatal(err)
//		//	}
//	}
//	cancel()
//
//	wg.Wait()
//}
