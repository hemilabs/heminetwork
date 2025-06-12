// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package mock

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/coder/websocket"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/hemi"
)

// Opgeth RPC API structs

type L2KeystoneValidityResponse struct {
	L2Keystones []hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}

// Same as ValidityResponse but keep separate in
// case one changes in future api versions.

type L2KeystoneLatestResponse struct {
	L2Keystones []hemi.L2Keystone `json:"keystones"`
	Error       *protocol.Error   `json:"error,omitempty"`
}

type jsonrpcSubscriptionNotification struct {
	Version string                `json:"jsonrpc"`
	Method  string                `json:"method"`
	Params  subscriptionResultEnc `json:"params"`
}

type subscriptionResultEnc struct {
	ID     string `json:"subscription"`
	Result any    `json:"result"`
}

type jsonrpcMessage struct {
	Version string          `json:"jsonrpc,omitempty"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Error   *jsonError      `json:"error,omitempty"`
	Result  any             `json:"result,omitempty"`
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Retrieve the URL from the test server
func (f *mockHandler) URL() string {
	return f.server.URL
}

type OpGethMockHandler struct {
	mockHandler
	keystones []hemi.L2Keystone
}

func NewMockOpGeth(pctx context.Context, errCh chan error, msgCh chan string, keystones []hemi.L2Keystone) *OpGethMockHandler {
	// Sort keystones in ascending order
	slices.SortFunc(keystones, func(a, b hemi.L2Keystone) int {
		return cmp.Compare(a.L2BlockNumber, b.L2BlockNumber)
	})

	th := OpGethMockHandler{
		mockHandler: mockHandler{
			errCh: errCh,
			msgCh: msgCh,
			name:  "mockOpGeth",
			pctx:  pctx,
			conns: make([]*websocket.Conn, 0),
		},
		keystones: keystones,
	}
	th.handleFunc = th.mockOpGethHandleFunc
	th.server = httptest.NewServer(&th)
	th.Start()
	return &th
}

func (f *OpGethMockHandler) mockOpGethHandleFunc(w http.ResponseWriter, r *http.Request) error {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}
	defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

	f.mtx.Lock()
	f.conns = append(f.conns, c)
	f.mtx.Unlock()

	log.Infof("%v: new connection to %v", f.name, r.RemoteAddr)

	var keystoneCounter int
	var kssMtx sync.RWMutex
	for {
		var msg jsonrpcMessage
		_, br, err := c.Read(f.pctx)
		if err != nil {
			log.Errorf("%v", err)
			return nil
		}
		err = json.Unmarshal(br, &msg)
		if err != nil {
			return err
		}

		log.Tracef("%v: command is %v", f.name, msg.Method)

		go func() {
			select {
			case <-f.pctx.Done():
				err = f.pctx.Err()
				return
			case f.msgCh <- msg.Method:
			}
		}()

		var subResp jsonrpcMessage
		switch msg.Method {
		case "kss_subscribe":
			subResp = jsonrpcMessage{
				Version: "2.0",
				ID:      msg.ID,
				Result:  "0x5a395650bce324475634d746a831c227",
			}

			encResult := subscriptionResultEnc{
				ID:     "0x5a395650bce324475634d746a831c227",
				Result: "New Keystone Available",
			}
			subNotif := jsonrpcSubscriptionNotification{
				Version: "2.0",
				Method:  "eth_subscription",
				Params:  encResult,
			}

			p, err := json.Marshal(subNotif)
			if err != nil {
				panic(err)
			}

			// send new keystone notifications periodically
			go func() {
				for {
					select {
					case <-f.pctx.Done():
						return
					case <-time.After(DefaultNtfnDuration):
						if !f.Running() {
							return
						}
						log.Tracef("%v: Sending new keystone notification", f.name)
						err = c.Write(f.pctx, websocket.MessageText, p)
						if err != nil {
							log.Errorf("%v: notification sender: %w", f.name, err.Error())
							return
						}
						kssMtx.Lock()
						keystoneCounter++
						kssMtx.Unlock()
					}
				}
			}()
		case "kss_getLatestKeystones":
			var count []int
			err = json.Unmarshal(msg.Params, &count)
			if err != nil {
				panic(err)
			}
			kssMtx.RLock()
			kssResp := L2KeystoneLatestResponse{
				L2Keystones: lastKeystones(count[0], f.keystones[:min(keystoneCounter+count[0], len(f.keystones))]),
			}
			kssMtx.RUnlock()
			subResp = jsonrpcMessage{
				Version: "2.0",
				ID:      msg.ID,
				Result:  kssResp,
			}
		case "kss_getKeystone":
			var params []any
			err = json.Unmarshal(msg.Params, &params)
			if err != nil {
				panic(err)
			}

			shash, ok := params[0].(string)
			if !ok {
				panic("unexpected param type")
			}

			abrevHash, err := chainhash.NewHashFromStr(shash)
			if err != nil {
				return err
			}

			count, ok := params[1].(float64)
			if !ok {
				panic("unexpected param type")
			}

			found := -1
			for ki, kss := range f.keystones {
				if hemi.L2KeystoneAbbreviate(kss).Hash().IsEqual(abrevHash) {
					found = ki
				}
			}

			kssResp := L2KeystoneValidityResponse{}
			if found == -1 {
				kssResp.Error = protocol.Errorf("keystone not found: %v", abrevHash)
			} else {
				if found+int(count) >= len(f.keystones) {
					kssResp.L2Keystones = f.keystones[found:]
				} else {
					kssResp.L2Keystones = f.keystones[found : found+int(count)]
				}
			}

			subResp = jsonrpcMessage{
				Version: "2.0",
				ID:      msg.ID,
				Result:  kssResp,
			}

		default:
			return fmt.Errorf("unsupported message %v", msg.Method)
		}
		p, err := json.Marshal(subResp)
		if err != nil {
			return err
		}

		err = c.Write(f.pctx, websocket.MessageText, p)
		if err != nil {
			return err
		}
	}
}

func lastKeystones(n int, keystones []hemi.L2Keystone) []hemi.L2Keystone {
	return keystones[max(0, len(keystones)-n):]
}
