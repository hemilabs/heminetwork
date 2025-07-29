// Copyright (c) 2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package mock

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/coder/websocket"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/hemi"
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

func (f *OpGethMockHandler) handle(c *websocket.Conn, w http.ResponseWriter, r *http.Request, kc *keystoneCounter) (string, error) {
	var msg jsonrpcMessage

	_, rd, err := c.Reader(f.pctx)
	if err != nil {
		return "", fmt.Errorf("reader: %w", err)
	}

	br, err := io.ReadAll(rd)
	if err != nil {
		return "", fmt.Errorf("read: %w", err)
	}

	err = json.Unmarshal(br, &msg)
	if err != nil {
		return "", fmt.Errorf("unmarshal: %w", err)
	}

	log.Infof("%v: command is %v", f.name, msg.Method)

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

				case <-time.Tick(DefaultNtfnDuration):
					if !f.Running() {
						return
					}
					log.Tracef("%v: Sending new keystone notification", f.name)
					err = c.Write(f.pctx, websocket.MessageText, p)
					if err != nil {
						log.Errorf("%v: notification sender: %v", f.name, err.Error())
						return
					}
					kc.increment()
				}
			}
		}()
	case "kss_getLatestKeystones":
		var count []int
		err = json.Unmarshal(msg.Params, &count)
		if err != nil {
			panic(err)
		}
		currCount := kc.count()
		kssResp := L2KeystoneLatestResponse{
			L2Keystones: lastKeystones(count[0], f.keystones[:min(currCount+count[0], len(f.keystones))]),
		}
		subResp = jsonrpcMessage{
			Version: "2.0",
			ID:      msg.ID,
			Result:  kssResp,
		}
		log.Debugf("%v: sending %v last keystones", f.name, len(kssResp.L2Keystones))
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
			panic(err)
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
			kssResp.Error = protocol.NotFoundError("keystone", abrevHash)
		} else {
			desc := make([]hemi.L2Keystone, 0, int(count))
			for i := found; i < len(f.keystones) && i <= found+int(count); i++ {
				desc = append(desc, f.keystones[i])
			}
			kssResp.L2Keystones = desc
		}

		subResp = jsonrpcMessage{
			Version: "2.0",
			ID:      msg.ID,
			Result:  kssResp,
		}

		log.Debugf("%v: sending keystone %v and %v descendants", f.name, shash, len(kssResp.L2Keystones)-1)
	default:
		panic(fmt.Errorf("unsupported message %v", msg.Method))
	}
	p, err := json.Marshal(subResp)
	if err != nil {
		panic(err)
	}

	err = c.Write(f.pctx, websocket.MessageText, p)
	if err != nil {
		return "", fmt.Errorf("write: %w", err)
	}

	return msg.Method, nil
}

type keystoneCounter struct {
	counter int
	mtx     sync.RWMutex
}

func (kc *keystoneCounter) increment() {
	kc.mtx.Lock()
	defer kc.mtx.Unlock()
	kc.counter++
}

func (kc *keystoneCounter) count() int {
	kc.mtx.RLock()
	defer kc.mtx.RUnlock()
	return kc.counter
}

func (f *OpGethMockHandler) mockOpGethHandleFunc(w http.ResponseWriter, r *http.Request) error {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		panic(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

	f.mtx.Lock()
	f.conns = append(f.conns, c) // XXX don't we need to reap this?
	f.mtx.Unlock()

	log.Infof("%v: new connection to %v", f.name, r.RemoteAddr)

	var kc keystoneCounter
	for {
		// Handle command
		method, err := f.handle(c, w, r, &kc)
		if err != nil {
			log.Errorf("exiting mockOpGethHandleFunc: %v", err)
			return err
		}
		f.notifyMsg(f.pctx, method)
	}
}

func lastKeystones(n int, keystones []hemi.L2Keystone) []hemi.L2Keystone {
	return keystones[max(0, len(keystones)-n):]
}
