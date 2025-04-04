package popm

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"
	"github.com/hemilabs/heminetwork/api/popapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/juju/loggo"
)

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

type handler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
	errCh      chan error
}

func (f handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f.handleFunc(w, r); err != nil {
		f.errCh <- err
	}
}

func digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

func mockOpgeth(ctx context.Context, t *testing.T) (*httptest.Server, chan string, chan error) {

	msgCh := make(chan string, 10)
	errCh := make(chan error)

	hf := func(w http.ResponseWriter, r *http.Request) error {

		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return err
		}

		defer func() {
			if err := c.Close(websocket.StatusNormalClosure, ""); err != nil {
				t.Logf("error closing websocket: %s", err)
			}
		}()

		for {

			var msg jsonrpcMessage
			_, br, err := c.Read(ctx)
			if err != nil {
				return err
			}
			err = json.Unmarshal(br, &msg)
			if err != nil {
				return err
			}

			t.Logf("command is %s", msg.Method)

			go func() {
				select {
				case <-ctx.Done():
					err = ctx.Err()
					return
				case msgCh <- msg.Method:
				}
			}()

			switch msg.Method {
			case "kss_subscribe":
				subResp := jsonrpcMessage{
					Version: "2.0",
					ID:      1,
					Result:  "0x5a395650bce324475634d746a831c227",
				}

				p, err := json.Marshal(subResp)
				if err != nil {
					return err
				}

				err = c.Write(ctx, websocket.MessageText, p)
				if err != nil {
					return err
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

				go func() {
					p, err := json.Marshal(subNotif)
					if err != nil {
						panic(err)
					}
					for range 3 {
						t.Log("Sending new keystone notification")
						err = c.Write(ctx, websocket.MessageText, p)
						if err != nil {
							panic(err)
						}
					}
				}()
			case "keystone_request":
				l2Keystone := hemi.L2Keystone{
					Version:            1,
					L1BlockNumber:      0xbadc0ffe,
					L2BlockNumber:      0xdeadbeef,
					ParentEPHash:       digest256([]byte{1, 1, 3, 7}),
					PrevKeystoneEPHash: digest256([]byte{0x04, 0x20, 69}),
					StateRoot:          digest256([]byte("Hello, world!")),
					EPHash:             digest256([]byte{0xaa, 0x55}),
				}
				kssResp := popapi.L2KeystoneResponse{
					L2Keystones: []*hemi.L2Keystone{&l2Keystone},
				}
				subResp := jsonrpcMessage{
					Version: "2.0",
					ID:      msg.ID,
					Result:  kssResp,
				}

				p, err := json.Marshal(subResp)
				if err != nil {
					return err
				}

				err = c.Write(ctx, websocket.MessageText, p)
				if err != nil {
					return err
				}
			default:
				t.Errorf("unsupported message %v", msg.Method)
			}

		}
	}

	h := handler{handleFunc: hf, errCh: errCh}

	opgeth := httptest.NewServer(h)
	return opgeth, msgCh, errCh
}

func TestPopMiner(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create test server with the request handler.
	opgeth, msgCh, errCh := mockOpgeth(ctx, t)
	defer opgeth.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.GozerType = "blockstream"
	// This address doesn't have funds so mining will fail
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c" +
		"b0602599b867332dfec245547baafae40dad247f21564a0de925527f2445a086fd"
	// cfg.LogLevel = "popm=TRACE"
	cfg.OpgethURL = "ws" + strings.TrimPrefix(opgeth.URL, "http")
	if err := loggo.ConfigureLoggers(cfg.LogLevel); err != nil {
		t.Fatal(err)
	}

	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Run(ctx); !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	expectedMsg := map[string]int{
		"kss_subscribe":    1,
		"keystone_request": 3,
	}

	for {
		select {
		case err = <-errCh:
			t.Fatal(err)
		case n := <-msgCh:
			expectedMsg[n]--
			finished := true
			for msg, k := range expectedMsg {
				if k > 0 {
					t.Logf("Still missing %v messages of type %s", k, msg)
					finished = false
				}
			}
			if finished {
				t.Log("Received all expected messages")
				return
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
}
