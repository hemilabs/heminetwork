package popm

import (
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/gorilla/websocket"
	"github.com/juju/loggo"
)

var upgrader = websocket.Upgrader{}

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
	Result  string          `json:"result,omitempty"`
}

type jsonError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func handleSubscription(w http.ResponseWriter, r *http.Request) {
	c, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer c.Close()
	for {
		var msg jsonrpcMessage
		err := c.ReadJSON(&msg)
		if err != nil {
			panic(err)
		}

		fakeHeader := types.Header{
			ParentHash:  common.HexToHash("0000H45H"),
			UncleHash:   common.HexToHash("0000H45H"),
			Coinbase:    common.HexToAddress("0000H45H"),
			Root:        common.HexToHash("0000H00H"),
			TxHash:      common.HexToHash("0000H45H"),
			ReceiptHash: common.HexToHash("0000H45H"),
			Difficulty:  big.NewInt(1337),
			Number:      big.NewInt(1337),
			GasLimit:    1338,
			GasUsed:     1338,
			Time:        1338,
			Extra: []byte("Extra data Extra data Extra data  Extra data" +
				"Extra data  Extra data  Extra data Extra data"),
			MixDigest: common.HexToHash("0x0000H45H"),
		}
		encResult := subscriptionResultEnc{
			ID:     "0x5a395650bce324475634d746a831c227",
			Result: fakeHeader,
		}
		subData := jsonrpcSubscriptionNotification{
			Version: "2.0",
			Method:  "eth_subscription",
			Params:  encResult,
		}
		subResp := jsonrpcMessage{
			Version: "2.0",
			ID:      1,
			Result:  "0x5a395650bce324475634d746a831c227",
		}

		err = c.WriteJSON(subResp)
		if err != nil {
			panic(err)
		}

		for {
			time.Sleep(500 * time.Millisecond)
			c.WriteJSON(subData)
			if err != nil {
				panic(err)
			}
		}
	}
}

func TestPopMiner(t *testing.T) {
	var wg sync.WaitGroup

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Create test server with the echo handler.
	opgeth := httptest.NewServer(http.HandlerFunc(handleSubscription))
	defer opgeth.Close()

	// Setup pop miner
	cfg := NewDefaultConfig()
	cfg.BitcoinSecret = "5e2deaa9f1bb2bcef294cc36513c591c5594d6b671fe83a104aa2708bc634c" +
		"b0602599b867332dfec245547baafae40dad247f21564a0de925527f2445a086fd"
	cfg.LogLevel = "popm=TRACE"
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

	time.Sleep(5 * time.Second)
}
