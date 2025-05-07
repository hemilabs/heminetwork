package testutil

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/coder/websocket"
	"github.com/ethereum/go-ethereum/eth"

	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/api/tbcapi"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/pop"
)

var defaultNtfnDuration = 1 * time.Second

func MakeSharedKeystones(n int) (map[chainhash.Hash]*hemi.L2KeystoneAbrev, []hemi.L2Keystone) {
	kssList := make([]hemi.L2Keystone, 0, n)
	kssMap := make(map[chainhash.Hash]*hemi.L2KeystoneAbrev, 0)

	prevKeystone := &hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      10000,
		L2BlockNumber:      25,
		PrevKeystoneEPHash: digest256([]byte{0, 0}),
		EPHash:             digest256([]byte{0}),
	}
	for ci := range n {
		x := uint8(ci + 1)
		l2Keystone := hemi.L2Keystone{
			Version:            1,
			L1BlockNumber:      prevKeystone.L1BlockNumber + 1,
			L2BlockNumber:      uint32(ci+1) * 25,
			ParentEPHash:       digest256([]byte{x, x}),
			PrevKeystoneEPHash: prevKeystone.EPHash,
			StateRoot:          digest256([]byte{x, x, x}),
			EPHash:             digest256([]byte{x}),
		}

		abrevKss := hemi.L2KeystoneAbbreviate(l2Keystone)
		kssMap[*abrevKss.Hash()] = abrevKss
		kssList = append(kssList, l2Keystone)
		prevKeystone = &l2Keystone
	}

	return kssMap, kssList
}

func fillOutBytes(prefix string, size int) []byte {
	result := []byte(prefix)
	for len(result) < size {
		result = append(result, 0)
	}

	return result
}

func digest256(x []byte) []byte {
	xx := sha256.Sum256(x)
	return xx[:]
}

// Opgeth RPC Messages structs

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

type mockHandler struct {
	handleFunc func(w http.ResponseWriter, r *http.Request) error
	errCh      chan error
	msgCh      chan string
	name       string
	pctx       context.Context
}

func (f mockHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if err := f.handleFunc(w, r); err != nil {
		f.errCh <- fmt.Errorf("%s error: %w", f.name, err)
	}
}

type TBCMockHandler struct {
	mockHandler
	keystones map[chainhash.Hash]*hemi.L2KeystoneAbrev
	btcTip    uint
}

type OpGethMockHandler struct {
	mockHandler
	keystones []hemi.L2Keystone
}

func NewMockTBC(pctx context.Context, keystones map[chainhash.Hash]*hemi.L2KeystoneAbrev, btcTip uint) (chan string, chan error, *httptest.Server) {
	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

	th := TBCMockHandler{
		mockHandler: mockHandler{
			errCh: errCh,
			msgCh: msgCh,
			name:  "mockTBC",
			pctx:  pctx,
		},
		keystones: keystones,
		btcTip:    btcTip,
	}
	th.handleFunc = th.mockTBCHandleFunc

	tbc := httptest.NewServer(th)
	return msgCh, errCh, tbc
}

func NewMockOpGeth(pctx context.Context, keystones []hemi.L2Keystone) (chan string, chan error, *httptest.Server) {
	errCh := make(chan error, 10)
	msgCh := make(chan string, 10)

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
		},
		keystones: keystones,
	}
	th.handleFunc = th.mockOpGethHandleFunc

	tbc := httptest.NewServer(th)
	return msgCh, errCh, tbc
}

func (f TBCMockHandler) mockTBCHandleFunc(w http.ResponseWriter, r *http.Request) error {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		return fmt.Errorf("failed to accept websocket connection for %s: %w",
			r.RemoteAddr, err)
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

	// Always ping, required by protocol.
	ping := &tbcapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	wsConn := protocol.NewWSConn(conn)

	if err = tbcapi.Write(r.Context(), wsConn, "0", ping); err != nil {
		return fmt.Errorf("write ping: %w", err)
	}

	fmt.Printf("mockTBC: connection from %v\n", r.RemoteAddr)

	for {
		cmd, id, payload, err := tbcapi.Read(f.pctx, wsConn)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				return fmt.Errorf("handleWebsocketRead: %w", err)
			}
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("handleWebsocketRead: EOF")
			}

			return fmt.Errorf("handleWebsocketRead: %w", err)
		}

		fmt.Printf("mockTBC: command is %v\n", cmd)

		go func() {
			select {
			case <-f.pctx.Done():
				err = f.pctx.Err()
				return
			case f.msgCh <- string(cmd):
			}
		}()

		var resp any
		switch cmd {
		case tbcapi.CmdBlockHeaderBestRequest:
			resp = &tbcapi.BlockHeaderBestResponse{
				Height:      8,
				BlockHeader: nil,
			}
		case tbcapi.CmdUTXOsByAddressRequest:
			resp = &tbcapi.UTXOsByAddressResponse{
				UTXOs: []*tbcapi.UTXO{
					{
						TxId:     chainhash.Hash{},
						Value:    1000000,
						OutIndex: 1,
					},
				},
			}
		case tbcapi.CmdTxBroadcastRequest:
			pl, ok := payload.(*tbcapi.TxBroadcastRequest)
			if !ok {
				return fmt.Errorf("unexpected payload format: %v", payload)
			}

			ph := make([]byte, 32)
			_, err := rand.Read(ph)
			if err != nil {
				panic(err)
			}

			ch, err := chainhash.NewHash(ph)
			if err != nil {
				panic(ch)
			}
			resp = tbcapi.TxBroadcastResponse{TxID: ch}

			for _, txOut := range pl.Tx.TxOut {
				aPoPTx, err := pop.ParseTransactionL2FromOpReturn(txOut.PkScript)
				if err != nil {
					continue
				}
				f.keystones[*aPoPTx.L2Keystone.Hash()] = aPoPTx.L2Keystone
				break
			}
		case tbcapi.CmdBlockKeystoneByL2KeystoneAbrevHashRequest:
			pl, ok := payload.(*tbcapi.BlockKeystoneByL2KeystoneAbrevHashRequest)
			if !ok {
				return fmt.Errorf("unexpected payload format: %v", payload)
			}

			kss, ok := f.keystones[pl.L2KeystoneAbrevHash]
			if !ok {
				resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
					Error: protocol.Errorf("unknown keystone: %v", pl.L2KeystoneAbrevHash),
				}
			} else {
				ch, err := chainhash.NewHash(digest256([]byte{byte(kss.L1BlockNumber)}))
				if err != nil {
					panic(err)
				}
				tch, err := chainhash.NewHash(digest256([]byte{byte(f.btcTip)}))
				if err != nil {
					panic(err)
				}
				resp = &tbcapi.BlockKeystoneByL2KeystoneAbrevHashResponse{
					L2KeystoneAbrev:       kss,
					L2KeystoneBlockHash:   ch,
					L2KeystoneBlockHeight: uint(kss.L1BlockNumber),
					BtcTipBlockHash:       tch,
					BtcTipBlockHeight:     f.btcTip,
				}
			}
		case tbcapi.CmdFeeEstimateRequest:
			resp = tbcapi.FeeEstimateResponse{
				FeeEstimates: []*tbcapi.FeeEstimate{
					{Blocks: 1, SatsPerByte: 1},
					{Blocks: 2, SatsPerByte: 1},
					{Blocks: 3, SatsPerByte: 1},
					{Blocks: 4, SatsPerByte: 1},
					{Blocks: 5, SatsPerByte: 1},
					{Blocks: 6, SatsPerByte: 1},
					{Blocks: 7, SatsPerByte: 1},
					{Blocks: 8, SatsPerByte: 1},
					{Blocks: 9, SatsPerByte: 1},
					{Blocks: 10, SatsPerByte: 1},
				},
			}
		default:
			return fmt.Errorf("unknown command: %v", cmd)
		}

		if err = tbcapi.Write(f.pctx, wsConn, id, resp); err != nil {
			return fmt.Errorf("failed to handle %s request: %w",
				cmd, err)
		}
	}
}

func (f OpGethMockHandler) mockOpGethHandleFunc(w http.ResponseWriter, r *http.Request) error {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return err
	}

	defer c.Close(websocket.StatusNormalClosure, "") // Force close connection

	fmt.Printf("mockOpgeth: connection from %v\n", r.RemoteAddr)

	for i := 1; ; i++ {

		var msg jsonrpcMessage
		_, br, err := c.Read(f.pctx)
		if err != nil {
			return err
		}
		err = json.Unmarshal(br, &msg)
		if err != nil {
			return err
		}

		fmt.Printf("mockOpgeth: command is %s\n", msg.Method)

		go func() {
			select {
			case <-f.pctx.Done():
				err = f.pctx.Err()
				return
			case f.msgCh <- msg.Method:
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

			err = c.Write(f.pctx, websocket.MessageText, p)
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

			fmt.Println("Sending new keystone notification")
			err = c.Write(f.pctx, websocket.MessageText, p)
			if err != nil {
				return err
			}

			go func() {
				p, err := json.Marshal(subNotif)
				if err != nil {
					panic(err)
				}
				for {
					select {
					case <-f.pctx.Done():
						return
					case <-time.After(defaultNtfnDuration):
						fmt.Println("Sending new keystone notification")
						err = c.Write(f.pctx, websocket.MessageText, p)
						if err != nil {
							fmt.Println(err.Error())
							return
						}
					}
				}
			}()
		case "kss_getLatestKeystones":
			var count []int
			err = json.Unmarshal(msg.Params, &count)
			if err != nil {
				panic(err)
			}

			kssResp := eth.L2KeystoneLatestResponse{
				L2Keystones: f.keystones[i : i+count[0]],
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

			err = c.Write(f.pctx, websocket.MessageText, p)
			if err != nil {
				return err
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
				if *abrevHash == *hemi.L2KeystoneAbbreviate(kss).Hash() {
					found = ki
				}
			}

			kssResp := eth.L2KeystoneValidityResponse{}
			if found == -1 {
				kssResp.Error = protocol.Errorf("keystone not found: %v", abrevHash)
			} else {
				if found+int(count) >= len(f.keystones) {
					kssResp.L2Keystones = f.keystones[found:]
				} else {
					kssResp.L2Keystones = f.keystones[found : found+int(count)]
				}
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

			err = c.Write(f.pctx, websocket.MessageText, p)
			if err != nil {
				return err
			}

		default:
			return fmt.Errorf("unsupported message %v", msg.Method)
		}

	}
}
