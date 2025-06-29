// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package e2e_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	mathrand "math/rand/v2"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil"
	btcchaincfg "github.com/btcsuite/btcd/chaincfg"
	btcchainhash "github.com/btcsuite/btcd/chaincfg/chainhash"
	btctxscript "github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/davecgh/go-spew/spew"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	dcrecdsa "github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-test/deep"

	"github.com/hemilabs/heminetwork/api"
	"github.com/hemilabs/heminetwork/api/auth"
	"github.com/hemilabs/heminetwork/api/bfgapi"
	"github.com/hemilabs/heminetwork/api/bssapi"
	"github.com/hemilabs/heminetwork/api/protocol"
	"github.com/hemilabs/heminetwork/database/bfgd"
	"github.com/hemilabs/heminetwork/database/bfgd/postgres"
	"github.com/hemilabs/heminetwork/ethereum"
	"github.com/hemilabs/heminetwork/hemi"
	"github.com/hemilabs/heminetwork/hemi/electrs"
	"github.com/hemilabs/heminetwork/hemi/pop"
	"github.com/hemilabs/heminetwork/service/bfg"
	"github.com/hemilabs/heminetwork/service/bss"
	"github.com/hemilabs/heminetwork/testutil"
)

const (
	testDBPrefix              = "e2e_ext_test_db_"
	mockEncodedBlockHeader    = "\"0000c02048cd664586152c3dcf356d010cbb9216fdeb3b1aeae256d59a0700000000000086182c855545356ec11d94972cf31b97ef01ae7c9887f4349ad3f0caf2d3c0b118e77665efdf2819367881fb\""
	mockTxHash                = "7fe9c3262f8fe26764b01955b4c996296f7c0c72945af1556038a084fcb37dbb"
	mockTxPos                 = 3
	mockTxheight              = 10
	mockElectrsConnectTimeout = 3 * time.Second
)

var mockMerkleHashes = []string{
	"2ab69ae0bb89b378c7ffa5e3b08389002d08394c6eba21f5655e32e1f60b6261",
	"18b2c85e1159d6945eb0b3adab5fef7dc4ab8a04089736c5f3abc5c0e68e7c89",
	"a0bead79e8ef526e5e96656e7096055e52c059d92834944e7e37131198aae527",
	"01ed7fae1204d5ba058dbb15caf03d253198db053e4bb7bb2f7ec6da7f66a433",
	"08cba6d9e9d436a5c76289571795be59b44e61cc0e12d037ec46cae69bae2c09",
	"d5c8f9a5257818bf44961b9aedb8602b1fa9000423ee9aede5eeec1d65f197ee",
	"d0e8c725b128222b6d284320f5a24c9d49df4270c9c749ee57a104d5e3206b68",
}

var minerPrivateKeyBytes = []byte{1, 2, 3, 4, 5, 6, 7, 199} // XXX make this a real hardcoded key

type bssWs struct { // XXX: use protocol.WSConn directly
	conn *protocol.WSConn
}

type bfgWs bssWs // XXX: use protocol.WSConn directly

// Setup some private keys and authenticators
var (
	privateKey *secp256k1.PrivateKey
	authClient *auth.Secp256k1Auth
)

func init() {
	var err error
	privateKey, err = secp256k1.GeneratePrivateKey()
	if err != nil {
		panic(err)
	}

	authClient, err = auth.NewSecp256k1AuthClient(privateKey)
	if err != nil {
		panic(err)
	}
}

func EnsureCanConnect(t *testing.T, url string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(t.Context(), timeout)
	defer cancel()

	t.Logf("connecting to %s", url)

	var err error

	doneCh := make(chan bool)
	go func() {
		for {
			c, _, err := websocket.Dial(ctx, url, nil)
			if err != nil {
				time.Sleep(1 * time.Second)
				continue
			}
			c.CloseNow()
			doneCh <- true
		}
	}()

	select {
	case <-doneCh:
	case <-ctx.Done():
		return fmt.Errorf("timed out trying to reach WS server in tests, last error: %w", err)
	}

	return nil
}

func EnsureCanConnectTCP(t *testing.T, addr string, timeout time.Duration) error {
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return err
	}

	conn.Close()
	return nil
}

func applySQLFiles(ctx context.Context, t *testing.T, sdb *sql.DB, path string) {
	t.Helper()

	sqlFiles, err := filepath.Glob(path)
	if err != nil {
		t.Fatalf("Failed to get schema files: %v", err)
	}
	sort.Strings(sqlFiles)

	for _, sqlFile := range sqlFiles {
		t.Logf("Applying SQL file %v", filepath.Base(sqlFile))
		sql, err := os.ReadFile(sqlFile)
		if err != nil {
			t.Fatalf("Failed to read SQL file: %v", err)
		}
		if _, err := sdb.ExecContext(ctx, string(sql)); err != nil {
			t.Fatalf("Failed to execute SQL: %v", err)
		}
	}
}

func getPgUri(t *testing.T) string {
	pgURI := os.Getenv("PGTESTURI")
	if pgURI == "" {
		t.Skip("PGTESTURI environment variable is not set, skipping...")
	}

	return pgURI
}

func createTestDB(ctx context.Context, t *testing.T) (bfgd.Database, string, *sql.DB, func()) {
	t.Helper()

	pgURI := getPgUri(t)

	var (
		cleanup     func()
		ddb, sdb    *sql.DB
		needCleanup = true
	)
	defer func() {
		if !needCleanup {
			return
		}
		if sdb != nil {
			sdb.Close()
		}
		if cleanup != nil {
			cleanup()
		}
		if ddb != nil {
			ddb.Close()
		}
	}()

	ddb, err := postgres.Connect(ctx, pgURI)
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	dbn := mathrand.IntN(999999999)
	dbName := fmt.Sprintf("%v_%d", testDBPrefix, dbn)

	t.Logf("Creating test database %v", dbName)

	qCreateDB := fmt.Sprintf("CREATE DATABASE %v", dbName)
	if _, err := ddb.ExecContext(ctx, qCreateDB); err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	cleanup = func() {
		t.Logf("Removing test database %v", dbName)
		qDropDB := fmt.Sprintf("DROP DATABASE %v WITH (FORCE)", dbName)
		if _, err := ddb.ExecContext(ctx, qDropDB); err != nil {
			t.Fatalf("Failed to drop test database: %v", err)
		}
		ddb.Close()
	}

	u, err := url.Parse(pgURI)
	if err != nil {
		t.Fatalf("Failed to parse postgresql URI: %v", err)
	}
	u.Path = dbName

	sdb, err = postgres.Connect(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	// Load schema.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	applySQLFiles(ctx, t, sdb, filepath.Join(wd, "./../database/bfgd/scripts/*.sql"))

	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("Failed to connect to database: %v", err)
	}

	if dbVersion, err := db.Version(ctx); err != nil {
		t.Fatalf("Failed to obtain database version: %v", err)
	} else {
		t.Logf("Database version: %v", dbVersion)
	}

	needCleanup = false

	return db, u.String(), sdb, cleanup
}

func createBfgServerWithAccess(ctx context.Context, t *testing.T, pgUri string, electrsAddr string, btcStartHeight uint64, otherBfgUrl string, publicDisabled bool) (*bfg.Server, string, string, string) {
	bfgPrivateListenAddress := fmt.Sprintf(":%v", testutil.FreePort())
	bfgPublicListenAddress := fmt.Sprintf(":%v", testutil.FreePort())

	cfg := &bfg.Config{
		PrivateListenAddress: bfgPrivateListenAddress,
		PublicListenAddress:  bfgPublicListenAddress,
		PgURI:                pgUri,
		EXBTCAddress:         electrsAddr,
		BTCStartHeight:       btcStartHeight,
		RequestLimit:         bfgapi.DefaultRequestLimit,
		RequestTimeout:       bfgapi.DefaultRequestTimeout,
		BFGURL:               otherBfgUrl,
		DisablePublicConns:   publicDisabled,
	}

	if cfg.BFGURL != "" {
		privKey, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatal(err)
		}

		cfg.BTCPrivateKey = hex.EncodeToString(privKey.Serialize())
	}

	bfgServer, err := bfg.NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := bfgServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	bfgWsPrivateUrl := fmt.Sprintf("http://localhost%s%s", bfgPrivateListenAddress, bfgapi.RouteWebsocketPrivate)
	bfgWsPublicUrl := fmt.Sprintf("http://localhost%s%s", bfgPublicListenAddress, bfgapi.RouteWebsocketPublic)

	if err := EnsureCanConnect(t, bfgWsPrivateUrl, 5*time.Second); err != nil {
		t.Fatalf("could not connect to %s: %s", bfgWsPrivateUrl, err.Error())
	}

	if err := EnsureCanConnect(t, bfgWsPublicUrl, 5*time.Second); err != nil {
		t.Fatalf("could not connect to %s: %s", bfgWsPublicUrl, err.Error())
	}

	return bfgServer, bfgPrivateListenAddress, bfgWsPrivateUrl, bfgWsPublicUrl
}

func createBfgServerGeneric(ctx context.Context, t *testing.T, pgUri string, electrsAddr string, btcStartHeight uint64, otherBfgUrl string) (*bfg.Server, string, string, string) {
	return createBfgServerWithAccess(ctx, t, pgUri, electrsAddr, btcStartHeight, otherBfgUrl, false)
}

func createBfgServer(ctx context.Context, t *testing.T, pgUri string, electrsAddr string, btcStartHeight uint64) (*bfg.Server, string, string, string) {
	return createBfgServerGeneric(ctx, t, pgUri, electrsAddr, btcStartHeight, "")
}

// func createBfgServerConnectedToAnother(ctx context.Context, t *testing.T, pgUri string, electrsAddr string, btcStartHeight uint64, otherBfgUrl string) (*bfg.Server, string, string)
// 	return createBfgServerGeneric(ctx, t, pgUri, electrsAddr, btcStartHeight, otherBfgUrl)
// }

func createBssServer(ctx context.Context, t *testing.T, bfgWsurl string) (*bss.Server, string, string) {
	bssListenAddress := fmt.Sprintf(":%v", testutil.FreePort())

	bssServer, err := bss.NewServer(&bss.Config{
		BFGURL:        bfgWsurl,
		ListenAddress: bssListenAddress,
	})
	if err != nil {
		t.Fatal(err)
	}

	go func() {
		err := bssServer.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) {
			panic(err)
		}
	}()

	bssWsurl := fmt.Sprintf("http://localhost%s%s", bssListenAddress, bssapi.RouteWebsocket)
	err = EnsureCanConnect(t, bssWsurl, 5*time.Second)
	if err != nil {
		t.Fatalf("could not connect to %s: %s", bssWsurl, err.Error())
	}

	return bssServer, bssListenAddress, bssWsurl
}

func reverseAndEncodeEncodedHash(encodedHash string) string {
	rev, err := hex.DecodeString(encodedHash)
	if err != nil {
		panic(err)
	}

	return hex.EncodeToString(rev)
}

func createMockElectrsServer(ctx context.Context, t *testing.T, l2Keystone *hemi.L2Keystone, btx []byte) (string, func()) {
	addr := fmt.Sprintf("localhost:%v", testutil.FreePort())

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		listener.Close()
	}

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			conn, err := listener.Accept()

			// annoyingly, we have to compare the error string here
			if err != nil && strings.Contains(err.Error(), "use of closed network connection") {
				time.Sleep(100 * time.Millisecond)
				continue
			}

			if err != nil {
				panic(err)
			}

			go handleMockElectrsConnection(ctx, t, conn, btx)
		}
	}()

	return addr, cleanup
}

func handleMockElectrsConnection(ctx context.Context, t *testing.T, conn net.Conn, btx []byte) {
	mb := wire.MsgTx{}
	if err := mb.Deserialize(bytes.NewBuffer(btx)); err != nil {
		panic(fmt.Sprintf("failed to deserialize tx: %v", err))
	}

	t.Helper()
	defer conn.Close()

	t.Logf("Handling connection: %s", conn.RemoteAddr())

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := make([]byte, 1000)
		n, err := conn.Read(buf)
		if err != nil {
			t.Logf(
				"error occurred reading from conn, will listen again: %s",
				err.Error(),
			)
			return
		}

		req := electrs.JSONRPCRequest{}
		err = json.Unmarshal(buf[:n], &req)
		if err != nil {
			panic(err)
		}

		res := electrs.JSONRPCResponse{}
		if req.Method == "blockchain.transaction.broadcast" {
			res.ID = req.ID
			res.Error = ""
			res.Result = json.RawMessage([]byte(fmt.Sprintf("\"%s\"", mb.TxID())))
		}

		if req.Method == "blockchain.headers.subscribe" {
			res.ID = req.ID
			res.Error = ""
			headerNotification := electrs.HeaderNotification{
				Height:       mockTxheight,
				BinaryHeader: "aaaa",
			}

			b, err := json.Marshal(&headerNotification)
			if err != nil {
				panic(err)
			}

			res.Result = b
		}

		if req.Method == "blockchain.block.header" {
			res.ID = req.ID
			res.Error = ""
			res.Result = json.RawMessage([]byte(mockEncodedBlockHeader))
		}

		if req.Method == "blockchain.transaction.id_from_pos" {
			res.ID = req.ID
			res.Error = ""

			params := []any{}

			err := json.Unmarshal(req.Params, &params)
			if err != nil {
				panic(err)
			}

			result := struct {
				TXHash string   `json:"tx_hash"`
				Merkle []string `json:"merkle"`
			}{}

			t.Logf("checking height %d, pos %d", params[0], params[1])

			if params[0].(float64) == mockTxheight && params[1].(float64) == mockTxPos {
				result.TXHash = reverseAndEncodeEncodedHash(mb.TxID())
				result.Merkle = mockMerkleHashes
			}

			// pretend that there are no transactions past mockTxHeight
			// and mockTxPos
			if params[0].(float64) >= mockTxheight && params[1].(float64) > mockTxPos {
				res.Error = "no tx at position"
			}

			b, err := json.Marshal(&result)
			if err != nil {
				panic(err)
			}

			res.Result = b
		}

		if req.Method == "blockchain.transaction.get" {
			res.ID = req.ID
			res.Error = ""

			params := []any{}

			err := json.Unmarshal(req.Params, &params)
			if err != nil {
				panic(err)
			}

			if params[0] == reverseAndEncodeEncodedHash(mb.TxID()) {
				j, err := json.Marshal(hex.EncodeToString(btx))
				if err != nil {
					panic(err)
				}
				res.Result = j
			}
		}

		if req.Method == "blockchain.scripthash.get_balance" {
			res.ID = req.ID
			res.Error = ""
			j, err := json.Marshal(electrs.Balance{
				Confirmed:   1,
				Unconfirmed: 2,
			})
			if err != nil {
				panic(err)
			}

			res.Result = j
		}

		if req.Method == "blockchain.headers.subscribe" {
			res.ID = req.ID
			res.Error = ""
			j, err := json.Marshal(electrs.HeaderNotification{
				Height: 10,
			})
			if err != nil {
				panic(err)
			}
			res.Result = j
		}

		if req.Method == "blockchain.scripthash.listunspent" {
			res.ID = req.ID
			res.Error = ""
			hash := []byte{
				1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2, 3, 4, 5, 6,
				7, 8, 9, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1, 2,
			}
			j := []struct {
				Hash   string `json:"tx_hash"`
				Height uint64 `json:"height"`
				Index  uint64 `json:"tx_pos"`
				Value  uint64 `json:"value"`
			}{{
				Height: 99,
				Hash:   hex.EncodeToString(hash),
				Index:  9999,
				Value:  999999,
			}}

			b, err := json.Marshal(j)
			if err != nil {
				panic(err)
			}

			res.Result = b
		}

		b, err := json.Marshal(res)
		if err != nil {
			panic(err)
		}

		b = append(b, '\n')
		_, err = io.Copy(conn, bytes.NewReader(b))
		if err != nil {
			panic(err)
		}
	}
}

func defaultTestContext(t *testing.T) (context.Context, context.CancelFunc) {
	return context.WithTimeout(t.Context(), 30*time.Second)
}

// assertPing is a short helper method to assert reading a ping after connecting
func assertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command) {
	var v protocol.Message
	err := wsjson.Read(ctx, c, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != cmd {
		t.Fatalf("unexpected command: %s", v.Header.Command)
	}
}

func bfgdL2KeystoneToHemiL2Keystone(l2KeystoneSavedDB *bfgd.L2Keystone) *hemi.L2Keystone {
	return &hemi.L2Keystone{
		Version:            uint8(l2KeystoneSavedDB.Version),
		L1BlockNumber:      l2KeystoneSavedDB.L1BlockNumber,
		L2BlockNumber:      l2KeystoneSavedDB.L2BlockNumber,
		ParentEPHash:       api.ByteSlice(l2KeystoneSavedDB.ParentEPHash),
		PrevKeystoneEPHash: api.ByteSlice(l2KeystoneSavedDB.PrevKeystoneEPHash),
		StateRoot:          api.ByteSlice(l2KeystoneSavedDB.StateRoot),
		EPHash:             api.ByteSlice(l2KeystoneSavedDB.EPHash),
	}
}

func createBtcTx(t *testing.T, btcHeight uint64, l2Keystone *hemi.L2Keystone, minerPrivateKeyBytes []byte) []byte {
	btx := &wire.MsgTx{
		Version:  2,
		LockTime: uint32(btcHeight),
	}

	popTx := pop.TransactionL2{
		L2Keystone: hemi.L2KeystoneAbbreviate(*l2Keystone),
	}

	popTxOpReturn, err := popTx.EncodeToOpReturn()
	if err != nil {
		t.Fatal(err)
	}

	privateKey := secp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)
	publicKey := privateKey.PubKey()
	pubKeyBytes := publicKey.SerializeCompressed()
	btcAddress, err := btcutil.NewAddressPubKey(pubKeyBytes, &btcchaincfg.TestNet3Params)
	if err != nil {
		t.Fatal(err)
	}

	payToScript, err := btctxscript.PayToAddrScript(btcAddress.AddressPubKeyHash())
	if err != nil {
		t.Fatal(err)
	}

	if len(payToScript) != 25 {
		t.Fatalf("incorrect length for pay to public key script (%d != 25)", len(payToScript))
	}

	outPoint := wire.OutPoint{Hash: btcchainhash.Hash(testutil.FillBytes("hash", 32)), Index: 0}
	btx.TxIn = []*wire.TxIn{wire.NewTxIn(&outPoint, payToScript, nil)}

	changeAmount := int64(100)
	btx.TxOut = []*wire.TxOut{wire.NewTxOut(changeAmount, payToScript)}

	btx.TxOut = append(btx.TxOut, wire.NewTxOut(0, popTxOpReturn))

	sig := dcrecdsa.Sign(privateKey, []byte{})
	sigBytes := append(sig.Serialize(), byte(btctxscript.SigHashAll))
	sigScript, err := btctxscript.NewScriptBuilder().AddData(sigBytes).AddData(pubKeyBytes).Script()
	if err != nil {
		t.Fatal(err)
	}
	btx.TxIn[0].SignatureScript = sigScript

	var buf bytes.Buffer
	if err := btx.Serialize(&buf); err != nil {
		t.Fatal(err)
	}

	return buf.Bytes()
}

func TestBFGPublicDisabled(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServerWithAccess(ctx, t, pgUri, "", 1, "", true)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	err = authClient.HandshakeClient(ctx, protocol.NewWSConn(c))

	if err == nil {
		t.Fatal("expected error")
	}

	if !errors.Is(err, protocol.ErrPublicKeyAuth) {
		t.Fatal("expected ErrPublicKeyAuth")
	}
	if !strings.Contains(err.Error(), "status = StatusCode(4100)") {
		t.Fatal(err)
	}
}

// TestNewL2Keystone sends an L2Keystone, via websocket, to BSS which proxies
// it to BFG.  This test then ensures that L2Keystone was saved in the db
// 1. Create a new L2Keystone
// 2. Send aforementioned L2Keystone to BSS via websocket
// 3. Query database to ensure that the L2Keystone was saved
func TestNewL2Keystone(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	// 1
	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	l2KeystoneRequest := bssapi.L2KeystoneRequest{
		L2Keystone: l2Keystone,
	}

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	// 2
	err = bssapi.Write(ctx, bws.conn, "someid", l2KeystoneRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message

	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bssapi.CmdL2KeystoneResponse {
			break
		}
	}

	l2KeystoneAbrevHash := hemi.L2KeystoneAbbreviate(l2KeystoneRequest.L2Keystone).HashB()

	time.Sleep(2 * time.Second)

	// 3
	l2KeystoneSavedDB, err := db.L2KeystoneByAbrevHash(ctx, [32]byte(l2KeystoneAbrevHash))
	if err != nil {
		t.Fatal(err)
	}

	l2KeystoneSaved := bfgdL2KeystoneToHemiL2Keystone(l2KeystoneSavedDB)

	diff := deep.Equal(l2KeystoneSaved, &l2Keystone)
	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

// TestL2Keystone tests getting the latest L2Keystones from the db
// and ensuring the are ordered by L2BlockNumber
// 1. Create multiple L2Keystones with different L2BlockNumbers
// 2. Insert aforementioned L2Keystones into database
// 3. Query BFG via http json rpc for latest keystones
// 4. Assert that the saved keystones are returned ordered by L2BlockNumber desc
func TestL2Keystone(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, "", 1)

	keystoneOneHash := testutil.FillBytes("somehashone", 32)
	keystoneTwoHash := testutil.FillBytes("somehashtwo", 32)

	// 1
	keystoneOne := bfgd.L2Keystone{
		Hash:               keystoneOneHash,
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephashone", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
		StateRoot:          testutil.FillBytes("staterootone", 32),
		EPHash:             testutil.FillBytes("ephashone", 32),
	}

	keystoneTwo := bfgd.L2Keystone{
		Hash:               keystoneTwoHash,
		Version:            1,
		L1BlockNumber:      33,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephashtwo", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashtwo", 32),
		StateRoot:          testutil.FillBytes("stateroottwo", 32),
		EPHash:             testutil.FillBytes("ephashtwo", 32),
	}

	// 2
	err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{
		keystoneOne,
		keystoneTwo,
	})
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(2 * time.Second)

	l2KeystonesRequest := bfgapi.L2KeystonesRequest{
		NumL2Keystones: 5,
	}

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	// 2
	err = bfgapi.Write(ctx, bws.conn, "someid", l2KeystonesRequest)
	if err != nil {
		t.Fatal(err)
	}

	var response any
	var command protocol.Command

	for {
		command, _, response, err = bfgapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		// there is a chance we get notifications from the L2KeystonesInsert
		// call above, if they haven't been broadcast yet.  ignore those.
		if command == bfgapi.CmdL2KeystonesNotification {
			continue
		}

		if command != bfgapi.CmdL2KeystonesResponse {
			t.Fatalf("unexpected command %s", command)
		}

		break
	}

	l2KeystonesResponse := response.(*bfgapi.L2KeystonesResponse)

	// 4
	diff := deep.Equal(l2KeystonesResponse, &bfgapi.L2KeystonesResponse{
		L2Keystones: []hemi.L2Keystone{
			*bfgdL2KeystoneToHemiL2Keystone(&keystoneTwo),
			*bfgdL2KeystoneToHemiL2Keystone(&keystoneOne),
		},
	})

	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestPublicPing(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, "", 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)
}

func TestBitcoinBalance(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, nil, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	sh := make([]byte, 32)
	_, err = rand.Read(sh)
	if err != nil {
		t.Fatal(err)
	}

	if err := bfgapi.Write(ctx, bws.conn, "someid", &bfgapi.BitcoinBalanceRequest{
		ScriptHash: sh,
	}); err != nil {
		t.Fatal(err)
	}

	command, _, v, err := bfgapi.Read(ctx, bws.conn)
	if err != nil {
		t.Fatal(err)
	}
	bitcoinBalanceResponse := v.(*bfgapi.BitcoinBalanceResponse)

	if command != bfgapi.CmdBitcoinBalanceResponse {
		t.Fatalf("unexpected command: %s", command)
	}

	if diff := deep.Equal(bitcoinBalanceResponse, &bfgapi.BitcoinBalanceResponse{
		Unconfirmed: 2,
		Confirmed:   1,
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestBFGPublicErrorCases(t *testing.T) {
	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	type testTableItem struct {
		name          string
		expectedError string
		requests      any
		electrs       bool
		skip          bool
	}

	testTable := []testTableItem{
		{
			name:          "bitcoin balance error",
			expectedError: "internal error",
			requests:      []bfgapi.BitcoinBalanceRequest{},
			electrs:       false,
		},
		{
			name:          "bitcoin broadcast deserialize error",
			expectedError: "failed to deserialize tx: unexpected EOF",
			requests: []bfgapi.BitcoinBroadcastRequest{
				{
					Transaction: []byte("invalid..."),
				},
			},
			electrs: false,
		},
		{
			name:          "bitcoin broadcast electrs error",
			expectedError: "internal error",
			requests: []bfgapi.BitcoinBroadcastRequest{
				{
					Transaction: btx,
				},
			},
			electrs: false,
			skip:    true,
		},
		{
			name:          "bitcoin broadcast database error",
			expectedError: "pop basis already exists",
			requests: []bfgapi.BitcoinBroadcastRequest{
				{
					Transaction: btx,
				},
				{
					Transaction: btx,
				},
			},
			skip:    true,
			electrs: true,
		},
		{
			name:          "bitcoin info electrs error",
			expectedError: "internal error",
			requests: []bfgapi.BitcoinInfoRequest{
				{},
			},
			electrs: false,
			skip:    true,
		},
		{
			name:          "bitcoin utxos electrs error",
			expectedError: "internal error",
			requests: []bfgapi.BitcoinUTXOsRequest{
				{},
			},
			electrs: false,
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			if tti.skip {
				t.Skip()
			}
			db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
			defer func() {
				db.Close()
				sdb.Close()
				cleanup()
			}()

			ctx, cancel := defaultTestContext(t)
			defer cancel()

			electrsAddr := ""
			var cleanupE func()

			if tti.electrs {
				l2Keystone := hemi.L2Keystone{
					Version:            1,
					L1BlockNumber:      5,
					L2BlockNumber:      44,
					ParentEPHash:       testutil.FillBytes("parentephash", 32),
					PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
					StateRoot:          testutil.FillBytes("stateroot", 32),
					EPHash:             testutil.FillBytes("ephash", 32),
				}

				btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

				electrsAddr, cleanupE = createMockElectrsServer(ctx, t, nil, btx)
				defer cleanupE()
				err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
				if err != nil {
					t.Fatal(err)
				}
			}

			_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

			c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseNow()

			protocolConn := protocol.NewWSConn(c)
			if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
				t.Fatal(err)
			}

			assertPing(ctx, t, c, bfgapi.CmdPingRequest)

			bws := &bfgWs{
				conn: protocol.NewWSConn(c),
			}

			requests := reflect.ValueOf(tti.requests)
			for i := range requests.Len() {
				req := requests.Index(i).Interface()
				if err := bfgapi.Write(ctx, bws.conn, "someid", req); err != nil {
					t.Fatal(err)
				}

				_, _, response, err := bfgapi.Read(ctx, bws.conn)
				if err != nil {
					t.Fatal(err)
				}

				// we only care about testing the final response, this allows
				// us to test multiple and duplicate requests
				if i != requests.Len()-1 {
					continue
				}

				switch v := response.(type) {
				case *bfgapi.BitcoinBalanceResponse:
					if v.Error.Message != tti.expectedError {
						t.Fatalf("%s != %s", v.Error.Message, tti.expectedError)
					}
				case *bfgapi.BitcoinBroadcastResponse:
					if v.Error.Message != tti.expectedError {
						t.Fatalf("%s != %s", v.Error.Message, tti.expectedError)
					}
				case *bfgapi.BitcoinInfoResponse:
					if v.Error.Message != tti.expectedError {
						t.Fatalf("%s != %s", v.Error.Message, tti.expectedError)
					}
				case *bfgapi.BitcoinUTXOsResponse:
					if v.Error.Message != tti.expectedError {
						t.Fatalf("%s != %s", v.Error.Message, tti.expectedError)
					}
				default:
					t.Fatalf("cannot determine type %T", v)
				}
			}
		})
	}
}

func TestBitcoinInfo(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, nil, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	sh := make([]byte, 32)
	_, err = rand.Read(sh)
	if err != nil {
		t.Fatal(err)
	}

	time.Sleep(6 * time.Second)

	if err := bfgapi.Write(
		ctx, bws.conn, "someid", &bfgapi.BitcoinInfoRequest{},
	); err != nil {
		t.Fatal(err)
	}

	var v any
	var command protocol.Command

	for {
		command, _, v, err = bfgapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		if command == bfgapi.CmdBitcoinInfoResponse {
			break
		}
	}
	bitcoinInfoResponse := v.(*bfgapi.BitcoinInfoResponse)

	if diff := deep.Equal(bitcoinInfoResponse, &bfgapi.BitcoinInfoResponse{
		Height: 10,
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestBitcoinUTXOs(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, nil, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	sh := make([]byte, 32)
	_, err = rand.Read(sh)
	if err != nil {
		t.Fatal(err)
	}

	if err := bfgapi.Write(ctx, bws.conn, "someid", &bfgapi.BitcoinUTXOsRequest{
		ScriptHash: sh,
	}); err != nil {
		t.Fatal(err)
	}

	command, _, v, err := bfgapi.Read(ctx, bws.conn)
	if err != nil {
		t.Fatal(err)
	}

	if command != bfgapi.CmdBitcoinUTXOsResponse {
		t.Fatalf("unexpected command: %s", command)
	}
	bitcoinUTXOsResponse := v.(*bfgapi.BitcoinUTXOsResponse)

	if diff := deep.Equal(bitcoinUTXOsResponse, &bfgapi.BitcoinUTXOsResponse{
		UTXOs: []*bfgapi.BitcoinUTXO{
			{
				Index: 9999,
				Value: 999999,
				Hash: []byte{
					2, 1, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 10, 9, 8,
					7, 6, 5, 4, 3, 2, 1, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
				},
			},
		},
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

// TestBitcoinBroadcast calls the BitcoinBroadcast RPC on BFG, it then
// ensures the correct fields were saved in pop_basis
// 1. create a bitcoin tx
// 2. call BitcoinBroadcast RPC on BFG
// 3. ensure that a pop_basis was inserted with the expected values
func TestBitcoinBroadcast(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	// 1
	btx := createBtcTx(t, 800, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, nil, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	minerPrivateKeyBytes := []byte{1, 2, 3, 4, 5, 6, 7, 199}

	bitcoinBroadcastRequest := bfgapi.BitcoinBroadcastRequest{
		Transaction: btx,
	}

	mb := wire.MsgTx{}
	if err := mb.Deserialize(bytes.NewBuffer(btx)); err != nil {
		t.Fatalf("failed to deserialize tx: %v", err)
	}

	// 2
	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer c.CloseNow()

	privateKey := secp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)

	authClient, err := auth.NewSecp256k1AuthClient(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	if err := bfgapi.Write(
		ctx, bws.conn, "someid", bitcoinBroadcastRequest,
	); err != nil {
		t.Fatal(err)
	}

	// async now, in a rush, sleep should work
	time.Sleep(2 * time.Second)

	var command protocol.Command
	for {
		command, _, _, err = bfgapi.Read(ctx, bws.conn)
		if err != nil {
			t.Fatal(err)
		}

		if command == bfgapi.CmdBitcoinBroadcastResponse {
			break
		}
	}

	l2k, err := db.L2KeystonesMostRecentN(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}

	// assert that the L2Keystone was stored in the database,
	// IMPORTANT NOTE: since we derive this from a btc pop tx, only the
	// abbreviated keystone is stored.  we still want to store this if we
	// have not seen it before so it's stored with padded 0 bytes. this will
	// go away in the future once we add "missing keystone" logic and
	// functionality
	if diff := deep.Equal(l2k, []bfgd.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytesZero("parentephas", 32),
			PrevKeystoneEPHash: testutil.FillBytesZero("prevkeystone", 32),
			StateRoot:          testutil.FillBytes("stateroot", 32),
			EPHash:             testutil.FillBytesZero("ephash______", 32),
			Hash:               hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
		},
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}

	if len(l2k) != 1 {
		t.Fatalf("unexpected number of keystones: %d", len(l2k))
	}
}

// TestBitcoinBroadcastDuplicate calls BitcoinBroadcast twice with the same
// btc and ensures that only 1 pop_basis was inserted and the proper error code
// is returned upon duplicate attempt
// 1 create btc tx
// 2 call BitcoinBroadcast RPC with aforementioned btx
// 3 ensure that the correct pop_basis was inserted
// 4 repeat BitcoinBroadcast RPC call
// 5 assert error received
func TestBitcoinBroadcastDuplicate(t *testing.T) {
	t.Skip()
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	// 1
	btx := createBtcTx(t, 800, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, nil, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	minerPrivateKeyBytes := []byte{1, 2, 3, 4, 5, 6, 7, 199}

	// 2
	bitcoinBroadcastRequest := bfgapi.BitcoinBroadcastRequest{
		Transaction: btx,
	}

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	privateKey := secp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)

	authClient, err := auth.NewSecp256k1AuthClient(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	// 2
	if err := bfgapi.Write(
		ctx, bws.conn, "someid", bitcoinBroadcastRequest,
	); err != nil {
		t.Fatal(err)
	}

	command, _, _, err := bfgapi.Read(ctx, bws.conn)
	if err != nil {
		t.Fatal(err)
	}

	if command != bfgapi.CmdBitcoinBroadcastResponse {
		t.Fatalf("unexpected command %s", command)
	}

	publicKey := privateKey.PubKey()
	publicKeyUncompressed := publicKey.SerializeUncompressed()

	// 3
	popBases, err := db.PopBasisByL2KeystoneAbrevHash(ctx, [32]byte(hemi.L2KeystoneAbbreviate(l2Keystone).HashB()), false, 0)
	if err != nil {
		t.Fatal(err)
	}

	mb := wire.MsgTx{}
	if err := mb.Deserialize(bytes.NewBuffer(btx)); err != nil {
		t.Fatalf("failed to deserialize tx: %v", err)
	}

	btcTxId := mb.TxHash()

	diff := deep.Equal(popBases, []bfgd.PopBasis{
		{
			L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcRawTx:            btx,
			BtcTxId:             btcTxId[:],
			BtcMerklePath:       nil,
			BtcHeaderHash:       nil,
			PopTxId:             nil,
			BtcTxIndex:          nil,
		},
	})

	if len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}

	// 4
	c, _, err = websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn = protocol.NewWSConn(c)

	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws = &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	// 2
	if err := bfgapi.Write(
		ctx, bws.conn, "someid", bitcoinBroadcastRequest,
	); err != nil {
		t.Fatal(err)
	}

	// XXX need a way to check duplicate in response, like bad request 400
	// command, _, _, err = bfgapi.Read(ctx, bws.conn)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// if command != bfgapi.CmdBitcoinBroadcastResponse {
	// 	t.Fatalf("unexpected command %s", command)
	// }

	// // 5
	// if res.StatusCode != 400 {
	// 	t.Fatalf("received bad status code %d, body %s", res.StatusCode, bodyString)
	// }

	// if bodyString != "pop_basis insert failed: duplicate pop block entry: pq: duplicate key value violates unique constraint \"btc_txid_unconfirmed\"\n" {
	// 	t.Fatalf("unexpected error: \"%s\"", bodyString)
	// }
}

// TestProcessBitcoinBlockNewBtcBlock mocks a btc block response from electrs
// server and ensures that the btc block was inserted correctly
// 1 create mock electrs server, by default it will send a mock btc block
// when blockchain.block.header is called
// 2 ensure that btc_block is inserted with correct values.  this is checked on
// an internal timer, so give this a timeout
func TestProcessBitcoinBlockNewBtcBlock(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 800, &l2Keystone, minerPrivateKeyBytes)

	// 1
	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	expectedBtcBlockHeader, err := hex.DecodeString(strings.Replace(mockEncodedBlockHeader, "\"", "", 2))
	if err != nil {
		t.Fatal(err)
	}

	btcHeaderHash := btcchainhash.DoubleHashB(expectedBtcBlockHeader)
	btcHeight := 10
	btcHeader := expectedBtcBlockHeader

	// 2
	// wait a max of 10 seconds (with a resolution of 1 second) for the
	// btc_block to be inserted into the db.  this happens on a timer
	// when checking electrs
	lctx, lcancel := context.WithTimeout(ctx, 10*time.Second)
	defer lcancel()
	var btcBlockHeader *bfgd.BtcBlock
loop:
	for {
		select {
		case <-lctx.Done():
			t.Fatal(lctx.Err())
		case <-time.After(1 * time.Second):
			btcBlockHeader, err = db.BtcBlockByHash(ctx, [32]byte(btcHeaderHash))
			if err == nil {
				break loop
			}
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(btcBlockHeader, &bfgd.BtcBlock{
		Hash:   btcHeaderHash,
		Header: btcHeader,
		Height: uint64(btcHeight),
	})

	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	var l2k []bfgd.L2Keystone
	for {
		l2k, err = db.L2KeystonesMostRecentN(ctx, 100, 0)
		if err != nil {
			t.Fatal(err)
		}
		if l2k != nil {
			break
		}
	}

	// assert that the L2Keystone was stored in the database,
	// IMPORTANT NOTE: since we derive this from a btc pop tx, only the
	// abbreviated keystone is stored.  we still want to store this if we
	// have not seen it before so it's stored with padded 0 bytes. this will
	// go away in the future once we add "missing keystone" logic and
	// functionality
	if diff := deep.Equal(l2k, []bfgd.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytesZero("parentephas", 32),
			PrevKeystoneEPHash: testutil.FillBytesZero("prevkeystone", 32),
			StateRoot:          testutil.FillBytes("stateroot", 32),
			EPHash:             testutil.FillBytesZero("ephash______", 32),
			Hash:               hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
		},
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

// TestProcessBitcoinBlockNewFullPopBasis takes a full btc tx from the mock
// electrs server and ensures that a new full pop_basis was inserted into the
// db
// 1 create btc tx
// 2 run mock electrs, instructing it to use the created btc tx
// 3 query database for newly created pop_basis, this happens on a timer
// 4 ensure pop_basis was inserted and filled out with correct fields
func TestProcessBitcoinBlockNewFullPopBasis(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	// 1
	btx := createBtcTx(t, 199, &l2Keystone, []byte{1, 2, 3})

	// 2
	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	// 3
	// wait a max of 10 seconds (with a resolution of 1 second) for the
	// btc_block to be inserted into the db.  this happens on a timer
	// when checking electrs
	lctx, lcancel := context.WithTimeout(ctx, 10*time.Second)
	defer lcancel()
	var popBases []bfgd.PopBasis
loop:
	for {
		select {
		case <-lctx.Done():
			break loop
		case <-time.After(1 * time.Second):
			popBases, err = db.PopBasisByL2KeystoneAbrevHash(ctx, [32]byte(hemi.L2KeystoneAbbreviate(l2Keystone).HashB()), false, 0)
			if len(popBases) > 0 {
				break loop
			}
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	mb := wire.MsgTx{}
	if err := mb.Deserialize(bytes.NewBuffer(btx)); err != nil {
		t.Fatalf("failed to deserialize tx: %v", err)
	}

	btcTxId := mb.TxHash()

	btcHeader, err := hex.DecodeString(strings.Replace(mockEncodedBlockHeader, "\"", "", 2))
	if err != nil {
		t.Fatal(err)
	}

	btcHeaderHash := btcchainhash.DoubleHashB(btcHeader)

	privateKey := secp256k1.PrivKeyFromBytes([]byte{1, 2, 3})
	publicKey := privateKey.PubKey()
	publicKeyUncompressed := publicKey.SerializeUncompressed()

	var txIndex uint64 = 3

	// 4
	btcTxIdSlice := btcTxId[:]

	popTxIdFull := []byte{}
	popTxIdFull = append(popTxIdFull, btcTxIdSlice...)
	popTxIdFull = append(popTxIdFull, btcHeader...)
	popTxIdFull = binary.AppendUvarint(popTxIdFull, 3)

	popTxId := btcchainhash.DoubleHashB(popTxIdFull)

	diff := deep.Equal([]bfgd.PopBasis{
		{
			BtcTxId:             btcTxIdSlice,
			BtcHeaderHash:       btcHeaderHash,
			BtcTxIndex:          &txIndex,
			PopTxId:             popTxId,
			L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
			BtcRawTx:            btx,
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcMerklePath:       mockMerkleHashes,
		},
	}, popBases)

	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}

	l2k, err := db.L2KeystonesMostRecentN(ctx, 100, 0)
	if err != nil {
		t.Fatal(err)
	}

	// assert that the L2Keystone was stored in the database,
	// IMPORTANT NOTE: since we derive this from a btc pop tx, only the
	// abbreviated keystone is stored.  we still want to store this if we
	// have not seen it before so it's stored with padded 0 bytes. this will
	// go away in the future once we add "missing keystone" logic and
	// functionality
	if diff := deep.Equal(l2k, []bfgd.L2Keystone{
		{
			Version:            1,
			L1BlockNumber:      5,
			L2BlockNumber:      44,
			ParentEPHash:       testutil.FillBytesZero("parentephas", 32),
			PrevKeystoneEPHash: testutil.FillBytesZero("prevkeystone", 32),
			StateRoot:          testutil.FillBytes("stateroot", 32),
			EPHash:             testutil.FillBytesZero("ephash______", 32),
			Hash:               hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
		},
	}); len(diff) > 0 {
		t.Fatalf("unexpected diff: %s", diff)
	}
}

// TestBitcoinBroadcastThenUpdate will insert a pop_basis record from
// BitcoinBroadcast RPC call to BFG.  Then wait for electrs to send full
// information about that pop_basis from a pop tx.  then assert that the
// pop_basis was filled out correctly
// 1 create a btc tx
// 2 create a mock electrs server that will return that btc tx
// 3 call BitcoinBroadcast RPC call
// 4 wait for full pop_basis to be in database
// 5 assert the pop_basis fields are correct
func TestBitcoinBroadcastThenUpdate(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	// 1
	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)
	mb := wire.MsgTx{}
	if err := mb.Deserialize(bytes.NewBuffer(btx)); err != nil {
		t.Fatalf("failed to deserialize tx: %v", err)
	}

	// 2
	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	err := EnsureCanConnectTCP(t, electrsAddr, mockElectrsConnectTimeout)
	if err != nil {
		t.Fatal(err)
	}

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}

	defer c.CloseNow()

	privateKey := secp256k1.PrivKeyFromBytes(minerPrivateKeyBytes)

	authClient, err := auth.NewSecp256k1AuthClient(privateKey)
	if err != nil {
		t.Fatal(err)
	}

	protocolConn := protocol.NewWSConn(c)
	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	bitcoinBroadcastRequest := bfgapi.BitcoinBroadcastRequest{
		Transaction: btx,
	}

	if err := bfgapi.Write(
		ctx, bws.conn, "someid", bitcoinBroadcastRequest,
	); err != nil {
		t.Fatal(err)
	}

	command, _, _, err := bfgapi.Read(ctx, bws.conn)
	if err != nil {
		t.Fatal(err)
	}

	if command != bfgapi.CmdBitcoinBroadcastResponse {
		t.Fatalf("received wrong command %s", command)
	}

	publicKey := privateKey.PubKey()
	publicKeyUncompressed := publicKey.SerializeUncompressed()

	btcTxId, err := btcchainhash.NewHashFromStr(mb.TxID())
	if err != nil {
		t.Fatal(err)
	}

	// 4
	// wait a max of 10 seconds (with a resolution of 1 second) for the
	// btc_block to be inserted into the db.  this happens on a timer
	// when checking electrs
	lctx, lcancel := context.WithTimeout(ctx, 10*time.Second)
	defer lcancel()
	var popBases []bfgd.PopBasis
loop:
	for {
		select {
		case <-lctx.Done():
			break loop
		case <-time.After(1 * time.Second):
			popBases, err = db.PopBasisByL2KeystoneAbrevHash(ctx, [32]byte(hemi.L2KeystoneAbbreviate(l2Keystone).HashB()), true, 0)
			if len(popBases) > 0 {
				break loop
			}
		}
	}

	if err != nil {
		t.Fatal(err)
	}

	btcHeader, err := hex.DecodeString(strings.Replace(mockEncodedBlockHeader, "\"", "", 2))
	if err != nil {
		t.Fatal(err)
	}

	btcHeaderHash := btcchainhash.DoubleHashB(btcHeader)

	btcTxIdSlice := btcTxId[:]

	popTxIdFull := []byte{}
	popTxIdFull = append(popTxIdFull, btcTxIdSlice...)
	popTxIdFull = append(popTxIdFull, btcHeader...)
	popTxIdFull = binary.AppendUvarint(popTxIdFull, 3)

	popTxId := btcchainhash.DoubleHashB(popTxIdFull)

	var txIndex uint64 = 3

	// 5
	diff := deep.Equal([]bfgd.PopBasis{
		{
			BtcTxId:             btcTxIdSlice,
			BtcHeaderHash:       btcHeaderHash,
			BtcTxIndex:          &txIndex,
			PopTxId:             popTxId,
			L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(l2Keystone).HashB(),
			BtcRawTx:            btx,
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcMerklePath:       mockMerkleHashes,
		},
	}, popBases)

	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

// TestPopPayouts ensures that when querying for pop payouts by L2Keystone,
// we can filter out pop payouts not in that keystone and we can reduce
// multiple pop txs by the same miner to a single pop payout
// 1 create all of the pop txs via the pop_basis table, there will be (4) total,
// of those (1) will be filtered out, (2) will be for one pop miner, the remaining
// (1) will be for the other
// 2 query for the pop payouts by calling BSS.popPayouts
// 3 ensure the correct values
func TestPopPayouts(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	privateKey := secp256k1.PrivKeyFromBytes([]byte{9, 8, 7})
	publicKey := privateKey.PubKey()
	publicKeyUncompressed := publicKey.SerializeUncompressed()
	minerHash := crypto.Keccak256(publicKeyUncompressed[1:])
	minerHash = minerHash[len(minerHash)-20:]
	minerAddress := common.BytesToAddress(minerHash)

	privateKey = secp256k1.PrivKeyFromBytes([]byte{1, 2, 3})
	publicKey = privateKey.PubKey()
	otherPublicKeyUncompressed := publicKey.SerializeUncompressed()
	minerHash = crypto.Keccak256(otherPublicKeyUncompressed[1:])
	minerHash = minerHash[len(minerHash)-20:]
	otherMinerAddress := common.BytesToAddress(minerHash)

	includedL2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	differentL2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      13,
		L2BlockNumber:      23,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btcHeaderHash := testutil.FillBytes("btcheaderhash", 32)

	btcBlock := bfgd.BtcBlock{
		Hash:   btcHeaderHash,
		Header: testutil.FillBytes("btcheader", 80),
		Height: 99,
	}

	err := db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	// insert 4 pop bases, 1 will have the "different" l2 keystone
	// and be excluded from queries, the other 3 will be included,
	// and will contain a duplicate pop miner address

	// 1
	var txIndex uint64 = 1

	popBasis := bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid1", 32),
		BtcRawTx:            []byte("btcrawtx1"),
		PopTxId:             testutil.FillBytes("poptxid1", 32),
		L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(includedL2Keystone).HashB(),
		PopMinerPublicKey:   publicKeyUncompressed,
		BtcHeaderHash:       btcHeaderHash,
		BtcTxIndex:          &txIndex,
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	txIndex = 2

	popBasis = bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid2", 32),
		BtcRawTx:            []byte("btcrawtx2"),
		PopTxId:             testutil.FillBytes("poptxid2", 32),
		L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(includedL2Keystone).HashB(),
		PopMinerPublicKey:   otherPublicKeyUncompressed,
		BtcHeaderHash:       btcHeaderHash,
		BtcTxIndex:          &txIndex,
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	txIndex = 3

	popBasis = bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid3", 32),
		BtcRawTx:            []byte("btcrawtx3"),
		PopTxId:             testutil.FillBytes("poptxid3", 32),
		L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(includedL2Keystone).HashB(),
		PopMinerPublicKey:   publicKeyUncompressed,
		BtcHeaderHash:       btcHeaderHash,
		BtcTxIndex:          &txIndex,
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	txIndex = 4

	popBasis = bfgd.PopBasis{
		BtcTxId:             testutil.FillBytes("btctxid4", 32),
		BtcRawTx:            []byte("btcrawtx4"),
		PopTxId:             testutil.FillBytes("poptxid4", 32),
		L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(differentL2Keystone).HashB(),
		PopMinerPublicKey:   publicKeyUncompressed,
		BtcHeaderHash:       btcHeaderHash,
		BtcTxIndex:          &txIndex,
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	serializedL2Keystone := hemi.L2KeystoneAbbreviate(includedL2Keystone).Serialize()

	// 2
	popPayoutsRequest := bssapi.PopPayoutsRequest{
		L2BlockForPayout: serializedL2Keystone[:],
	}

	err = bssapi.Write(ctx, bws.conn, "someid", popPayoutsRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	err = wsjson.Read(ctx, c, &v)
	if err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != bssapi.CmdPopPayoutResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	popPayoutsResponse := bssapi.PopPayoutsResponse{}
	err = json.Unmarshal(v.Payload, &popPayoutsResponse)
	if err != nil {
		t.Fatal(err)
	}

	sortFn := func(a, b bssapi.PopPayout) int {
		// find first differing byte in miner addresses and sort by that,
		// this should lead to predictable ordering as
		// miner addresses are unique here

		var ab byte = 0
		var bb byte = 0

		for i := range len(a.MinerAddress) {
			ab = a.MinerAddress[i]
			bb = b.MinerAddress[i]
			if ab != bb {
				break
			}
		}

		if ab > bb {
			return -1
		}

		return 1
	}

	slices.SortFunc(popPayoutsResponse.PopPayouts, sortFn)

	// 3
	diff := deep.Equal(popPayoutsResponse.PopPayouts, []bssapi.PopPayout{
		{
			Amount:       big.NewInt(2 * hemi.HEMIBase),
			MinerAddress: minerAddress,
		},
		{
			Amount:       big.NewInt(1 * hemi.HEMIBase),
			MinerAddress: otherMinerAddress,
		},
	})

	if len(diff) != 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestPopPayoutsMultiplePages(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	includedL2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btcHeaderHash := testutil.FillBytes("btcheaderhash", 32)

	btcBlock := bfgd.BtcBlock{
		Hash:   btcHeaderHash,
		Header: testutil.FillBytes("btcheader", 80),
		Height: 99,
	}

	if err := db.BtcBlockInsert(ctx, &btcBlock); err != nil {
		t.Fatal(err)
	}

	// insert 151 pop payouts to different miners, get the first 3 pages,
	// we expect result counts like so : 100, 51, 0
	var txIndex uint64 = 1

	addresses := []string{}

	for range 151 {
		privateKey, err := secp256k1.GeneratePrivateKeyFromRand(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}

		address := ethereum.AddressFromPrivateKey(privateKey)
		addresses = append(addresses, address.String())

		publicKey := privateKey.PubKey()
		publicKeyUncompressed := publicKey.SerializeUncompressed()

		txIndex++
		popBasis := bfgd.PopBasis{
			BtcTxId:             testutil.FillBytes("btctxid1", 32),
			BtcRawTx:            []byte("btcrawtx1"),
			PopTxId:             testutil.FillBytes("poptxid1", 32),
			L2KeystoneAbrevHash: hemi.L2KeystoneAbbreviate(includedL2Keystone).HashB(),
			PopMinerPublicKey:   publicKeyUncompressed,
			BtcHeaderHash:       btcHeaderHash,
			BtcTxIndex:          &txIndex,
		}

		if err := db.PopBasisInsertFull(ctx, &popBasis); err != nil {
			t.Fatal(err)
		}
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	serializedL2Keystone := hemi.L2KeystoneAbbreviate(includedL2Keystone).Serialize()

	receivedAddresses := []string{}

	popPayoutsRequest := bssapi.PopPayoutsRequest{
		L2BlockForPayout: serializedL2Keystone[:],
	}

	err = bssapi.Write(ctx, bws.conn, "someid", popPayoutsRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != bssapi.CmdPopPayoutResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	popPayoutsResponse := bssapi.PopPayoutsResponse{}
	if err := json.Unmarshal(v.Payload, &popPayoutsResponse); err != nil {
		t.Fatal(err)
	}

	if len(popPayoutsResponse.PopPayouts) != 100 {
		t.Fatalf(
			"expected first page to have 100 results, received %d",
			len(popPayoutsResponse.PopPayouts),
		)
	}

	for _, p := range popPayoutsResponse.PopPayouts {
		receivedAddresses = append(receivedAddresses, p.MinerAddress.String())
	}

	popPayoutsRequest.Page = 1
	err = bssapi.Write(ctx, bws.conn, "someid", popPayoutsRequest)
	if err != nil {
		t.Fatal(err)
	}

	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != bssapi.CmdPopPayoutResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	err = json.Unmarshal(v.Payload, &popPayoutsResponse)
	if err != nil {
		t.Fatal(err)
	}

	if len(popPayoutsResponse.PopPayouts) != 51 {
		t.Fatalf(
			"expected first page to have 51 results, received %d",
			len(popPayoutsResponse.PopPayouts),
		)
	}

	for _, p := range popPayoutsResponse.PopPayouts {
		receivedAddresses = append(receivedAddresses, p.MinerAddress.String())
	}

	popPayoutsRequest.Page = 2
	err = bssapi.Write(ctx, bws.conn, "someid", popPayoutsRequest)
	if err != nil {
		t.Fatal(err)
	}

	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}

	if v.Header.Command != bssapi.CmdPopPayoutResponse {
		t.Fatalf("received unexpected command: %s", v.Header.Command)
	}

	if err := json.Unmarshal(v.Payload, &popPayoutsResponse); err != nil {
		t.Fatal(err)
	}

	if len(popPayoutsResponse.PopPayouts) != 0 {
		t.Fatalf(
			"expected first page to have 0 results, received %d",
			len(popPayoutsResponse.PopPayouts))
	}

	slices.Sort(addresses)
	slices.Sort(receivedAddresses)

	if diff := deep.Equal(addresses, receivedAddresses); len(diff) != 0 {
		t.Fatalf("unexpected diff %v", diff)
	}
}

func TestGetMostRecentL2BtcFinalitiesBSS(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1000)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	btcBlock := createBtcBlock(ctx, t, db, 1, 998, []byte{}, 1) // finality should be 1000 - 998 - 9 + 1 = -6
	b2 := createBtcBlock(ctx, t, db, 1, -1, []byte{}, 2)        // finality should be 1000 - 1000 - 9 + 1 = -8 (unpublished)
	b3 := createBtcBlock(ctx, t, db, 1, 1000, btcBlock.Hash, 3) // finality should be 1000 - 1000 - 9 + 1 = -8
	updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b2, uint32(b2.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b3, uint32(b3.Height))

	expectedFinalitiesDesc := []int32{-8, -8, -6}

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	finalityRequest := bssapi.BTCFinalityByRecentKeystonesRequest{
		NumRecentKeystones: 100,
	}

	time.Sleep(5 * time.Second)

	err = bssapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bssapi.CmdBTCFinalityByRecentKeystonesResponse {
			break
		}
	}

	time.Sleep(5 * time.Second)

	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 100, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for i, r := range recentFinalities {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = expectedFinalitiesDesc[i]
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bssapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bssapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func updateFinalityForBtcBlock(t *testing.T, ctx context.Context, db bfgd.Database, block *bfgd.BtcBlock, height uint32) {
	// some tests don't care about a btc block hash, fill it out here so it doesn't error
	if len(block.Hash) == 0 {
		block.Hash = testutil.FillBytes(fmt.Sprintf("%d", height), 32)
	}

	if err := db.BtcBlockUpdateKeystones(ctx, [32]byte(block.Hash), uint64(height), math.MaxInt64); err != nil {
		t.Fatal(err)
	}
}

func TestGetFinalitiesByL2KeystoneBSS(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1000)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	btcBlock := createBtcBlock(ctx, t, db, 1, 998, []byte{}, 1) // finality should be 1000 - 998 - 9 + 1 = -6
	b2 := createBtcBlock(ctx, t, db, 1, -1, []byte{}, 2)        // finality should be 1000 - 1000 - 9 + 1 = -8 (unpublished)
	b3 := createBtcBlock(ctx, t, db, 1, 1000, btcBlock.Hash, 3) // finality should be 1000 - 1000 - 9 + 1 = -8

	updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b2, uint32(b2.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b3, uint32(b3.Height))
	expectedFinalitiesDesc := []int32{-8, -6}

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(2 * time.Second)

	// first and second btcBlocks
	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 100, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	l2Keystones := []hemi.L2Keystone{}
	for _, r := range recentFinalities[1:] {
		l, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		l2Keystones = append(l2Keystones, l.L2Keystone)
	}

	finalityRequest := bssapi.BTCFinalityByKeystonesRequest{
		L2Keystones: l2Keystones,
	}

	err = bssapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message

	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bssapi.CmdBTCFinalityByKeystonesResponse {
			break
		}
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for i, r := range recentFinalities[1:] {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = expectedFinalitiesDesc[i]
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bssapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bssapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestGetFinalitiesByL2KeystoneBSSLowerServerHeight(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 999)

	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	btcBlock := createBtcBlock(ctx, t, db, 1, 998, []byte{}, 1) // finality should be 1000 - 998 - 9 + 1 = -6
	b2 := createBtcBlock(ctx, t, db, 1, -1, []byte{}, 2)        // finality should be 1000 - 1000 - 9 + 1 = -8 (unpublished)
	b3 := createBtcBlock(ctx, t, db, 1, 1000, btcBlock.Hash, 3) // finality should be 1000 - 1000 - 9 + 1 = -8
	updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b2, uint32(b2.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b3, uint32(b3.Height))

	expectedFinalitiesDesc := []int32{-8, -6}

	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	bws := &bssWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(2 * time.Second)

	// first and second btcBlocks
	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 100, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	l2Keystones := []hemi.L2Keystone{}
	for _, r := range recentFinalities[1:] {
		l, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		l2Keystones = append(l2Keystones, l.L2Keystone)
	}

	finalityRequest := bssapi.BTCFinalityByKeystonesRequest{
		L2Keystones: l2Keystones,
	}

	err = bssapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bssapi.CmdBTCFinalityByKeystonesResponse {
			break
		}
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for i, r := range recentFinalities[1:] {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = expectedFinalitiesDesc[i]
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bssapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bssapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestGetMostRecentL2BtcFinalitiesBFG(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1000)

	btcBlock := createBtcBlock(ctx, t, db, 1, 998, []byte{}, 1) // finality should be 1000 - 998 - 9 + 1 = -6
	b2 := createBtcBlock(ctx, t, db, 1, -1, []byte{}, 2)        // finality should be 1000 - 1000 - 9 + 1 = -8 (unpublished)
	b3 := createBtcBlock(ctx, t, db, 1, 1000, btcBlock.Hash, 3) // finality should be 1000 - 1000 - 9 + 1 = -8
	updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b2, uint32(b2.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b3, uint32(b3.Height))

	expectedFinalitiesDesc := []int32{-8, -8, -6}

	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(2 * time.Second)

	finalityRequest := bfgapi.BTCFinalityByRecentKeystonesRequest{
		NumRecentKeystones: 100,
	}

	err = bfgapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message
	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bfgapi.CmdBTCFinalityByRecentKeystonesResponse {
			break
		}
	}

	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 100, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for i, r := range recentFinalities {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = expectedFinalitiesDesc[i]
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestGetFinalitiesByL2KeystoneBFG(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1000)

	btcBlock := createBtcBlock(ctx, t, db, 1, 998, []byte{}, 1) // finality should be 1000 - 998 - 9 + 1 = -6
	b2 := createBtcBlock(ctx, t, db, 1, -1, []byte{}, 2)        // finality should be 1000 - 1000 - 9 + 1 = -8 (unpublished)
	b3 := createBtcBlock(ctx, t, db, 1, 1000, btcBlock.Hash, 3) // finality should be 1000 - 1000 - 9 + 1 = -8
	updateFinalityForBtcBlock(t, ctx, db, &btcBlock, uint32(btcBlock.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b2, uint32(b2.Height))
	updateFinalityForBtcBlock(t, ctx, db, &b3, uint32(b3.Height))
	expectedFinalitiesDesc := []int32{-8, -6}

	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(2 * time.Second)

	// first and second btcBlocks
	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 100, math.MaxInt64)
	if err != nil {
		t.Fatal(err)
	}

	l2Keystones := []hemi.L2Keystone{}
	for _, r := range recentFinalities[1:] {
		l, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		l2Keystones = append(l2Keystones, l.L2Keystone)
	}

	finalityRequest := bfgapi.BTCFinalityByKeystonesRequest{
		L2Keystones: l2Keystones,
	}

	err = bfgapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message

	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bfgapi.CmdBTCFinalityByKeystonesResponse {
			break
		}
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for i, r := range recentFinalities[1:] {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = expectedFinalitiesDesc[i]
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("comparing %v ?= %v", spew.Sdump(expectedApiResponse), spew.Sdump(finalityResponse))

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestGetFinalitiesByL2KeystoneBFGVeryOld(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()
	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1)

	height := 1
	l2BlockNumber := uint32(1)
	block := createBtcBlock(ctx, t, db, 1, height, []byte{}, l2BlockNumber)

	updateFinalityForBtcBlock(t, ctx, db, &block, uint32(height))

	// get the btc block's finality, this is the only one that
	// we care about in this test
	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 1, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	l2Keystones := []hemi.L2Keystone{}
	for _, r := range recentFinalities {
		l, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		l2Keystones = append(l2Keystones, l.L2Keystone)
	}

	finalityRequest := bfgapi.BTCFinalityByKeystonesRequest{
		L2Keystones: l2Keystones,
	}

	// create more than 100 blocks to achieve max finality threshold of 100
	for height < 300 {
		height++
		l2BlockNumber++
		block := createBtcBlock(ctx, t, db, 1, height, []byte{}, l2BlockNumber)
		updateFinalityForBtcBlock(t, ctx, db, &block, uint32(height))
	}

	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(2 * time.Second)

	err = bfgapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message

	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bfgapi.CmdBTCFinalityByKeystonesResponse {
			break
		}
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for _, r := range recentFinalities {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		// expect finality of 100, this is the max
		f.BTCFinality = 100
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

func TestGetFinalitiesByL2KeystoneBFGNotThatOld(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, "", 1)

	height := 1
	l2BlockNumber := uint32(1)
	block := createBtcBlock(ctx, t, db, 1, height, []byte{}, l2BlockNumber)
	updateFinalityForBtcBlock(t, ctx, db, &block, uint32(height))
	// get the btc block's finality, this is the only one that
	// we care about in this test
	recentFinalities, err := db.L2BTCFinalityMostRecent(ctx, 1, 9999999999)
	if err != nil {
		t.Fatal(err)
	}

	l2Keystones := []hemi.L2Keystone{}
	for _, r := range recentFinalities {
		l, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}
		l2Keystones = append(l2Keystones, l.L2Keystone)
	}

	finalityRequest := bfgapi.BTCFinalityByKeystonesRequest{
		L2Keystones: l2Keystones,
	}

	for height < 100+8 {
		height++
		l2BlockNumber++
		block := createBtcBlock(ctx, t, db, 1, height, []byte{}, l2BlockNumber)
		updateFinalityForBtcBlock(t, ctx, db, &block, uint32(height))
	}

	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	bws := &bfgWs{
		conn: protocol.NewWSConn(c),
	}

	time.Sleep(5 * time.Second)

	err = bfgapi.Write(ctx, bws.conn, "someid", finalityRequest)
	if err != nil {
		t.Fatal(err)
	}

	var v protocol.Message

	for {
		err = wsjson.Read(ctx, c, &v)
		if err != nil {
			t.Fatal(err)
		}

		if v.Header.Command == bfgapi.CmdBTCFinalityByKeystonesResponse {
			break
		}
	}

	expectedResponse := []hemi.L2BTCFinality{}
	for _, r := range recentFinalities {
		f, err := hemi.L2BTCFinalityFromBfgd(&r, 0, 0)
		if err != nil {
			t.Fatal(err)
		}

		f.BTCFinality = 99
		expectedResponse = append(expectedResponse, *f)
	}

	expectedApiResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{
		L2BTCFinalities: expectedResponse,
	}

	finalityResponse := bfgapi.BTCFinalityByRecentKeystonesResponse{}
	err = json.Unmarshal(v.Payload, &finalityResponse)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("checking finality for block number %d", l2Keystones[0].L2BlockNumber)

	diff := deep.Equal(expectedApiResponse, finalityResponse)
	if len(diff) > 0 {
		t.Fatalf("unexpected diff %s", diff)
	}
}

// TestNotifyOnNewBtcBlockBFGClients tests that upon getting a new btc block,
// in this case from (mock) electrs, that a new btc block
// notification will be sent to all clients connected to BFG
// 1. connect client
// 2. wait for notification
func TestNotifyOnNewBtcBlockBFGClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	// 1
	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	// 2
	retries := 2
	found := false
	for range retries {
		// 2
		var v protocol.Message
		if err = wsjson.Read(ctx, c, &v); err != nil {
			panic(fmt.Sprintf("error reading from ws: %s", err))
		}

		if v.Header.Command == bfgapi.CmdBTCNewBlockNotification {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("never received expected command: %s", bfgapi.CmdBTCNewBlockNotification)
	}
}

// TestNotifyOnNewBtcFinalityBFGClients tests that upon getting a new btc block,
// in this case from (mock) electrs, that a finality notification will be sent
// to all clients connected to BFG
// 1. connect client
// 2. wait for notification
func TestNotifyOnNewBtcFinalityBFGClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	// 1
	c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	retries := 2
	found := false
	for range retries {
		// 2
		var v protocol.Message
		if err = wsjson.Read(ctx, c, &v); err != nil {
			panic(fmt.Sprintf("error reading from ws: %s", err))
		}

		if v.Header.Command == bfgapi.CmdBTCFinalityNotification {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("never received expected command: %s", bfgapi.CmdBTCFinalityNotification)
	}
}

func TestNotifyOnL2KeystonesBFGClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, "", 1)

	c, _, err := websocket.Dial(ctx, bfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)

	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	l2Keystone := bfgd.L2Keystone{
		Hash:               testutil.FillBytes("somehashone", 32),
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephashone", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
		StateRoot:          testutil.FillBytes("staterootone", 32),
		EPHash:             testutil.FillBytes("ephashone", 32),
	}

	if err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{
		l2Keystone,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var v protocol.Message
			if err = wsjson.Read(ctx, c, &v); err != nil {
				panic(fmt.Sprintf("error reading from ws: %s", err))
			}

			if v.Header.Command == bfgapi.CmdL2KeystonesNotification {
				return
			}
		}
	}()

	wg.Wait()
}

func TestNotifyOnL2KeystonesBFGClientsViaOtherBFG(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	otherDb, otherPgUri, otherSdb, otherCleanup := createTestDB(t.Context(), t)
	defer func() {
		otherDb.Close()
		otherSdb.Close()
		otherCleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, "", 1)
	_, _, _, otherBfgPublicWsUrl := createBfgServerGeneric(ctx, t, otherPgUri, "", 1, bfgPublicWsUrl)

	c, _, err := websocket.Dial(ctx, otherBfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)

	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	l2Keystone := bfgd.L2Keystone{
		Hash:               testutil.FillBytes("somehashone", 32),
		Version:            1,
		L1BlockNumber:      11,
		L2BlockNumber:      22,
		ParentEPHash:       testutil.FillBytes("parentephashone", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
		StateRoot:          testutil.FillBytes("staterootone", 32),
		EPHash:             testutil.FillBytes("ephashone", 32),
	}

	// insert the l2 keystone into the first bfg server's postgres,
	// this should send a notification to the "other" bfg which should
	// broadcast the notification

	if err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{
		l2Keystone,
	}); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var v protocol.Message
			if err = wsjson.Read(ctx, c, &v); err != nil {
				panic(fmt.Sprintf("error reading from ws: %s", err))
			}

			if v.Header.Command == bfgapi.CmdL2KeystonesNotification {
				return
			}
		}
	}()

	wg.Wait()
}

func TestOtherBFGSavesL2KeystonesOnNotifications(t *testing.T) {
	t.Parallel()

	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	otherDb, otherPgUri, otherSdb, otherCleanup := createTestDB(t.Context(), t)
	defer func() {
		otherDb.Close()
		otherSdb.Close()
		otherCleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	_, _, _, bfgPublicWsUrl := createBfgServer(ctx, t, pgUri, "", 1)
	_, _, _, otherBfgPublicWsUrl := createBfgServerGeneric(ctx, t, otherPgUri, "", 1, bfgPublicWsUrl)

	c, _, err := websocket.Dial(ctx, otherBfgPublicWsUrl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	protocolConn := protocol.NewWSConn(c)

	if err := authClient.HandshakeClient(ctx, protocolConn); err != nil {
		t.Fatal(err)
	}
	assertPing(ctx, t, c, bfgapi.CmdPingRequest)

	l2Keystones := []bfgd.L2Keystone{
		{
			Hash:               testutil.FillBytes("somehash22", 32),
			Version:            1,
			L1BlockNumber:      11,
			L2BlockNumber:      22,
			ParentEPHash:       testutil.FillBytes("parentephashone", 32),
			PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
			StateRoot:          testutil.FillBytes("staterootone", 32),
			EPHash:             testutil.FillBytes("ephashone", 32),
		},
		{
			Hash:               testutil.FillBytes("somehash23", 32),
			Version:            1,
			L1BlockNumber:      11,
			L2BlockNumber:      23,
			ParentEPHash:       testutil.FillBytes("parentephashone", 32),
			PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
			StateRoot:          testutil.FillBytes("staterootone", 32),
			EPHash:             testutil.FillBytes("ephashone", 32),
		},
		{
			Hash:               testutil.FillBytes("somehash24", 32),
			Version:            1,
			L1BlockNumber:      11,
			L2BlockNumber:      24,
			ParentEPHash:       testutil.FillBytes("parentephashone", 32),
			PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephashone", 32),
			StateRoot:          testutil.FillBytes("staterootone", 32),
			EPHash:             testutil.FillBytes("ephashone", 32),
		},
	}

	if err := db.L2KeystonesInsert(ctx, l2Keystones); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			var v protocol.Message
			if err = wsjson.Read(ctx, c, &v); err != nil {
				panic(fmt.Sprintf("error reading from ws: %s", err))
			}

			if v.Header.Command == bfgapi.CmdL2KeystonesNotification {
				return
			}
		}
	}()

	wg.Wait()

	// give a few seconds for the notification to be processed in the other
	// bfg (saving keystones etc.)
	select {
	case <-time.After(5 * time.Second):
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			l2KeystonesRequest := bfgapi.L2KeystonesRequest{
				NumL2Keystones: 3,
			}

			if err := bfgapi.Write(ctx, protocolConn, "someid", &l2KeystonesRequest); err != nil {
				panic(err)
			}

			for {
				command, _, payload, err := bfgapi.Read(ctx, protocolConn)
				if err != nil {
					panic(err)
				}

				if command != bfgapi.CmdL2KeystonesResponse {
					continue
				}

				l2KeystonesResponse := payload.(*bfgapi.L2KeystonesResponse)

				hemiL2Keystones := make([]hemi.L2Keystone, 0, len(l2Keystones))
				for _, v := range l2Keystones {
					hemiL2Keystones = append(hemiL2Keystones, hemi.L2Keystone{
						Version:            uint8(v.Version),
						L1BlockNumber:      v.L1BlockNumber,
						L2BlockNumber:      v.L2BlockNumber,
						ParentEPHash:       api.ByteSlice(v.ParentEPHash),
						PrevKeystoneEPHash: api.ByteSlice(v.PrevKeystoneEPHash),
						StateRoot:          api.ByteSlice(v.StateRoot),
						EPHash:             api.ByteSlice(v.EPHash),
					})
				}

				slices.Reverse(hemiL2Keystones)

				if diff := deep.Equal(l2KeystonesResponse.L2Keystones, hemiL2Keystones); len(diff) != 0 {
					panic(fmt.Sprintf("l2keystones are not equal: %v", diff))
				}

				return
			}
		}
	}()

	wg.Wait()
}

// TestNotifyOnNewBtcBlockBSSClients tests that upon getting a new btc block,
// in this case from (mock) electrs, that a new btc notification
// will be sent to all clients connected to BSS
// 1. connect client
// 2. wait for notification
func TestNotifyOnNewBtcBlockBSSClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)
	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	// 1
	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	retries := 2
	found := false
	for range retries {
		// 2
		var v protocol.Message
		if err = wsjson.Read(ctx, c, &v); err != nil {
			panic(fmt.Sprintf("error reading from ws: %s", err))
		}

		if v.Header.Command == bssapi.CmdBTCNewBlockNotification {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("never received expected command: %s", bssapi.CmdBTCNewBlockNotification)
	}
}

// TestNotifyOnNewBtcFinalityBSSClients tests that upon getting a new btc block,
// in this case from (mock) electrs, that a new finality notification
// will be sent to all clients connected to BSS
// 1. connect client
// 2. wait for notification
func TestNotifyOnNewBtcFinalityBSSClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)
	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	// 1
	c, _, err := websocket.Dial(ctx, bssWsurl, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseNow()

	assertPing(ctx, t, c, bssapi.CmdPingRequest)

	retries := 2
	found := false
	for range retries {
		// 2
		var v protocol.Message
		if err = wsjson.Read(ctx, c, &v); err != nil {
			panic(fmt.Sprintf("error reading from ws: %s", err))
		}

		if v.Header.Command == bssapi.CmdBTCFinalityNotification {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("never received expected command: %s", bssapi.CmdBTCFinalityNotification)
	}
}

func TestNotifyMultipleBFGClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)

	wg := sync.WaitGroup{}

	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, err := websocket.Dial(ctx, bfgWsurl, nil)
			if err != nil {
				panic(err)
			}

			// ensure we can safely close 1 and handle the rest
			if i == 5 {
				c.CloseNow()
				return
			} else {
				defer c.CloseNow()
			}

			assertPing(ctx, t, c, bfgapi.CmdPingRequest)

			var v protocol.Message
			if err = wsjson.Read(ctx, c, &v); err != nil {
				panic(fmt.Sprintf("error reading from ws: %s", err))
			}

			if v.Header.Command != bfgapi.CmdBTCNewBlockNotification &&
				v.Header.Command != bfgapi.CmdBTCFinalityNotification {
				panic(fmt.Sprintf("wrong command: %s", v.Header.Command))
			}
		}()
	}

	wg.Wait()
}

func TestNotifyMultipleBSSClients(t *testing.T) {
	db, pgUri, sdb, cleanup := createTestDB(t.Context(), t)
	defer func() {
		db.Close()
		sdb.Close()
		cleanup()
	}()

	ctx, cancel := defaultTestContext(t)
	defer cancel()

	l2Keystone := hemi.L2Keystone{
		Version:            1,
		L1BlockNumber:      5,
		L2BlockNumber:      44,
		ParentEPHash:       testutil.FillBytes("parentephash", 32),
		PrevKeystoneEPHash: testutil.FillBytes("prevkeystoneephash", 32),
		StateRoot:          testutil.FillBytes("stateroot", 32),
		EPHash:             testutil.FillBytes("ephash", 32),
	}

	btx := createBtcTx(t, 199, &l2Keystone, minerPrivateKeyBytes)

	electrsAddr, cleanupE := createMockElectrsServer(ctx, t, &l2Keystone, btx)
	defer cleanupE()
	if err := EnsureCanConnectTCP(
		t,
		electrsAddr,
		mockElectrsConnectTimeout,
	); err != nil {
		t.Fatal(err)
	}

	_, _, bfgWsurl, _ := createBfgServer(ctx, t, pgUri, electrsAddr, 1)
	_, _, bssWsurl := createBssServer(ctx, t, bfgWsurl)

	wg := sync.WaitGroup{}

	for i := range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, _, err := websocket.Dial(ctx, bssWsurl, nil)
			if err != nil {
				panic(err)
			}

			// ensure we can safely close 1 and handle the rest
			if i == 5 {
				c.CloseNow()
				return
			} else {
				defer c.CloseNow()
			}

			assertPing(ctx, t, c, bssapi.CmdPingRequest)

			var v protocol.Message
			if err = wsjson.Read(ctx, c, &v); err != nil {
				panic(fmt.Sprintf("error reading from ws: %s", err))
			}

			if v.Header.Command != bssapi.CmdBTCNewBlockNotification &&
				v.Header.Command != bssapi.CmdBTCFinalityNotification {
				panic(fmt.Sprintf("wrong command: %s", v.Header.Command))
			}
		}()
	}

	wg.Wait()
}

func createBtcBlock(ctx context.Context, t *testing.T, db bfgd.Database, count int, height int, lastHash []byte, l2BlockNumber uint32) bfgd.BtcBlock {
	header := make([]byte, 80)
	hash := make([]byte, 32)
	parentEpHash := make([]byte, 32)
	prevKeystoneEpHash := make([]byte, 32)
	stateRoot := make([]byte, 32)
	epHash := make([]byte, 32)
	btcTxId := make([]byte, 32)
	btcRawTx := make([]byte, 32)
	popMinerPublicKey := make([]byte, 32)

	if _, err := rand.Read(header); err != nil {
		t.Fatal(err)
	}

	if _, err := rand.Read(hash); err != nil {
		t.Fatal(err)
	}

	if _, err := rand.Read(btcTxId); err != nil {
		t.Fatal(err)
	}

	if _, err := rand.Read(stateRoot); err != nil {
		t.Fatal(err)
	}

	if len(lastHash) != 0 {
		for k := 4; (k - 4) < 32; k++ {
			header[k] = lastHash[k-4]
		}
	}

	btcBlock := bfgd.BtcBlock{
		Header: header,
		Hash:   hash,
		Height: uint64(height),
	}

	hemiL2Keystone := hemi.L2Keystone{
		ParentEPHash:       parentEpHash,
		PrevKeystoneEPHash: prevKeystoneEpHash,
		StateRoot:          stateRoot,
		EPHash:             epHash,
		L2BlockNumber:      l2BlockNumber,
	}

	l2KeystoneAbrevHash := hemi.L2KeystoneAbbreviate(hemiL2Keystone).HashB()
	l2Keystone := bfgd.L2Keystone{
		Hash:               l2KeystoneAbrevHash,
		ParentEPHash:       parentEpHash,
		PrevKeystoneEPHash: prevKeystoneEpHash,
		StateRoot:          stateRoot,
		EPHash:             epHash,
		L2BlockNumber:      l2BlockNumber,
	}

	popBasis := bfgd.PopBasis{
		BtcTxId:             btcTxId,
		BtcRawTx:            btcRawTx,
		BtcHeaderHash:       hash,
		L2KeystoneAbrevHash: l2KeystoneAbrevHash,
		PopMinerPublicKey:   popMinerPublicKey,
	}

	if height == -1 {
		err := db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
		if err != nil {
			t.Fatal(err)
		}

		err = db.PopBasisInsertPopMFields(ctx, &popBasis)
		if err != nil {
			t.Fatal(err)
		}

		return bfgd.BtcBlock{}
	}

	err := db.BtcBlockInsert(ctx, &btcBlock)
	if err != nil {
		t.Fatal(err)
	}

	err = db.L2KeystonesInsert(ctx, []bfgd.L2Keystone{l2Keystone})
	if err != nil {
		t.Fatal(err)
	}

	err = db.PopBasisInsertFull(ctx, &popBasis)
	if err != nil {
		t.Fatal(err)
	}

	return btcBlock
}
