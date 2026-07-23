// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/database/tbcd"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
)

var (
	testJWTSecret = testutil.FillBytes("test_secret", 32)
	testJWTString = hex.EncodeToString(testJWTSecret)
)

func createAdminToken(t *testing.T) string {
	t.Helper()
	now := time.Now()
	claims := jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		NotBefore: jwt.NewNumericDate(now),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err := token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func dialAdmin(ctx context.Context, t *testing.T, url string) *websocket.Conn {
	t.Helper()
	token := createAdminToken(t)
	c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + token},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func readAdminMessage(ctx context.Context, t *testing.T, c *websocket.Conn) protocol.Message {
	t.Helper()
	var v protocol.Message
	if err := wsjson.Read(ctx, c, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

func TestAdminJWTAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	type testTableItem struct {
		name          string
		header        func() http.Header
		expectedError bool
	}

	testTable := []testTableItem{
		{
			name: "missing header",
			header: func() http.Header {
				return nil
			},
			expectedError: true,
		},
		{
			name: "invalid auth format",
			header: func() http.Header {
				return http.Header{
					"Authorization": []string{"Basic dXNlcjpwYXNz"},
				}
			},
			expectedError: true,
		},
		{
			name: "invalid token",
			header: func() http.Header {
				return http.Header{
					"Authorization": []string{"Bearer invalid_token_here"},
				}
			},
			expectedError: true,
		},
		{
			name: "invalid signature key",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString([]byte("wrong-key-wrong-key-wrong-key!!!"))
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "expired claims",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(-2 * time.Minute)),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "future claims",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
					NotBefore: jwt.NewNumericDate(now.Add(2 * time.Minute)),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "stale token",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now.Add(-2 * jwtExpiryTimeout)),
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "future token",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now.Add(2 * jwtExpiryTimeout)),
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "missing exp",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "missing nbf",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					IssuedAt:  jwt.NewNumericDate(now),
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
			expectedError: true,
		},
		{
			name: "missing optional iat",
			header: func() http.Header {
				now := time.Now()
				claims := jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
					NotBefore: jwt.NewNumericDate(now),
				}
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				signed, err := token.SignedString(testJWTSecret)
				if err != nil {
					t.Fatal(err)
				}
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
		},
		{
			name: "valid",
			header: func() http.Header {
				signed := createAdminToken(t)
				return http.Header{
					"Authorization": []string{"Bearer " + signed},
				}
			},
		},
	}

	adminURL, _, _ := createLocalTBCServer(ctx, t, testJWTString)

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			c, resp, err := websocket.Dial(ctx, adminURL, &websocket.DialOptions{
				HTTPHeader: tti.header(),
			})

			if tti.expectedError {
				if err == nil {
					t.Fatal("expected error")
				}
				if resp != nil && resp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("expected %d, got %d",
						http.StatusUnauthorized, resp.StatusCode)
				}
				return
			}

			// Successful admin connection sends an initial ping
			msg := readAdminMessage(ctx, t, c)
			if msg.Header.Command != tbcapi.CmdPingRequest {
				t.Fatalf("expected ping command, got %s", msg.Header.Command)
			}
		})
	}
}

func TestAdminRPCCommands(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	type testTableItem struct {
		name      string
		request   any
		postCheck func(*protocol.WSConn, protocol.Message) error
	}

	adminURL, s, _ := createLocalTBCServer(ctx, t, testJWTString)

	var ws sync.WaitGroup
	ws.Add(1)
	jrun := func(jctx context.Context, id string) {
		defer ws.Done()
		err := s.adminSessions.BroadcastProgress(jctx, id, JobStatusCompleted)
		if err != nil {
			panic(err)
		}
		// Wait for job cancellation to end and subtract the wait group
		<-jctx.Done()
	}
	jid, err := s.adminSessions.NewJob(jobType("some-job"), jrun)
	if err != nil {
		t.Fatal(err)
	}
	initialInfo, err := s.adminSessions.JobStatus(jid)
	if err != nil {
		t.Fatal(err)
	}

	testTable := []testTableItem{
		{
			name:    "JobListRequest",
			request: tbcadminapi.JobListRequest{},
			postCheck: func(_ *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobListResponse {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobListResponse, msg.Header.Command)
				}
				var resp tbcadminapi.JobListResponse
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if len(resp.Jobs) != 1 {
					return fmt.Errorf("expected 1 job, got %d", len(resp.Jobs))
				}
				if resp.Jobs[0] != initialInfo {
					return fmt.Errorf("wanted job %v, got %v",
						initialInfo, resp.Jobs[0])
				}
				return err
			},
		},
		{
			name:    "SyncIndexersToHashRequest",
			request: tbcadminapi.SyncIndexersToHashRequest{},
			postCheck: func(_ *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobUpdateNotification {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobUpdateNotification, msg.Header.Command)
				}
				var resp tbcadminapi.JobUpdateNotification
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.Job.JobID == "" {
					return errors.New("empty job ID")
				}
				if resp.Job.JobType != string(SyncIndexersToHashJob) {
					return fmt.Errorf("expected job type %s, got %s",
						SyncIndexersToHashJob, resp.Job.JobType)
				}
				return nil
			},
		},
		{
			name:    "JobStatusRequest",
			request: tbcadminapi.JobStatusRequest{JobID: jid},
			postCheck: func(_ *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobUpdateNotification {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobUpdateNotification, msg.Header.Command)
				}
				var resp tbcadminapi.JobUpdateNotification
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.Job.JobID != jid {
					return errors.New("unknown job ")
				}
				if resp.Job != initialInfo {
					return fmt.Errorf("wanted job %v, got %v",
						initialInfo, resp.Job)
				}
				return nil
			},
		},
		{
			name:    "JobSubscribeRequest",
			request: tbcadminapi.JobSubscribeRequest{JobID: jid},
			postCheck: func(c *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobUpdateNotification {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobUpdateNotification, msg.Header.Command)
				}
				var resp tbcadminapi.JobUpdateNotification
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.Job != initialInfo {
					return fmt.Errorf("wanted job %v, got %v",
						initialInfo, resp.Job)
				}
				if err := s.adminSessions.StartJob(jid); err != nil {
					return err
				}
				_, _, payload, err := tbcadminapi.Read(ctx, c)
				if err != nil {
					return err
				}
				p, ok := payload.(*tbcadminapi.JobUpdateNotification)
				if !ok {
					return fmt.Errorf("unexpected message type: %v", payload)
				}
				if p.Error != nil {
					return fmt.Errorf("unexpected error: %w", p.Error)
				}
				if p.Job.JobID != jid {
					return fmt.Errorf("wanted job id %s, got %s", jid, p.Job.JobID)
				}
				if p.Job.Status != string(JobStatusCompleted) {
					return fmt.Errorf("wanted job status %s, got %s",
						JobStatusCompleted, p.Job.Status)
				}
				return nil
			},
		},
		{
			name:    "JobCancelRequest",
			request: tbcadminapi.JobCancelRequest{JobID: jid},
			postCheck: func(c *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobCancelResponse {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobCancelResponse, msg.Header.Command)
				}
				var resp tbcadminapi.JobCancelResponse
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.JobID != jid {
					return fmt.Errorf("wanted job id %s, got %s", jid, resp.JobID)
				}
				ws.Wait()
				return nil
			},
		},

		// Test passthroughs to tbcAPI general commands

		{
			name:    "BlockHeaderBestRawRequest",
			request: tbcapi.BlockHeaderBestRawRequest{},
			postCheck: func(c *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcapi.CmdBlockHeaderBestRawResponse {
					return fmt.Errorf("expected %s, got %s",
						tbcapi.CmdBlockHeaderBestRawResponse, msg.Header.Command)
				}
				var resp tbcapi.BlockHeaderBestRawResponse
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.Height != 3 {
					return fmt.Errorf("expected height 3, got %d", resp.Height)
				}
				return nil
			},
		},
		{
			name:    "BlockHeaderBestRequest",
			request: tbcapi.BlockHeaderBestRequest{},
			postCheck: func(c *protocol.WSConn, msg protocol.Message) error {
				if msg.Header.Command != tbcapi.CmdBlockHeaderBestResponse {
					return fmt.Errorf("expected %s, got %s",
						tbcapi.CmdBlockHeaderBestResponse, msg.Header.Command)
				}
				var resp tbcapi.BlockHeaderBestResponse
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				if resp.Error != nil {
					return fmt.Errorf("unexpected error: %w", resp.Error)
				}
				if resp.Height != 3 {
					return fmt.Errorf("expected height 3, got %d", resp.Height)
				}
				if resp.BlockHeader == nil {
					return errors.New("expected non-nil block header")
				}
				return nil
			},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			c := dialAdmin(ctx, t, adminURL)
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{conn: protocol.NewWSConn(c)}

			if err := tbcadminapi.Write(ctx, tws.conn, "someid", tti.request); err != nil {
				t.Fatal(err)
			}

			msg := readAdminMessage(ctx, t, c)
			if err := tti.postCheck(tws.conn, msg); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdminRPCBlockHeadersInsert(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	type testTableItem struct {
		name      string
		request   tbcadminapi.BlockHeadersInsertRequest
		postCheck func(*tbcadminapi.BlockHeadersInsertResponse) error
	}

	adminURL, _, n := createLocalTBCServer(ctx, t, testJWTString)

	b3 := n.blocksAtHeight[3][0]
	b3h := wireBlockHeaderToTBC(&b3.MsgBlock().Header)

	powLimitBits := chaincfg.RegressionNetParams.PowLimitBits

	wValid := wire.NewBlockHeader(1, b3.Hash(), &chainhash.Hash{0xff, 0xff},
		powLimitBits, 0)
	wValid.Timestamp = time.Now()
	mineHeader(wValid)
	validHeader := *wireBlockHeaderToTBC(wValid)

	wFork := wire.NewBlockHeader(1, b3.Hash(), &chainhash.Hash{0xfe, 0xfe},
		powLimitBits, 0)
	wFork.Timestamp = time.Now()
	mineHeader(wFork)
	fork := *wireBlockHeaderToTBC(wFork)

	wForkHash := wFork.BlockHash()
	wForkExtend := wire.NewBlockHeader(1, &wForkHash, &chainhash.Hash{0xfd, 0xfd},
		0x1f7fffff, 0)
	wForkExtend.Timestamp = time.Now()
	mineHeader(wForkExtend)
	forkExtend := *wireBlockHeaderToTBC(wForkExtend)

	invalidBitsHeader := validHeader
	invalidBitsHeader.Bits = "invalidbits"

	testTable := []testTableItem{
		{
			name: "valid",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{*b3h, validHeader},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error != nil {
					return resp.Error
				}
				if *resp.CanonicalHeader != validHeader {
					return fmt.Errorf("wanted canonical header %v, got %v",
						validHeader, resp.CanonicalHeader)
				}
				if *resp.LastHeader != validHeader {
					return fmt.Errorf("wanted last header %v, got %v",
						validHeader, resp.LastHeader)
				}
				if resp.InsertType != tbcd.ITChainExtend.String() {
					return fmt.Errorf("wanted IT %s, got %s",
						tbcd.ITChainExtend, resp.InsertType)
				}
				if resp.InsertedCount != 1 {
					return fmt.Errorf("wanted insert count %d, got %d",
						1, resp.InsertedCount)
				}
				return nil
			},
		},
		{
			name: "fork extend",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{fork},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error != nil {
					return resp.Error
				}
				if *resp.CanonicalHeader != validHeader {
					return fmt.Errorf("wanted canonical header %v, got %v",
						validHeader, resp.CanonicalHeader)
				}
				if *resp.LastHeader != fork {
					return fmt.Errorf("wanted last header %v, got %v",
						fork, resp.LastHeader)
				}
				if resp.InsertType != tbcd.ITForkExtend.String() {
					return fmt.Errorf("wanted IT %s, got %s",
						tbcd.ITForkExtend, resp.InsertType)
				}
				if resp.InsertedCount != 1 {
					return fmt.Errorf("wanted insert count %d, got %d",
						1, resp.InsertedCount)
				}
				return nil
			},
		},
		{
			name: "chain fork",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{forkExtend},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error != nil {
					return resp.Error
				}
				if *resp.CanonicalHeader != forkExtend {
					return fmt.Errorf("wanted canonical header %v, got %v",
						forkExtend, resp.CanonicalHeader)
				}
				if *resp.LastHeader != forkExtend {
					return fmt.Errorf("wanted last header %v, got %v",
						forkExtend, resp.LastHeader)
				}
				if resp.InsertType != tbcd.ITChainFork.String() {
					return fmt.Errorf("wanted IT %s, got %s",
						tbcd.ITChainFork, resp.InsertType)
				}
				if resp.InsertedCount != 1 {
					return fmt.Errorf("wanted insert count %d, got %d",
						1, resp.InsertedCount)
				}
				return nil
			},
		},
		{
			name: "duplicate",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{validHeader},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error == nil {
					return errors.New("expected error")
				}
				return nil
			},
		},
		{
			name: "invalid bits",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{invalidBitsHeader},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error == nil {
					return errors.New("expected error")
				}
				return nil
			},
		},
		{
			name: "empty headers",
			request: tbcadminapi.BlockHeadersInsertRequest{
				BlockHeaders: []tbcapi.BlockHeader{},
			},
			postCheck: func(resp *tbcadminapi.BlockHeadersInsertResponse) error {
				if resp.Error == nil {
					return errors.New("expected error")
				}
				return nil
			},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			c := dialAdmin(ctx, t, adminURL)
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{conn: protocol.NewWSConn(c)}

			if err := tbcadminapi.Write(ctx, tws.conn, "someid", tti.request); err != nil {
				t.Fatal(err)
			}

			msg := readAdminMessage(ctx, t, c)
			var resp tbcadminapi.BlockHeadersInsertResponse
			if err := json.Unmarshal(msg.Payload, &resp); err != nil {
				t.Fatal(err)
			}

			if err := tti.postCheck(&resp); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAdminRPCSyncIndexersToHash(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	adminURL, s, n := createLocalTBCServer(ctx, t, testJWTString)

	// Connect to admin RPC
	c := dialAdmin(ctx, t, adminURL)
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)
	tws := &tbcWs{conn: protocol.NewWSConn(c)}

	b3 := n.blocksAtHeight[3][0]
	req := tbcadminapi.SyncIndexersToHashRequest{
		Hash: *b3.Hash(),
	}
	if err := tbcadminapi.Write(ctx, tws.conn, "someid", req); err != nil {
		t.Fatal(err)
	}

	var done bool
	for !done {
		_, _, payload, err := tbcadminapi.Read(ctx, tws.conn)
		if err != nil {
			t.Fatal(err)
		}
		p, ok := payload.(*tbcadminapi.JobUpdateNotification)
		if !ok {
			t.Fatalf("unexpected message type: %v", payload)
		}
		if p.Error != nil {
			t.Fatalf("unexpected error: %v", p.Error)
		}

		switch p.Job.Status {
		case string(JobStatusPending):
		case string(JobStatusRunning):
		case string(JobStatusCompleted):
			done = true
		default:
			t.Fatalf("unexpected job status: %s", p.Job.Status)
		}
	}

	b1 := n.blocksAtHeight[1][0]
	b2 := n.blocksAtHeight[2][0]
	err := mustHave(ctx, t, s, n.genesis, b1, b2, b3)
	if err != nil {
		t.Fatal(err)
	}

	// verify tx
	for address := range n.keys {
		balance, err := s.BalanceByAddress(ctx, address)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, balance)
		utxos, err := s.UtxosByAddress(ctx, true, address, 0, 100)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%v: %v", address, utxos)
	}

	// Verify linear indexing. Current TxIndex is sitting at b3
	t.Logf("b3: %v", b3)

	// b3 -> genesis should work with positive direction (cdiff is greater than target)
	direction, err := indexIsLinear(ctx, s.g, *b3.Hash(), *s.g.chain.GenesisHash)
	if err != nil {
		t.Fatalf("expected success b3 -> genesis, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}

	// b3 -> b1 should work with positive direction
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *b1.Hash())
	if err != nil {
		t.Fatalf("expected success b3 -> b1, got %v", err)
	}
	if direction != -1 {
		t.Fatalf("expected -1 going from b3 to genesis, got %v", direction)
	}
}

func TestAdminRPCNotFound(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()

	type testTableItem struct {
		name      string
		request   any
		postCheck func(msg protocol.Message) error
	}

	adminURL, _, _ := createLocalTBCServer(ctx, t, testJWTString)
	fakeID := "fakeID"

	testTable := []testTableItem{
		{
			name:    "JobStatusRequest",
			request: tbcadminapi.JobStatusRequest{JobID: fakeID},
			postCheck: func(msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobUpdateNotification {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobUpdateNotification, msg.Header.Command)
				}
				var resp tbcadminapi.JobUpdateNotification
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				expectedErr := protocol.NotFoundError("job", fakeID)
				if resp.Error.Message != expectedErr.Message {
					return fmt.Errorf("unexpected error %w, wanted %w",
						resp.Error, expectedErr)
				}
				return nil
			},
		},
		{
			name:    "JobSubscribeRequest",
			request: tbcadminapi.JobSubscribeRequest{JobID: fakeID},
			postCheck: func(msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobUpdateNotification {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobUpdateNotification, msg.Header.Command)
				}
				var resp tbcadminapi.JobUpdateNotification
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				expectedErr := protocol.NotFoundError("job", fakeID)
				if resp.Error.Message != expectedErr.Message {
					return fmt.Errorf("unexpected error %w, wanted %w",
						resp.Error, expectedErr)
				}
				return nil
			},
		},
		{
			name:    "JobCancelRequest",
			request: tbcadminapi.JobCancelRequest{JobID: fakeID},
			postCheck: func(msg protocol.Message) error {
				if msg.Header.Command != tbcadminapi.CmdJobCancelResponse {
					return fmt.Errorf("expected %s, got %s",
						tbcadminapi.CmdJobCancelResponse, msg.Header.Command)
				}
				var resp tbcadminapi.JobCancelResponse
				if err := json.Unmarshal(msg.Payload, &resp); err != nil {
					return err
				}
				expectedErr := protocol.NotFoundError("job", fakeID)
				if resp.Error.Message != expectedErr.Message {
					return fmt.Errorf("unexpected error %w, wanted %w",
						resp.Error, expectedErr)
				}
				return nil
			},
		},
	}

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			c := dialAdmin(ctx, t, adminURL)
			defer c.CloseNow()

			assertPing(ctx, t, c, tbcapi.CmdPingRequest)

			tws := &tbcWs{conn: protocol.NewWSConn(c)}

			if err := tbcadminapi.Write(ctx, tws.conn, "someid", tti.request); err != nil {
				t.Fatal(err)
			}

			msg := readAdminMessage(ctx, t, c)
			if err := tti.postCheck(msg); err != nil {
				t.Fatal(err)
			}
		})
	}
}
