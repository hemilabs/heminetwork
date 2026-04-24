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
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/golang-jwt/jwt/v5"
	"github.com/juju/loggo/v2"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	"github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
	"github.com/hemilabs/heminetwork/v2/internal/testutil"
	"github.com/hemilabs/heminetwork/v2/service/tbc/peer/rawpeer"
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

func createTbcAdminServer(ctx context.Context, t *testing.T, seeds []string) (*Server, string) {
	t.Helper()

	cfg := &Config{
		AutoIndex:               false,
		BlockCacheSize:          "10mb",
		BlockheaderCacheSize:    "1mb",
		BlockSanity:             false,
		LevelDBHome:             t.TempDir(),
		MaxCachedTxs:            1000,
		PeersWanted:             len(seeds),
		PrometheusListenAddress: "",
		ListenAddress:           "127.0.0.1:0",
		Network:                 networkLocalnet,
		NotificationBlocking:    true,
		Seeds:                   seeds,
		JWTSecret:               testJWTString,
		// LogLevel:                "tbcd=TRACE:tbc=TRACE:level=DEBUG",
	}
	_ = loggo.ConfigureLoggers(cfg.LogLevel)
	s, err := NewServer(cfg)
	if err != nil {
		t.Fatal(err)
	}

	// subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	go func() {
		err := s.Run(ctx)
		if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, rawpeer.ErrNoConn) {
			panic(err)
		}
	}()

	// Wait for http service to start up
	var tbcURL string
	for {
		msg, err := l.Listen(ctx)
		if err != nil {
			t.Fatal(err)
		}
		t.Log(msg)
		if msg.Error != nil {
			t.Fatal(msg.Error)
		}
		// TBC sends a notification when the http service has started.
		if !msg.Is(NotificationService("", "")) {
			continue
		}
		if addr := s.HTTPAddress(); addr != nil {
			tbcURL = addr.String()
			break
		}
	}
	adminURL := fmt.Sprintf("http://%s%s", tbcURL, tbcadminapi.RouteAdminWs)
	return s, adminURL
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

	now := time.Now()

	// Wrong key
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
	wrongKeySig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	// Valid
	signed, err = token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	validSig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	// Expired
	claims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(-2 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now),
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err = token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	expiredSig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	// Not ready
	claims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Minute)),
		NotBefore: jwt.NewNumericDate(now.Add(2 * time.Minute)),
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err = token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	futureSig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	// Stale token
	claims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(-2 * jwtExpiryTimeout)),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		NotBefore: jwt.NewNumericDate(now),
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err = token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	staleTokenSig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	// Future token
	claims = jwt.RegisteredClaims{
		IssuedAt:  jwt.NewNumericDate(now.Add(2 * jwtExpiryTimeout)),
		ExpiresAt: jwt.NewNumericDate(now.Add(30 * time.Second)),
		NotBefore: jwt.NewNumericDate(now),
	}
	token = jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signed, err = token.SignedString(testJWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	futureTokenSig := http.Header{
		"Authorization": []string{"Bearer " + signed},
	}

	type testTableItem struct {
		name          string
		header        http.Header
		expectedError bool
	}

	testTable := []testTableItem{
		{
			name:          "missing header",
			expectedError: true,
		},
		{
			name: "invalid auth format",
			header: http.Header{
				"Authorization": []string{"Basic dXNlcjpwYXNz"},
			},
			expectedError: true,
		},
		{
			name: "invalid token",
			header: http.Header{
				"Authorization": []string{"Bearer invalid_token_here"},
			},
			expectedError: true,
		},
		{
			name:          "invalid signature key",
			header:        wrongKeySig,
			expectedError: true,
		},
		{
			name:          "expired claims",
			header:        expiredSig,
			expectedError: true,
		},
		{
			name:          "future claims",
			header:        futureSig,
			expectedError: true,
		},
		{
			name:          "stale token",
			header:        staleTokenSig,
			expectedError: true,
		},
		{
			name:          "future token",
			header:        futureTokenSig,
			expectedError: true,
		},
		{
			name:   "valid",
			header: validSig,
		},
	}

	_, adminURL := createTbcAdminServer(ctx, t, nil)

	for _, tti := range testTable {
		t.Run(tti.name, func(t *testing.T) {
			c, resp, err := websocket.Dial(ctx, adminURL, &websocket.DialOptions{
				HTTPHeader: tti.header,
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

	s, adminURL := createTbcAdminServer(ctx, t, nil)

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
					return fmt.Errorf("empty job ID")
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
					return fmt.Errorf("unknown job ")
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
				if resp.Height != 0 {
					return fmt.Errorf("expected height 0, got %d", resp.Height)
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
				if resp.Height != 0 {
					return fmt.Errorf("expected height 0, got %d", resp.Height)
				}
				if resp.BlockHeader == nil {
					return fmt.Errorf("expected non-nil block header")
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

func TestAdminRPCSyncIndexersToHash(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer func() {
		cancel()
	}()

	n, err := newFakeNode(t)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		err := n.Stop()
		if err != nil {
			t.Logf("node stop: %v", err)
		}
	}()
	go func() {
		err := n.Run(ctx)
		if !testutil.ErrorIsOneOf(err, []error{net.ErrClosed, context.Canceled, rawpeer.ErrNoConn}) {
			panic(err)
		}
	}()

	s, adminURL := createTbcAdminServer(ctx, t, []string{n.Address()})

	// Subscribe to tbc notifications
	l, err := s.SubscribeNotifications(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Unsubscribe()

	// wait for node to connect as peer
	select {
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	case <-n.msgCh:
	}

	// g ->  b1 ->  b2 -> b3

	parent := chaincfg.RegressionNetParams.GenesisHash
	address := n.address
	b1, err := n.MineAndSend(ctx, "b1", parent, address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := n.MineAndSend(ctx, "b2", b1.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}
	b3, err := n.MineAndSend(ctx, "b3", b2.Hash(), address, MineNoKeystones)
	if err != nil {
		t.Fatal(err)
	}

	// make sure tbc downloads blocks
	if err := n.MineAndSendEmpty(ctx); err != nil {
		t.Fatal(err)
	}

	// Wait for tbc to insert all blocks
	if err := s.waitForBlocks(ctx, l, n.blocksAtHeight); err != nil {
		t.Fatal(err)
	}
	l.Unsubscribe()

	// Verify linear indexing. Current TxIndex is sitting at genesis

	// genesis -> b3 should work with negative direction (cdiff is less than target)
	direction, err := indexIsLinear(ctx, s.g, *s.g.chain.GenesisHash, *b3.Hash())
	if err != nil {
		t.Fatalf("expected success g -> b3, got %v", err)
	}
	if direction <= 0 {
		t.Fatalf("expected 1 going from genesis to b3, got %v", direction)
	}

	// Connect to admin RPC
	c := dialAdmin(ctx, t, adminURL)
	defer c.CloseNow()

	assertPing(ctx, t, c, tbcapi.CmdPingRequest)
	tws := &tbcWs{conn: protocol.NewWSConn(c)}

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

	err = mustHave(ctx, t, s, n.genesis, b1, b2, b3)
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
	direction, err = indexIsLinear(ctx, s.g, *b3.Hash(), *s.g.chain.GenesisHash)
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

	_, adminURL := createTbcAdminServer(ctx, t, nil)
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
