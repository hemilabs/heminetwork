// Copyright (c) 2024-2025 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package tbc

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hemilabs/heminetwork/v2/api/protocol"
	tapi "github.com/hemilabs/heminetwork/v2/api/tbcadminapi"
	"github.com/hemilabs/heminetwork/v2/api/tbcapi"
)

const jwtExpiryTimeout = 60 * time.Second

type tbcAdminWs struct {
	tbcWs
	listener *Listener
}

func (s *Server) validateJWT(strToken string) error {
	keyFunc := func(token *jwt.Token) (any, error) {
		return s.adminJWTSecret, nil
	}

	var claims jwt.RegisteredClaims
	token, err := jwt.ParseWithClaims(strToken, &claims, keyFunc,
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuedAt(),
		jwt.WithExpirationRequired(), jwt.WithNotBeforeRequired(),
		jwt.WithLeeway(5*time.Second))
	if err != nil {
		return err
	}

	// Sanity checks
	switch {
	case !token.Valid:
		return errors.New("invalid token")
	case time.Since(claims.IssuedAt.Time) > jwtExpiryTimeout:
		return errors.New("stale token")
	case time.Until(claims.IssuedAt.Time) > jwtExpiryTimeout:
		return errors.New("future token")
	case time.Now().After(claims.ExpiresAt.Add(5 * time.Second)):
		return errors.New("token is expired")
	case time.Now().Before(claims.NotBefore.Add(-5 * time.Second)):
		return errors.New("token not ready for use")
	}

	return nil
}

// handleAdminWebsocket handles incoming admin WebSocket connections,
// authenticated using a JWT bearer token in the which MUST be signed
// with HS256 using the shared secret.
func (s *Server) handleAdminWebsocket(w http.ResponseWriter, r *http.Request) {
	log.Tracef("handleAdminWebsocket: %v", r.RemoteAddr)
	defer log.Tracef("handleAdminWebsocket exit: %v", r.RemoteAddr)

	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		http.Error(w, "missing authorization header", http.StatusUnauthorized)
		return
	}
	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		http.Error(w, "invalid authorization header format", http.StatusUnauthorized)
		return
	}
	if err := s.validateJWT(token); err != nil {
		log.Errorf("Admin: JWT validation failed for %v: %v", r.RemoteAddr, err)
		http.Error(w, "invalid JWT token", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		CompressionMode: websocket.CompressionContextTakeover,
	})
	if err != nil {
		log.Errorf("Failed to accept websocket connection for %s: %v",
			r.RemoteAddr, err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "") // Force close connection

	aws := &tbcAdminWs{
		tbcWs: tbcWs{
			addr:           r.RemoteAddr,
			conn:           protocol.NewWSConn(conn),
			requestContext: r.Context(),
		},
	}

	// Admin connections must receive the notifications, so force notifiers
	// to block until the notification goes through.
	aws.sessionID, aws.listener, err = s.adminSessions.NewSession(r.Context(), true)
	if err != nil {
		log.Errorf("An error occurred while creating client: %v", err)
		return
	}
	defer s.adminSessions.DeleteSession(aws.sessionID)

	aws.wg.Add(1)
	go s.handleAdminWebsocketRead(r.Context(), aws)

	aws.wg.Add(1)
	go s.handleAdminNotificationRead(r.Context(), aws)

	// Send initial ping (required by protocol).
	ping := &tbcapi.PingRequest{
		Timestamp: time.Now().Unix(),
	}

	log.Tracef("Responding with %v", spew.Sdump(ping))
	if err := tapi.Write(r.Context(), aws.conn, "0", ping); err != nil {
		log.Errorf("Admin: write ping: %v", err)
		return
	}

	log.Infof("Admin RPC connection from %v", r.RemoteAddr)

	// Wait for termination.
	aws.wg.Wait()

	log.Infof("Admin RPC connection terminated from %v", r.RemoteAddr)
}

func (s *Server) getTBCAdminAPICommandHandler(cmd protocol.Command, payload any, ws *tbcAdminWs) func(ctx context.Context) (any, string, error) {
	switch cmd {
	case tapi.CmdSyncIndexersToHashRequest:
		return func(ctx context.Context) (any, string, error) {
			return s.handleSyncIndexersToHashRequest(ctx, ws.sessionID, payload.(*tapi.SyncIndexersToHashRequest))
		}
	case tapi.CmdJobSubscribeRequest:
		return func(ctx context.Context) (any, string, error) {
			res, err := s.handleJobSubscribeRequest(ctx, ws.sessionID, payload.(*tapi.JobSubscribeRequest))
			return res, "", err
		}
	case tapi.CmdJobListRequest:
		return func(ctx context.Context) (any, string, error) {
			res, err := s.handleJobListRequest(ctx, payload.(*tapi.JobListRequest))
			return res, "", err
		}
	case tapi.CmdJobStatusRequest:
		return func(ctx context.Context) (any, string, error) {
			res, err := s.handleJobStatusRequest(ctx, payload.(*tapi.JobStatusRequest))
			return res, "", err
		}
	case tapi.CmdJobCancelRequest:
		return func(ctx context.Context) (any, string, error) {
			res, err := s.handleJobCancelRequest(ctx, payload.(*tapi.JobCancelRequest))
			return res, "", err
		}
	default:
		// fallthrough to default tbcapi commands
		handler := s.getTBCAPICommandHandler(cmd, payload)
		if handler != nil {
			return func(ctx context.Context) (any, string, error) {
				res, err := handler(ctx)
				return res, "", err
			}
		}
		return nil
	}
}

func (s *Server) handleAdminNotificationRead(ctx context.Context, ws *tbcAdminWs) {
	defer ws.wg.Done()

	log.Tracef("handleAdminNotificationRead: %v", ws.addr)
	defer log.Tracef("handleAdminNotificationRead exit: %v", ws.addr)

	for {
		msg, err := ws.listener.Listen(ctx)
		if err != nil {
			log.Errorf("handleAdminNotificationRead: listen %v: %v",
				ws.addr, err)
			return
		}
		info := &tapi.JobUpdateNotification{
			Job: tapi.JobInfo{
				JobID:   msg.ID,
				JobType: msg.Type,
				Status:  msg.Msg,
			},
		}
		if err := tapi.Write(ctx, ws.conn, msg.ID, info); err != nil {
			log.Errorf("handleAdminNotificationRead: write to %v: %v",
				ws.addr, err)
			return
		}
	}
}

func (s *Server) handleAdminWebsocketRead(ctx context.Context, ws *tbcAdminWs) {
	defer ws.wg.Done()

	log.Tracef("handleAdminWebsocketRead: %v", ws.addr)
	defer log.Tracef("handleAdminWebsocketRead exit: %v", ws.addr)

	for {
		cmd, id, payload, err := tapi.Read(ctx, ws.conn)
		if err != nil {
			var ce websocket.CloseError
			if errors.As(err, &ce) {
				log.Tracef("handleAdminWebsocketRead: %v", err)
				return
			}
			if errors.Is(err, io.EOF) {
				log.Tracef("handleAdminWebsocketRead: EOF")
				return
			}
			log.Errorf("handleAdminWebsocketRead: %v", err)
			return
		}

		handler := s.getTBCAdminAPICommandHandler(cmd, payload, ws)
		if handler == nil {
			log.Errorf("handleAdminWebsocketRead %s %s %s: %v",
				ws.addr, cmd, id, "unknown command")
			return
		}

		go s.handleAdminRequest(ctx, ws, id, cmd, handler)
	}
}

func (s *Server) handleAdminRequest(ctx context.Context, ws *tbcAdminWs, id string, cmd protocol.Command, handler func(ctx context.Context) (any, string, error)) {
	log.Tracef("handleRequest: %s: %s", ws.addr, cmd)
	defer log.Tracef("handleRequest exit: %s: %s", ws.addr, cmd)

	ctx, cancel := context.WithTimeout(ctx, s.requestTimeout)
	defer cancel()

	res, jobID, err := handler(ctx)
	if err != nil {
		log.Errorf("Failed to handle %s request for %s: %v", cmd, ws.addr, err)
	}

	if res == nil {
		return
	}

	if err = tapi.Write(ctx, ws.conn, id, res); err != nil {
		log.Errorf("Failed to handle %s request for %s: protocol write failed: %v",
			cmd, ws.addr, err)
	}

	if jobID != "" {
		if err := s.adminSessions.StartJob(jobID); err != nil {
			// This should never happen, as the only possible error
			// would be from the hub not knowing the job. Still, if
			// more errors are added, this may become relevant.

			log.Errorf("Failed to start job %s: %v", jobID, err)
			if err := s.adminSessions.CancelJob(jobID); err != nil {
				log.Errorf("Failed to cancel job %s: %v", jobID, err)
			}

			err := s.adminSessions.BroadcastProgress(ctx, jobID, JobStatusFailed)
			if err != nil {
				log.Errorf("Failed to broadcast job failure %s: %v", jobID, err)
			}

			s.adminSessions.DeleteJob(jobID)
		}
	}

	// Request processed successfully
	s.cmdsProcessed.Inc()
}

func (s *Server) handleJobSubscribeRequest(_ context.Context, clientID string, req *tapi.JobSubscribeRequest) (any, error) {
	log.Tracef("handleJobSubscribeRequest")
	defer log.Tracef("handleJobSubscribeRequest exit")

	s.adminSessions.Subscribe(clientID, req.JobID)

	info, err := s.adminSessions.JobStatus(req.JobID)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			return tapi.JobUpdateNotification{
				Error: protocol.NotFoundError("job", req.JobID),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return tapi.JobUpdateNotification{
			Error: e.ProtocolError(),
		}, e
	}

	return tapi.JobUpdateNotification{
		Job: info,
	}, nil
}

func (s *Server) handleJobCancelRequest(_ context.Context, req *tapi.JobCancelRequest) (any, error) {
	log.Tracef("handleJobCancelRequest")
	defer log.Tracef("handleJobCancelRequest exit")

	if err := s.adminSessions.CancelJob(req.JobID); err != nil {
		if errors.Is(err, ErrJobNotFound) {
			return tapi.JobCancelResponse{
				Error: protocol.NotFoundError("job", req.JobID),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return tapi.JobCancelResponse{
			Error: e.ProtocolError(),
		}, e
	}

	return &tapi.JobCancelResponse{
		JobID: req.JobID,
	}, nil
}

func (s *Server) handleJobListRequest(_ context.Context, _ *tapi.JobListRequest) (any, error) {
	log.Tracef("handleJobListRequest")
	defer log.Tracef("handleJobListRequest exit")

	return &tapi.JobListResponse{
		Jobs: s.adminSessions.JobList(),
	}, nil
}

func (s *Server) handleJobStatusRequest(_ context.Context, req *tapi.JobStatusRequest) (any, error) {
	log.Tracef("handleJobStatusRequest")
	defer log.Tracef("handleJobStatusRequest exit")

	info, err := s.adminSessions.JobStatus(req.JobID)
	if err != nil {
		if errors.Is(err, ErrJobNotFound) {
			return tapi.JobUpdateNotification{
				Error: protocol.NotFoundError("job", req.JobID),
			}, nil
		}

		e := protocol.NewInternalError(err)
		return tapi.JobUpdateNotification{
			Error: e.ProtocolError(),
		}, e
	}

	return &tapi.JobUpdateNotification{
		Job: info,
	}, nil
}

func (s *Server) handleSyncIndexersToHashRequest(_ context.Context, sessionID string, req *tapi.SyncIndexersToHashRequest) (any, string, error) {
	log.Tracef("handleSyncIndexersToHashRequest")
	defer log.Tracef("handleSyncIndexersToHashRequest exit")

	runFunc := func(jctx context.Context, jobID string) {
		defer s.adminSessions.DeleteJob(jobID)

		// Broadcast initial running status.
		err := s.adminSessions.BroadcastProgress(jctx, jobID, JobStatusRunning)
		if err != nil {
			log.Errorf("Failed to broadcast job update %s: %v", jobID, err)
		}

		if err := s.SyncIndexersToHash(jctx, req.Hash); err != nil {
			err := s.adminSessions.BroadcastProgress(s.adminSessions.ctx, jobID, JobStatusFailed)
			if err != nil {
				log.Errorf("Failed to broadcast job update %s: %v", jobID, err)
			}
			return
		}

		// Job may theoretically have been cancelled, but if we completed
		// despite the ctx being cancelled, report as success.
		err = s.adminSessions.BroadcastProgress(jctx, jobID, JobStatusCompleted)
		if err != nil {
			log.Errorf("Failed to broadcast job update %s: %v", jobID, err)
		}
	}

	jid, err := s.adminSessions.NewJob(SyncIndexersToHashJob, runFunc)
	if err != nil {
		e := protocol.NewInternalError(err)
		return tapi.JobUpdateNotification{
			Error: e.ProtocolError(),
		}, "", e
	}

	s.adminSessions.Subscribe(sessionID, jid)

	return &tapi.JobUpdateNotification{
		Job: tapi.JobInfo{
			JobID:   jid,
			JobType: string(SyncIndexersToHashJob),
			Status:  string(JobStatusPending),
		},
	}, jid, nil
}
