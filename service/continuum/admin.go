// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import (
	"context"
	"errors"
	"net"
)

// listenAdmin runs the admin accept loop on a dedicated port.
// Admin connections bypass PeersWanted capacity limits and do not
// participate in gossip or the ping/pong lifecycle.  They exist
// solely to inject ceremony commands (keygen, sign, reshare) and
// query status.
func (s *Server) listenAdmin(ctx context.Context, errC chan error) {
	defer s.wg.Done()

	listener, err := s.listenConfig.Listen(ctx, "tcp", s.cfg.AdminListenAddress)
	if err != nil {
		sendErr(ctx, errC, err)
		return
	}
	s.mtx.Lock()
	s.adminListenAddr = listener.Addr().String()
	s.mtx.Unlock()

	go func() {
		<-ctx.Done()
		if err := listener.Close(); err != nil {
			log.Errorf("admin listener close: %v", err)
		}
	}()

	for {
		conn, err := listener.Accept()
		if errors.Is(ctx.Err(), context.Canceled) {
			return
		}
		if err != nil {
			log.Errorf("admin accept: %v", err)
			continue
		}
		tcpKeepAlive(conn, tcpKeepAlivePeriod)
		s.wg.Add(1)
		go s.handleAdminConnection(ctx, conn)
	}
}

// handleAdminConnection performs KX + handshake on an admin connection,
// then enters the admin dispatch loop.  No capacity check, no
// handshake semaphore.
func (s *Server) handleAdminConnection(ctx context.Context, conn net.Conn) {
	var success bool
	defer func() {
		if !success {
			s.wg.Done()
		}
	}()

	id, transport, _, err := s.newTransport(ctx, conn)
	if err != nil {
		log.Warningf("admin transport %v: %v", conn.RemoteAddr(), err)
		return
	}

	log.Infof("admin connected: %v from %v", id, conn.RemoteAddr())

	success = true
	s.handle(ctx, id, transport, true)
}

// AdminListenAddress returns the actual bound address of the admin
// listener, or empty if not started.
func (s *Server) AdminListenAddress() string {
	s.mtx.RLock()
	defer s.mtx.RUnlock()
	return s.adminListenAddr
}
