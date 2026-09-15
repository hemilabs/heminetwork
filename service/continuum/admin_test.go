// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package continuum

import "testing"

// TestAdminListenerLoopbackGuard locks the decision the admin accept
// loop makes before spending a goroutine and an unbounded KX/handshake
// on an inbound connection: only loopback peers are admitted.  An admin
// listener accidentally bound to an external interface must reject a
// remote client at accept time — not after requireAdmin refuses its
// RPCs, by which point the goroutine and crypto handshake work (which
// bypass the peer listener's handshake semaphore) are already spent.
func TestAdminListenerLoopbackGuard(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want bool
	}{
		{"ipv4 loopback", "127.0.0.1:45068", true},
		{"ipv6 loopback", "[::1]:45068", true},
		{"private", "192.168.1.10:45068", false},
		{"public", "1.2.3.4:45068", false},
		{"unspecified", "0.0.0.0:45068", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This is exactly the predicate the accept loop applies to
			// conn.RemoteAddr() before dispatching handleAdminConnection.
			if got := isLocalhost(badAddr(tt.addr)); got != tt.want {
				t.Fatalf("admin guard isLocalhost(%q) = %v, want %v",
					tt.addr, got, tt.want)
			}
		})
	}
}
