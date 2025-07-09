package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	addr = flag.String("addr", ":8531", "address to listen")

	activeConns atomic.Int64
	reqCount    atomic.Int64
)

func main() {
	flag.Parse()

	server := &http.Server{
		Addr:      *addr,
		ConnState: connTracker,
		Handler:   http.HandlerFunc(rpcHandler),
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go statsLogger()

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}

	go func() {
		if os.Getenv("PERFTEST") != "" {
			// captured by script
			log.Printf("LISTEN_PORT=%d\n", ln.Addr().(*net.TCPAddr).Port)
		}
		log.Println("Listening on", ln.Addr())
		if err := server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("Shutting down...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}
}

func connTracker(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew:
		activeConns.Add(1)
	case http.StateHijacked, http.StateClosed:
		activeConns.Add(-1)
	}
}

func rpcHandler(w http.ResponseWriter, r *http.Request) {
	reqCount.Add(1)

	if r.Method != http.MethodPost {
		log.Printf("Method not POST: %s\n", r.Method)
		http.Error(w, "invalid method", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Method string `json:"method"`
		ID     any    `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		log.Println("Invalid JSON")
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Method != "eth_blockNumber" {
		http.Error(w, "method not supported", http.StatusNotImplemented)
		return
	}

	resp := map[string]any{
		"jsonrpc": "2.0",
		"id":      req.ID,
		"result":  "0xdeadbeef", // block number
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
}

func statsLogger() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	nodeID := os.Getenv("NODE_ID")
	if nodeID != "" {
		nodeID = fmt.Sprintf("[%s] ", nodeID)
	}

	for range ticker.C {
		rc := reqCount.Swap(0)
		ac := activeConns.Load()
		fmt.Printf("%s[stats] conns=%d rps=%d\n", nodeID, ac, rc)
	}
}
