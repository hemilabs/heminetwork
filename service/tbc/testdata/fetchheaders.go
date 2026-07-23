// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build ignore

// fetchheaders connects to a Bitcoin mainnet node via P2P and downloads
// raw block headers using the getheaders protocol message. Headers are
// written as a concatenated binary file (80 bytes per header).
//
// Usage: go run fetchheaders.go -blocks 32260 -out mainnet_headers.bin
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/wire"
)

func main() {
	target := flag.Int("blocks", 32260, "number of block headers to fetch")
	out := flag.String("out", "mainnet_headers.bin", "output file")
	peer := flag.String("peer", "", "peer address (host:port); if empty, uses DNS seeds")
	flag.Parse()

	params := &chaincfg.MainNetParams

	var addr string
	if *peer != "" {
		addr = *peer
	} else {
		// Resolve a mainnet DNS seed, prefer IPv4.
		for _, seed := range params.DNSSeeds {
			ips, err := net.LookupIP(seed.Host)
			if err != nil || len(ips) == 0 {
				continue
			}
			for _, ip := range ips {
				if ip.To4() != nil {
					addr = net.JoinHostPort(ip.String(), "8333")
					fmt.Fprintf(os.Stderr, "resolved %s -> %s\n", seed.Host, addr)
					break
				}
			}
			if addr != "" {
				break
			}
		}
		if addr == "" {
			fmt.Fprintln(os.Stderr, "could not resolve any DNS seed to IPv4")
			os.Exit(1)
		}
	}

	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dial %s: %v\n", addr, err)
		os.Exit(1)
	}
	defer conn.Close()

	pver := uint32(70016)
	btcnet := wire.MainNet

	// Send version.
	localAddr := wire.NewNetAddress(conn.LocalAddr().(*net.TCPAddr), 0)
	remoteAddr := wire.NewNetAddress(conn.RemoteAddr().(*net.TCPAddr), wire.SFNodeNetwork)
	nonce := uint64(0x1234)
	verMsg := wire.NewMsgVersion(localAddr, remoteAddr, nonce, 0)
	verMsg.UserAgent = "/fetchheaders/"
	verMsg.Services = 0

	conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := wire.WriteMessage(conn, verMsg, pver, btcnet); err != nil {
		fmt.Fprintf(os.Stderr, "write version: %v\n", err)
		os.Exit(1)
	}

	// Read version.
	msg, _, err := wire.ReadMessage(conn, pver, btcnet)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read version: %v\n", err)
		os.Exit(1)
	}
	if _, ok := msg.(*wire.MsgVersion); !ok {
		fmt.Fprintf(os.Stderr, "expected version, got %T\n", msg)
		os.Exit(1)
	}

	// Send verack.
	if err := wire.WriteMessage(conn, wire.NewMsgVerAck(), pver, btcnet); err != nil {
		fmt.Fprintf(os.Stderr, "write verack: %v\n", err)
		os.Exit(1)
	}

	// Read verack (skip other messages like sendheaders, feefilter).
	for {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		msg, _, err = wire.ReadMessage(conn, pver, btcnet)
		if err != nil {
			// btcd may not recognize newer protocol messages;
			// try reading the next one.
			fmt.Fprintf(os.Stderr, "skipping unrecognized message: %v\n", err)
			continue
		}
		if _, ok := msg.(*wire.MsgVerAck); ok {
			break
		}
	}

	fmt.Fprintln(os.Stderr, "handshake complete")

	// Collect headers via repeated getheaders.
	var allHeaders []*wire.BlockHeader
	tip := params.GenesisHash

	for len(allHeaders) < *target {
		getHeaders := wire.NewMsgGetHeaders()
		getHeaders.AddBlockLocatorHash(tip)

		conn.SetDeadline(time.Now().Add(30 * time.Second))
		if err := wire.WriteMessage(conn, getHeaders, pver, btcnet); err != nil {
			fmt.Fprintf(os.Stderr, "write getheaders: %v\n", err)
			os.Exit(1)
		}

		// Read until we get headers response (skip pings, unknown msgs).
		var hdrs *wire.MsgHeaders
		for {
			conn.SetDeadline(time.Now().Add(30 * time.Second))
			msg, _, err := wire.ReadMessage(conn, pver, btcnet)
			if err != nil {
				// Skip unrecognized protocol messages.
				fmt.Fprintf(os.Stderr, "skipping: %v\n", err)
				continue
			}
			switch m := msg.(type) {
			case *wire.MsgHeaders:
				hdrs = m
			case *wire.MsgPing:
				pong := wire.NewMsgPong(m.Nonce)
				if err := wire.WriteMessage(conn, pong, pver, btcnet); err != nil {
					fmt.Fprintf(os.Stderr, "pong: %v\n", err)
					os.Exit(1)
				}
				continue
			default:
				continue
			}
			break
		}

		if len(hdrs.Headers) == 0 {
			fmt.Fprintf(os.Stderr, "no more headers at height %d\n", len(allHeaders))
			break
		}

		allHeaders = append(allHeaders, hdrs.Headers...)
		last := hdrs.Headers[len(hdrs.Headers)-1]
		lastHash := last.BlockHash()
		tip = &lastHash
		fmt.Fprintf(os.Stderr, "received %d headers (total: %d)\n",
			len(hdrs.Headers), len(allHeaders))
	}

	if len(allHeaders) > *target {
		allHeaders = allHeaders[:*target]
	}

	// Write binary file: 4-byte LE count + 80 bytes per header.
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create: %v\n", err)
		os.Exit(1)
	}

	var countBuf [4]byte
	binary.LittleEndian.PutUint32(countBuf[:], uint32(len(allHeaders)))
	if _, err := f.Write(countBuf[:]); err != nil {
		fmt.Fprintf(os.Stderr, "write count: %v\n", err)
		os.Exit(1)
	}

	for i, hdr := range allHeaders {
		if err := hdr.BtcEncode(f, 0, wire.BaseEncoding); err != nil {
			fmt.Fprintf(os.Stderr, "serialize header %d: %v\n", i, err)
			os.Exit(1)
		}
	}

	if err := f.Close(); err != nil {
		fmt.Fprintf(os.Stderr, "close: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "wrote %d headers (%d bytes) to %s\n",
		len(allHeaders), 4+len(allHeaders)*80, *out)
}
