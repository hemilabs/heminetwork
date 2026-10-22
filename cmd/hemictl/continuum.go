// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

// defaultContinuumAddress is transfunctionerd's admin listener, not
// its peer listener.  Admin RPCs are authorized on the provenance of
// that listener; the same request sent to the peer port is refused.
const defaultContinuumAddress = "localhost:45068"

var (
	continuumAddress string
	continuumCM      = config.CfgMap{
		"HEMICTL_CONTINUUM_ADDRESS": config.Config{
			Value:        &continuumAddress,
			DefaultValue: defaultContinuumAddress,
			Help:         "admin address of local transfunctionerd (TRF_ADMIN_LISTEN_ADDRESS)",
			Print:        config.PrintAll,
		},
	}
)

// continuumDial connects to a running transfunctionerd using an
// ephemeral secp256k1 key, performs KX + handshake, and returns the
// transport and the ephemeral secret (for writing).  The caller is
// responsible for closing the transport.
func continuumDial(ctx context.Context, addr string) (*continuum.Transport, *continuum.Secret, error) {
	secret, err := continuum.NewSecret()
	if err != nil {
		return nil, nil, fmt.Errorf("new secret: %w", err)
	}

	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("dial %s: %w", addr, err)
	}

	transport := new(continuum.Transport)
	ok := false
	defer func() {
		if !ok {
			transport.Close()
		}
	}()

	if err := transport.KeyExchange(ctx, conn); err != nil {
		return nil, nil, fmt.Errorf("key exchange: %w", err)
	}

	_, _, err = transport.Handshake(ctx, secret)
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}

	ok = true
	return transport, secret, nil
}

func init() {
	registerCommand("continuum", "transfunctionerd admin RPCs", continuumHandler)
}

// continuumCommands holds the continuum actions.  The continuum_debug
// build tag adds ceremony commands (keygen, sign, reshare, suggest) from
// init().  Production builds only carry the read-only actions below —
// ceremony initiation comes from the blockchain, not from hemictl.
var continuumCommands = map[string]command{
	"peers": {
		help: "List all known peers with session status.",
		run: func(ctx context.Context, _ map[string]string) error {
			return continuumPeers(ctx)
		},
	},
	"status": {
		help: "Query ceremony status.",
		args: map[string]argument{
			"ceremony_id": {required: true, help: "ceremony id (hex)"},
		},
		run: func(ctx context.Context, args map[string]string) error {
			return continuumStatus(ctx, args["ceremony_id"])
		},
	},
	"list": {
		help: "List all known ceremonies.",
		run: func(ctx context.Context, _ map[string]string) error {
			return continuumList(ctx)
		},
	},
}

func continuumHandler(pctx context.Context, flags []string) error {
	grp := commandGroup{
		help:     "Issue admin RPCs to a running transfunctionerd.",
		commands: continuumCommands,
	}

	fs := flag.NewFlagSet("continuum", flag.ExitOnError)
	helpShort := fs.Bool("h", false, "display help")
	helpLong := fs.Bool("help", false, "display help")
	fs.Usage = func() {
		printGroupHelp("continuum", grp)
		fmt.Fprintf(os.Stderr, "\nENVIRONMENT:\n")
		config.Help(os.Stderr, continuumCM)
	}
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if len(flags) == 0 || *helpShort || *helpLong {
		fs.Usage()
		return nil
	}

	if err := config.Parse(continuumCM); err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	return dispatchGroup(ctx, grp, "continuum", fs.Args())
}

// continuumReadResponse reads from the transport, discarding gossip
// messages (PeerNotify, PeerListRequest, PingRequest) until we get a
// message of a type other than gossip.  Returns an error after 20
// reads without a match or if ctx is cancelled.
func continuumReadResponse(ctx context.Context, t *continuum.Transport) (any, error) {
	for i := 0; i < 20; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		_, cmd, err := t.Read()
		if err != nil {
			return nil, fmt.Errorf("read: %w", err)
		}
		switch cmd.(type) {
		case *continuum.PeerNotify,
			*continuum.PeerListRequest,
			*continuum.PeerListResponse,
			*continuum.PingRequest,
			*continuum.PingResponse:
			continue // gossip — discard
		}
		return cmd, nil
	}
	return nil, errors.New("no admin response after 20 reads")
}

// continuumPeers queries the peer list from a running transfunctionerd.
func continuumPeers(ctx context.Context) error {
	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	if err := t.Write(secret.Identity, continuum.PeerListAdminRequest{}); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	cmd, err := continuumReadResponse(ctx, t)
	if err != nil {
		return err
	}

	resp, ok := cmd.(*continuum.PeerListAdminResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %T", cmd)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

// continuumStatus queries a specific ceremony's status.
func continuumStatus(ctx context.Context, cidHex string) error {
	var ceremonyID continuum.CeremonyID
	if err := ceremonyID.UnmarshalJSON([]byte(`"` + cidHex + `"`)); err != nil {
		return fmt.Errorf("invalid ceremony_id: %w", err)
	}

	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	err = t.Write(secret.Identity, continuum.CeremonyStatusRequest{
		CeremonyID: ceremonyID,
	})
	if err != nil {
		return fmt.Errorf("write: %w", err)
	}

	cmd, err := continuumReadResponse(ctx, t)
	if err != nil {
		return err
	}

	resp, ok := cmd.(*continuum.CeremonyStatusResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %T", cmd)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}

// continuumList queries all known ceremonies.
func continuumList(ctx context.Context) error {
	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	if err := t.Write(secret.Identity, continuum.CeremonyListRequest{}); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	cmd, err := continuumReadResponse(ctx, t)
	if err != nil {
		return err
	}

	resp, ok := cmd.(*continuum.CeremonyListResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %T", cmd)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(resp)
}
