// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/hemilabs/heminetwork/v2/config"
	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

const defaultContinuumAddress = "localhost:45067"

var (
	continuumAddress string
	continuumCM      = config.CfgMap{
		"HEMICTL_CONTINUUM_ADDRESS": config.Config{
			Value:        &continuumAddress,
			DefaultValue: defaultContinuumAddress,
			Help:         "address of local transfunctionerd",
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

	_, _, _, err = transport.Handshake(ctx, secret, "")
	if err != nil {
		return nil, nil, fmt.Errorf("handshake: %w", err)
	}

	ok = true
	return transport, secret, nil
}

// continuumctl implements the `hemictl continuum` subcommand.
func continuumctl(pctx context.Context, flags []string) error {
	flagSet := flag.NewFlagSet("continuum commands", flag.ExitOnError)
	var (
		helpFlag     = flagSet.Bool("h", false, "displays help information")
		helpLongFlag = flagSet.Bool("help", false, "displays help information")
	)

	flagSet.Usage = func() {
		fmt.Fprintf(os.Stderr, "%v\n", welcome)
		fmt.Fprintf(os.Stderr, "Usage: %v continuum [OPTION]... [ACTION]\n\n", os.Args[0])
		fmt.Println("COMMAND OVERVIEW:")
		fmt.Println("\tThe 'continuum' command issues admin RPCs to a running transfunctionerd.")
		fmt.Println("")
		fmt.Println("OPTIONS:")
		fmt.Println("\t-h, -help\tDisplay help information")
		fmt.Println("")
		fmt.Println("ACTIONS:")
		fmt.Println("\tpeers\t\tList all known peers with session status")
		fmt.Println("\tstatus\t\tQuery ceremony status (ceremony_id=<hex>)")
		fmt.Println("\tlist\t\tList all known ceremonies")
		for _, h := range continuumActionHelp {
			fmt.Println(h)
		}
		fmt.Println("")
		fmt.Println("ENVIRONMENT:")
		config.Help(os.Stderr, continuumCM)
	}

	if err := flagSet.Parse(flags); err != nil {
		return err
	}

	if len(flagSet.Args()) < 1 || *helpFlag || *helpLongFlag {
		flagSet.Usage()
		return nil
	}

	if err := config.Parse(continuumCM); err != nil {
		return err
	}

	action, args, err := parseArgs(flagSet.Args())
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(pctx)
	defer cancel()

	switch action {
	case "peers":
		return continuumPeers(ctx)
	case "status":
		cidHex := args["ceremony_id"]
		if cidHex == "" {
			return fmt.Errorf("ceremony_id required")
		}
		return continuumStatus(ctx, cidHex)
	case "list":
		return continuumList(ctx)
	default:
		if fn, ok := continuumActions[action]; ok {
			return fn(ctx, args)
		}
		return fmt.Errorf("unknown continuum action: %v", action)
	}
}

// continuumActions is populated by build-tagged init() functions.
// Debug builds register ceremony commands (keygen, sign, reshare).
var continuumActions = map[string]func(context.Context, map[string]string) error{}

// continuumActionHelp is populated alongside continuumActions.
var continuumActionHelp []string

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
	return nil, fmt.Errorf("no admin response after 20 reads")
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

	if err := t.Write(secret.Identity, continuum.CeremonyStatusRequest{
		CeremonyID: ceremonyID,
	}); err != nil {
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
