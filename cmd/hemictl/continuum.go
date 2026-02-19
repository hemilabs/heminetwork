// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
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
		fmt.Println("\tkeygen\t\tTrigger keygen ceremony (seed=<hex> threshold=<n> committee=<n>)")
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
	case "keygen":
		return continuumKeygen(ctx, args)
	default:
		return fmt.Errorf("unknown continuum action: %v", action)
	}
}

// continuumReadResponse reads from the transport, discarding gossip
// messages (PeerNotify, PeerListRequest, PingRequest) until we get a
// message of a type other than gossip.  Returns an error after 20
// reads without a match.
func continuumReadResponse(t *continuum.Transport) (any, error) {
	for i := 0; i < 20; i++ {
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

	cmd, err := continuumReadResponse(t)
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

	cmd, err := continuumReadResponse(t)
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

	cmd, err := continuumReadResponse(t)
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

// continuumKeygen triggers a keygen ceremony.  Connects to the local
// transfunctionerd, queries peers, elects a committee, and sends
// encrypted KeygenRequest to each committee member.  Fire-and-forget:
// use `hemictl continuum status` to poll the result.
//
// Args: seed=<hex> threshold=<n> committee=<n>
// If seed is omitted, SHA256(unix_timestamp) is used.
func continuumKeygen(ctx context.Context, args map[string]string) error {
	// Parse threshold.
	thresholdStr := args["threshold"]
	if thresholdStr == "" {
		return fmt.Errorf("threshold required")
	}
	threshold, err := strconv.Atoi(thresholdStr)
	if err != nil {
		return fmt.Errorf("invalid threshold: %w", err)
	}

	// Parse committee size.
	committeeSizeStr := args["committee"]
	if committeeSizeStr == "" {
		return fmt.Errorf("committee required")
	}
	committeeSize, err := strconv.Atoi(committeeSizeStr)
	if err != nil {
		return fmt.Errorf("invalid committee: %w", err)
	}

	// Parse seed (optional — default to SHA256 of current unix timestamp).
	var seed []byte
	if seedHex := args["seed"]; seedHex != "" {
		seed, err = hex.DecodeString(seedHex)
		if err != nil {
			return fmt.Errorf("invalid seed hex: %w", err)
		}
	} else {
		h := sha256.Sum256([]byte(strconv.FormatInt(time.Now().Unix(), 10)))
		seed = h[:]
	}

	// Connect.
	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	// Query peers.
	if err := t.Write(secret.Identity, continuum.PeerListAdminRequest{}); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	cmd, err := continuumReadResponse(t)
	if err != nil {
		return err
	}
	resp, ok := cmd.(*continuum.PeerListAdminResponse)
	if !ok {
		return fmt.Errorf("unexpected response: %T", cmd)
	}

	// Filter to connected peers with valid NaClPub.  Exclude our
	// own ephemeral identity — hemictl is not a ceremony participant.
	type candidate struct {
		id      continuum.Identity
		naclPub []byte
	}
	candidates := make([]candidate, 0, len(resp.Peers))
	for _, pr := range resp.Peers {
		if pr.Identity == secret.Identity {
			continue // exclude ourselves
		}
		if !pr.Connected && !pr.Self {
			continue
		}
		if len(pr.NaClPub) != continuum.NaClPubSize {
			continue
		}
		candidates = append(candidates, candidate{
			id:      pr.Identity,
			naclPub: pr.NaClPub,
		})
	}

	if len(candidates) < committeeSize {
		return fmt.Errorf("only %d eligible peers, need %d",
			len(candidates), committeeSize)
	}

	// Extract identities for election.
	peerIDs := make([]continuum.Identity, len(candidates))
	for i, c := range candidates {
		peerIDs[i] = c.id
	}

	// Elect committee.
	committee, err := continuum.Elect(seed, peerIDs, committeeSize)
	if err != nil {
		return fmt.Errorf("election: %w", err)
	}

	coordinator := committee[0]
	fmt.Printf("elected committee (%d members, threshold %d):\n", committeeSize, threshold)
	for i, id := range committee {
		role := "  member"
		if i == 0 {
			role = "  coordinator"
		}
		fmt.Printf("%s: %v\n", role, id)
	}

	// Build KeygenRequest.
	ceremonyID := continuum.NewCeremonyID()
	partyIDs := continuum.IdentitiesToPartyIDs(committee)
	req := continuum.KeygenRequest{
		CeremonyID:  ceremonyID,
		Curve:       "secp256k1",
		Committee:   partyIDs,
		Threshold:   threshold,
		Coordinator: coordinator,
	}

	// Send KeygenRequest to each committee member.  Plain routed
	// payload — hop-by-hop transport encryption is sufficient for
	// ceremony parameters (no secrets in a KeygenRequest).  The
	// local transfunctionerd forwards to the destination via the
	// routing header.
	for _, dest := range committee {
		if err := t.WriteTo(secret.Identity, dest, 8, req); err != nil {
			return fmt.Errorf("send to %v: %w", dest, err)
		}
		fmt.Printf("sent keygen to %v\n", dest)
	}

	fmt.Printf("ceremony initiated: %s\n", ceremonyID)
	return nil
}
