// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

package main

// This file implements the hemictl ceremony commands: keygen, sign, and
// reshare.  These are debug stand-ins for the production smart contract
// flow.  In production, the smart contract determines committee
// membership and ceremony parameters; here, the operator provides them
// explicitly via the command line.
//
// # Architecture: hemictl as blockchain stand-in
//
// In production, ceremony initiation is a blockchain event:
//
//  1. Smart contract emits a ceremony event (keygen/sign/reshare) with
//     the committee identities, threshold, and other parameters.
//  2. Every continuum node watches the chain.  Each node checks whether
//     its own identity appears in the committee.
//  3. Nodes that are in the committee start their TSS engine locally.
//     TSS round messages travel over the p2p mesh.
//  4. The coordinator (committee[0]) broadcasts the CeremonyResult.
//
// The p2p mesh is transport only — it carries TSS messages between
// nodes.  All "brains" (who participates, what ceremony, when) come
// from the blockchain.  Split brain, failover, coordinator election —
// all the blockchain's problem.
//
// hemictl short-circuits step 1: instead of a chain event, the
// operator calls hemictl which sends the ceremony request directly
// to each committee member via the local node's admin transport.
// From the receiving node's perspective, the KeygenRequest /
// SignRequest / ReshareRequest is identical regardless of whether
// it originated from a chain watcher or from hemictl.
//
// # Committee selection modes
//
// Two modes mirror the production/debug split:
//
//	members=<id1>,<id2>,...  Explicit identity list.  This is the
//	                         production code path — the smart contract
//	                         provides these identities.  hemictl
//	                         exercises the exact same dispatch.
//
//	auto=<n>                 Debug convenience.  Queries the local
//	                         node for connected peers, sorts them
//	                         deterministically by identity, and picks
//	                         the first N.  The result is fed into the
//	                         same explicit-members path.
//
// For reshare, old and new committees use prefixed variants:
// old_members= / old_auto= and new_members= / new_auto=.
//
// # Examples
//
// Generate a new key with 3 nodes, threshold 1 (need 2 of 3 to sign):
//
//	hemictl continuum keygen auto=3 threshold=1
//
// Same thing with explicit identities (what the chain would provide):
//
//	hemictl continuum keygen \
//	  members=aabbccddee00112233445566778899aabbccddee,\
//	  00112233445566778899aabbccddeeff00112233,\
//	  ffeeddccbbaa99887766554433221100ffeeddcc \
//	  threshold=1
//
// Poll until keygen completes and note the key_id:
//
//	hemictl continuum status ceremony_id=<hex from keygen output>
//
// Sign a 32-byte hash with 2 of the 3 key holders:
//
//	hemictl continuum sign auto=2 threshold=1 \
//	  key_id=<hex from status output> \
//	  data=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef
//
// Reshare from 3-node committee to 5-node committee:
//
//	hemictl continuum reshare \
//	  old_auto=3 new_auto=5 \
//	  old_threshold=1 new_threshold=2 \
//	  key_id=<hex>
//
// All commands are fire-and-forget.  Poll with:
//
//	hemictl continuum status ceremony_id=<hex>
//
// List all known ceremonies:
//
//	hemictl continuum list

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/hemilabs/heminetwork/v2/service/continuum"
)

func init() {
	continuumActions["keygen"] = continuumKeygen
	continuumActions["sign"] = continuumSign
	continuumActions["reshare"] = continuumReshare

	continuumActionHelp = append(continuumActionHelp,
		"\tkeygen\t\tTrigger keygen (members=<id1>,<id2>,... OR auto=<n> threshold=<n>)",
		"\tsign\t\tTrigger sign (members=... OR auto=<n> threshold=<n> key_id=<hex> data=<hex>)",
		"\treshare\t\tTrigger reshare (old_members=... new_members=... OR old_auto=<n> new_auto=<n> old_threshold=<n> new_threshold=<n> key_id=<hex>)",
	)
}

// =============================================================================
// Ceremony commands
// =============================================================================

// XXX(AL-CT): continuumKeygen, continuumSign, continuumReshare, autoSelectPeers,
// sendToUnion, and printCommittee have 0% unit coverage — they need a live
// Transport.  Wire these into the e2e test harness.

// continuumKeygen triggers a keygen ceremony.  Sends a KeygenRequest to
// each committee member via the local transfunctionerd's routed
// transport.  The first member in the resolved committee is designated
// the coordinator (responsible for broadcasting CeremonyResult).
//
// Fire-and-forget: use `hemictl continuum status ceremony_id=<hex>`
// to poll the result.
//
// Examples:
//
//	hemictl continuum keygen auto=3 threshold=1
//	hemictl continuum keygen members=02ab...,03cd...,04ef... threshold=1
func continuumKeygen(ctx context.Context, args map[string]string) error {
	threshold, err := requireInt(args, "threshold")
	if err != nil {
		return err
	}

	// Connect to local transfunctionerd.
	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	// Resolve committee: explicit members or auto-select.
	committee, err := resolveCommittee(ctx, t, secret, args)
	if err != nil {
		return err
	}

	// First member is the coordinator — mirrors the production
	// pattern where the smart contract designates committee[0].
	coordinator := committee[0]
	ceremonyID := continuum.NewCeremonyID()
	partyIDs := continuum.IdentitiesToPartyIDs(committee)

	req := continuum.KeygenRequest{
		CeremonyID:  ceremonyID,
		Curve:       "secp256k1",
		Committee:   partyIDs,
		Threshold:   threshold,
		Coordinator: coordinator,
	}

	printCommittee("keygen", committee, threshold)

	// Send to each committee member.  The local node routes via
	// the mesh — hemictl never talks to remote nodes directly.
	for _, dest := range committee {
		if err := t.WriteTo(secret.Identity, dest, 8, req); err != nil {
			return fmt.Errorf("send to %v: %w", dest, err)
		}
	}

	fmt.Printf("ceremony initiated: %s\n", ceremonyID)
	return nil
}

// continuumSign triggers a signing ceremony.  Sends a SignRequest to
// each committee member.  The committee must hold key shares for the
// specified keyID (obtained from a prior keygen via
// `hemictl continuum status`).
//
// data= must be a 32-byte hex hash — this is what the committee signs.
//
// Examples:
//
//	hemictl continuum sign auto=2 threshold=1 key_id=ab01... data=deadbeef...
//	hemictl continuum sign members=02ab...,03cd... threshold=1 key_id=ab01... data=deadbeef...
func continuumSign(ctx context.Context, args map[string]string) error {
	threshold, err := requireInt(args, "threshold")
	if err != nil {
		return err
	}

	keyID, err := requireHex(args, "key_id")
	if err != nil {
		return err
	}

	data, err := requireHex(args, "data")
	if err != nil {
		return err
	}
	if len(data) != 32 {
		return fmt.Errorf("data must be 32 bytes, got %d", len(data))
	}

	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	committee, err := resolveCommittee(ctx, t, secret, args)
	if err != nil {
		return err
	}

	ceremonyID := continuum.NewCeremonyID()
	partyIDs := continuum.IdentitiesToPartyIDs(committee)

	req := continuum.SignRequest{
		CeremonyID: ceremonyID,
		KeyID:      keyID,
		Committee:  partyIDs,
		Threshold:  threshold,
		Data:       data,
	}

	printCommittee("sign", committee, threshold)

	for _, dest := range committee {
		if err := t.WriteTo(secret.Identity, dest, 8, req); err != nil {
			return fmt.Errorf("send to %v: %w", dest, err)
		}
	}

	fmt.Printf("ceremony initiated: %s\n", ceremonyID)
	return nil
}

// continuumReshare triggers a reshare ceremony.  Reshare transfers key
// shares from an old committee to a new committee with potentially
// different size and threshold.  Both old and new committees receive the
// ReshareRequest; the TSS engine figures out each node's role based on
// which committee(s) it belongs to.
//
// Old and new committees are resolved independently using prefixed
// args: old_members=/old_auto= and new_members=/new_auto=.
//
// Examples:
//
//	hemictl continuum reshare old_auto=3 new_auto=5 old_threshold=1 new_threshold=2 key_id=ab01...
//	hemictl continuum reshare old_members=02ab...,03cd...,04ef... new_members=02ab...,05gh...,06ij...,07kl...,08mn... old_threshold=1 new_threshold=2 key_id=ab01...
func continuumReshare(ctx context.Context, args map[string]string) error {
	oldThreshold, err := requireInt(args, "old_threshold")
	if err != nil {
		return err
	}
	newThreshold, err := requireInt(args, "new_threshold")
	if err != nil {
		return err
	}

	keyID, err := requireHex(args, "key_id")
	if err != nil {
		return err
	}

	t, secret, err := continuumDial(ctx, continuumAddress)
	if err != nil {
		return err
	}
	defer t.Close()

	// Resolve old and new committees independently.  The prefix
	// maps old_members/old_auto and new_members/new_auto to the
	// same resolveCommittee logic.
	oldCommittee, err := resolveCommitteePrefix(ctx, t, secret, args, "old_")
	if err != nil {
		return fmt.Errorf("old committee: %w", err)
	}
	newCommittee, err := resolveCommitteePrefix(ctx, t, secret, args, "new_")
	if err != nil {
		return fmt.Errorf("new committee: %w", err)
	}

	ceremonyID := continuum.NewCeremonyID()
	oldPartyIDs := continuum.IdentitiesToPartyIDs(oldCommittee)
	newPartyIDs := continuum.IdentitiesToPartyIDs(newCommittee)

	req := continuum.ReshareRequest{
		CeremonyID:   ceremonyID,
		Curve:        "secp256k1",
		KeyID:        keyID,
		OldCommittee: oldPartyIDs,
		NewCommittee: newPartyIDs,
		OldThreshold: oldThreshold,
		NewThreshold: newThreshold,
	}

	fmt.Printf("old committee (%d members, threshold %d):\n",
		len(oldCommittee), oldThreshold)
	for _, id := range oldCommittee {
		fmt.Printf("  %v\n", id)
	}
	fmt.Printf("new committee (%d members, threshold %d):\n",
		len(newCommittee), newThreshold)
	for _, id := range newCommittee {
		fmt.Printf("  %v\n", id)
	}

	if err := sendToUnion(t, secret, req, oldCommittee, newCommittee); err != nil {
		return err
	}

	fmt.Printf("ceremony initiated: %s\n", ceremonyID)
	return nil
}

// =============================================================================
// Committee resolution
// =============================================================================

// resolveCommittee resolves a committee from args.  Two modes:
//
//	members=<id1>,<id2>,...  Production path.  Comma-separated hex
//	                         identity strings.  Exercises the exact
//	                         same code path as the smart contract.
//
//	auto=<n>                 Debug path.  Queries the local node for
//	                         connected peers, sorts by identity bytes,
//	                         picks first N.  Result is fed into the
//	                         same dispatch as explicit members.
//
// Exactly one of members= or auto= must be provided.
func resolveCommittee(ctx context.Context, t *continuum.Transport,
	secret *continuum.Secret, args map[string]string,
) ([]continuum.Identity, error) {
	return resolveCommitteePrefix(ctx, t, secret, args, "")
}

// resolveCommitteePrefix is resolveCommittee with a key prefix.
// Reshare uses "old_" and "new_" prefixes so old_members=/old_auto=
// and new_members=/new_auto= resolve independently.
func resolveCommitteePrefix(ctx context.Context, t *continuum.Transport,
	secret *continuum.Secret, args map[string]string, prefix string,
) ([]continuum.Identity, error) {
	membersKey := prefix + "members"
	autoKey := prefix + "auto"

	membersVal := args[membersKey]
	autoVal := args[autoKey]

	// Exactly one must be set.
	if membersVal != "" && autoVal != "" {
		return nil, fmt.Errorf("specify %s or %s, not both",
			membersKey, autoKey)
	}
	if membersVal == "" && autoVal == "" {
		return nil, fmt.Errorf("%s or %s required", membersKey, autoKey)
	}

	if membersVal != "" {
		return parseMembers(membersVal)
	}

	n, err := strconv.Atoi(autoVal)
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", autoKey, err)
	}
	if n < 1 {
		return nil, fmt.Errorf("%s must be >= 1", autoKey)
	}
	return autoSelectPeers(ctx, t, secret, n)
}

// parseMembers parses a comma-separated list of hex-encoded identity
// strings into a slice of Identities.  Each identity is a 20-byte
// ripemd160 hash (40 hex chars).
//
// Example input: "aabbccddee...,11223344..."
func parseMembers(s string) ([]continuum.Identity, error) {
	parts := strings.Split(s, ",")
	ids := make([]continuum.Identity, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		id, err := continuum.NewIdentityFromString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid identity %q: %w", p, err)
		}
		ids = append(ids, *id)
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("empty members list")
	}
	return ids, nil
}

// autoSelectPeers queries the local transfunctionerd for connected
// peers, filters to those with active sessions and valid NaCl public
// keys, sorts deterministically by identity bytes, and returns the
// first n.
//
// This is the debug convenience path.  The production path never calls
// this — the smart contract provides explicit identities.  auto= feeds
// the result into the same dispatch as members=, so the ceremony code
// doesn't know or care how the committee was selected.
func autoSelectPeers(ctx context.Context, t *continuum.Transport,
	secret *continuum.Secret, n int,
) ([]continuum.Identity, error) {
	// Ask the local node for its peer list.
	if err := t.Write(secret.Identity, continuum.PeerListAdminRequest{}); err != nil {
		return nil, fmt.Errorf("peer list request: %w", err)
	}

	cmd, err := continuumReadResponse(ctx, t)
	if err != nil {
		return nil, err
	}
	resp, ok := cmd.(*continuum.PeerListAdminResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected response: %T", cmd)
	}

	// Filter to connected peers with valid NaCl public keys.
	// Exclude our own ephemeral identity — hemictl is not a
	// ceremony participant, it's the stand-in smart contract.
	eligible := make([]continuum.Identity, 0, len(resp.Peers))
	for _, pr := range resp.Peers {
		if pr.Identity == secret.Identity {
			continue // exclude ourselves
		}
		if !pr.Connected && !pr.Self {
			continue // not reachable
		}
		if len(pr.NaClPub) != continuum.NaClPubSize {
			continue // can't do e2e encryption
		}
		eligible = append(eligible, pr.Identity)
	}

	// Sort by raw identity bytes for deterministic selection.
	// Two operators running auto=3 against the same node at the
	// same time get the same committee.
	sort.Slice(eligible, func(i, j int) bool {
		return bytes.Compare(eligible[i][:], eligible[j][:]) < 0
	})

	if len(eligible) < n {
		return nil, fmt.Errorf("only %d eligible peers, need %d",
			len(eligible), n)
	}

	return eligible[:n], nil
}

// =============================================================================
// Argument parsing helpers
// =============================================================================

// requireInt parses a required integer argument by key name.
// Returns a clear error if missing or malformed.
func requireInt(args map[string]string, key string) (int, error) {
	s := args[key]
	if s == "" {
		return 0, fmt.Errorf("%s required", key)
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %w", key, err)
	}
	return v, nil
}

// requireHex parses a required hex-encoded byte slice argument.
// Returns a clear error if missing or malformed.
func requireHex(args map[string]string, key string) ([]byte, error) {
	s := args[key]
	if s == "" {
		return nil, fmt.Errorf("%s required", key)
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("invalid %s hex: %w", key, err)
	}
	return b, nil
}

// =============================================================================
// Transport helpers
// =============================================================================

// sendToUnion sends cmd to the deduplicated union of committees a and b.
// Nodes that appear in both receive exactly one message.
func sendToUnion(t *continuum.Transport, secret *continuum.Secret, cmd any, a, b []continuum.Identity) error {
	sent := make(map[continuum.Identity]struct{}, len(a)+len(b))
	for _, dest := range a {
		sent[dest] = struct{}{}
		if err := t.WriteTo(secret.Identity, dest, 8, cmd); err != nil {
			return fmt.Errorf("send to %v: %w", dest, err)
		}
	}
	for _, dest := range b {
		if _, ok := sent[dest]; ok {
			continue
		}
		if err := t.WriteTo(secret.Identity, dest, 8, cmd); err != nil {
			return fmt.Errorf("send to %v: %w", dest, err)
		}
	}
	return nil
}

// =============================================================================
// Output helpers
// =============================================================================

// printCommittee prints the committee with role labels.  The first
// member is the coordinator (broadcasts CeremonyResult on completion).
func printCommittee(ceremony string, committee []continuum.Identity, threshold int) {
	fmt.Printf("%s committee (%d members, threshold %d):\n",
		ceremony, len(committee), threshold)
	for i, id := range committee {
		role := "  member"
		if i == 0 {
			role = "  coordinator"
		}
		fmt.Printf("%s: %v\n", role, id)
	}
}
