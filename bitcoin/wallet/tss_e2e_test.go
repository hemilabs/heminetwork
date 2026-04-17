// Copyright (c) 2026 Hemi Labs, Inc.
// Use of this source code is governed by the MIT License,
// which can be found in the LICENSE file.

//go:build tss_e2e
// +build tss_e2e

// This end-to-end test exercises the full TSS signing path against a
// real 2-of-3 ECDSA threshold committee assembled in-process from
// github.com/hemilabs/x/tss-lib/v3.  No mocks, no shortcuts:
//
//   1. Real Paillier pre-parameters (safe-prime generation).
//   2. Real 4-round distributed keygen.
//   3. Real 9-round distributed signing.
//   4. Assemble DER via ECDSASigFromRS from the raw (r, s) scalars the
//      committee emits.
//   5. Inject via TransactionApplyECDSA into a bitcoin tx whose
//      funding input is locked to the group public key's P2WPKH
//      address.
//   6. Run the btcd script engine against the signed transaction.
//
// The script engine is the same consensus validator that bitcoin
// nodes run against every witnessed input.  A pass here means the
// committee-produced signature is accepted by the bitcoin network
// for a real spend — not a simulation.
//
// Build tag `tss_e2e` gates this test because Paillier safe-prime
// generation makes it take several minutes per run.  Run with:
//
//     go test -tags tss_e2e -timeout 15m -run TestTSS_E2E \
//         ./bitcoin/wallet/
//
// Regular `make test` does not build this file.

package wallet

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
	"github.com/hemilabs/x/tss-lib/v3/crypto"
	"github.com/hemilabs/x/tss-lib/v3/ecdsa/keygen"
	"github.com/hemilabs/x/tss-lib/v3/ecdsa/signing"
	"github.com/hemilabs/x/tss-lib/v3/tss"
)

// TestTSS_E2E_P2WPKH runs the complete flow: real distributed ECDSA
// keygen, derive a P2WPKH address from the group pubkey, build an
// unsigned tx spending the funding output, compute BIP-143 sighash,
// drive a real distributed signing ceremony, inject via
// TransactionApplyECDSA, and validate through the btcd script
// engine.  A failure anywhere along this path is a real-world
// failure — there is no mock layer hiding anything.
func TestTSS_E2E_P2WPKH(t *testing.T) {
	const (
		parties   = 3
		threshold = 1 // tss-lib uses t = minSigners-1 for t-of-n
	)
	ctx := context.Background()

	// Phase 1: Paillier pre-parameters — slow, do out of band.
	t.Logf("generating Paillier pre-params for %d parties...", parties)
	t0 := time.Now()
	preParams := make([]keygen.LocalPreParams, parties)
	for i := range preParams {
		pp, err := keygen.GeneratePreParams(5 * time.Minute)
		if err != nil {
			t.Fatalf("GeneratePreParams[%d]: %v", i, err)
		}
		preParams[i] = *pp
	}
	preParamsDur := time.Since(t0)
	t.Logf("pre-params ready in %.1fs", preParamsDur.Seconds())

	// Phase 2: Party IDs and peer context.
	pIDs := tss.GenerateTestPartyIDs(parties)
	peerCtx := tss.NewPeerContext(pIDs)

	// Phase 3: Run the distributed keygen ceremony.
	t.Log("running 4-round distributed keygen...")
	tKeygen := time.Now()
	saves := runKeygen(t, ctx, parties, threshold, pIDs, peerCtx, preParams)
	keygenDur := time.Since(tKeygen)
	tssPub := saves[0].ECDSAPub
	t.Logf("keygen complete in %.1fs", keygenDur.Seconds())

	// Convert the tss-lib public key to a btcec public key via the
	// SEC1 compressed encoding — this forces btcec.ParsePubKey's
	// on-curve validation, so a malformed point from a buggy or
	// malicious TSS coordinator would be rejected here rather than
	// silently accepted by direct field-element construction.
	pubKey := tssPubKeyToBtcec(t, tssPub)
	pubX, pubY := tssPub.X(), tssPub.Y()

	// Phase 4: Derive a P2WPKH address from the group public key.
	// This is the address that external observers (regular bitcoin
	// nodes, indexers, explorers) would see as the owner of the
	// UTXO.  It is controlled by the TSS committee, not any single
	// party.
	params := &chaincfg.TestNet3Params
	pkHash := btcutil.Hash160(pubKey.SerializeCompressed())
	addr, err := btcutil.NewAddressWitnessPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	pkScript, err := txscript.PayToAddrScript(addr)
	if err != nil {
		t.Fatal(err)
	}

	// Phase 5: Build an unsigned transaction that spends a funding
	// UTXO locked to the TSS address.
	fundHash := chainhash.DoubleHashH([]byte("tss-e2e-funding"))
	fundOutpoint := wire.NewOutPoint(&fundHash, 0)
	const inputAmount int64 = 100_000
	const outputAmount int64 = 99_000 // 1000 sat fee

	tx := wire.NewMsgTx(2)
	tx.AddTxIn(wire.NewTxIn(fundOutpoint, nil, nil))
	// Send to an arbitrary P2WPKH recipient — the recipient does
	// not matter for the signing exercise.
	recipPriv, err := btcec.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	recipHash := btcutil.Hash160(recipPriv.PubKey().SerializeCompressed())
	recipAddr, err := btcutil.NewAddressWitnessPubKeyHash(recipHash, params)
	if err != nil {
		t.Fatal(err)
	}
	recipScript, err := txscript.PayToAddrScript(recipAddr)
	if err != nil {
		t.Fatal(err)
	}
	tx.AddTxOut(wire.NewTxOut(outputAmount, recipScript))

	// Serialise the unsigned tx for the evidence block.
	var unsignedBuf bytes.Buffer
	if err := tx.Serialize(&unsignedBuf); err != nil {
		t.Fatalf("serialize unsigned tx: %v", err)
	}
	unsignedHex := hex.EncodeToString(unsignedBuf.Bytes())

	// Phase 6: Compute the BIP-143 sighash for the TSS-controlled
	// input.  This is the message the committee will sign.
	prev := wire.NewTxOut(inputAmount, pkScript)
	prevOuts := PrevOuts{
		fundOutpoint.String(): prev,
	}
	fetcher := prevOutsFetcher(prevOuts)
	sigHashes := txscript.NewTxSigHashes(tx, fetcher)
	// For P2WPKH the sighash is computed against the P2PKH-equivalent
	// script per BIP-143.
	p2pkhScript, err := txscript.PayToAddrScript(
		mustP2PKH(t, params, pkHash),
	)
	if err != nil {
		t.Fatal(err)
	}
	sighash, err := txscript.CalcWitnessSigHash(p2pkhScript, sigHashes,
		txscript.SigHashAll, tx, 0, inputAmount)
	if err != nil {
		t.Fatalf("CalcWitnessSigHash: %v", err)
	}

	// Phase 7: Run the distributed signing ceremony on the sighash.
	// This is NINE rounds plus finalize of real MPC — the private
	// key exists only as shares across the committee.
	t.Log("running 9-round distributed signing...")
	tSign := time.Now()
	tssSig := runSigning(t, ctx, parties, threshold, pIDs, peerCtx, saves,
		new(big.Int).SetBytes(sighash))
	signDur := time.Since(tSign)
	t.Logf("committee produced signature in %.2fs", signDur.Seconds())

	// Phase 8: Assemble DER via the helper this branch ships.
	sigDER, err := ECDSASigFromRS(tssSig.R, tssSig.S)
	if err != nil {
		t.Fatalf("ECDSASigFromRS: %v", err)
	}

	// Phase 9: Pre-broadcast verify gate.
	if err := VerifyECDSA(sighash, sigDER, pubKey); err != nil {
		t.Fatalf("VerifyECDSA rejected committee signature: %v", err)
	}

	// Phase 10: Inject into the transaction.
	if err := TransactionApplyECDSA(params, tx, 0, prev, pubKey,
		sigDER, txscript.SigHashAll); err != nil {
		t.Fatalf("TransactionApplyECDSA: %v", err)
	}

	// Serialise the signed tx for the evidence block.  Anyone can
	// paste this hex into `bitcoin-cli decoderawtransaction` or an
	// online parser to inspect the witness stack and confirm the
	// signature is well-formed.
	var signedBuf bytes.Buffer
	if err := tx.Serialize(&signedBuf); err != nil {
		t.Fatalf("serialize signed tx: %v", err)
	}
	signedHex := hex.EncodeToString(signedBuf.Bytes())
	txid := tx.TxHash().String()

	// Phase 11: Consensus validation.  The btcd script engine is
	// the same validator bitcoin nodes run.  Passing here means
	// the network would accept this spend.
	vm, err := txscript.NewEngine(pkScript, tx, 0,
		txscript.StandardVerifyFlags, nil, sigHashes,
		inputAmount, fetcher)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	if err := vm.Execute(); err != nil {
		t.Fatalf("script engine rejected TSS-signed tx: %v", err)
	}

	// -------------------------------------------------------------
	// EVIDENCE BLOCK — self-contained, paste-able.  Values are
	// single-run; R, S, sighash, the group key, and derived
	// address change on every invocation because TSS keygen and
	// signing both use fresh randomness.
	// -------------------------------------------------------------
	ev := evidence{
		parties:     parties,
		threshold:   threshold,
		pIDs:        pIDs,
		pubX:        pubX,
		pubY:        pubY,
		pubKey:      pubKey,
		addr:        addr,
		fundOutpt:   fundOutpoint,
		inputAmt:    inputAmount,
		outputAmt:   outputAmount,
		recipAddr:   recipAddr,
		unsignedHex: unsignedHex,
		sighash:     sighash,
		tssR:        tssSig.R,
		tssS:        tssSig.S,
		sigDER:      sigDER,
		tx:          tx,
		txid:        txid,
		signedHex:   signedHex,
		pkScript:    pkScript,
		recipScript: recipScript,
		p2pkhScript: p2pkhScript,
		pkHash:      pkHash,
		preParams:   preParamsDur,
		keygen:      keygenDur,
		sign:        signDur,
	}
	printEvidence(ev)
}

// mustP2PKH returns a P2PKH address for pkHash on the given params.
// It's a small convenience so the caller above doesn't have to
// handle the error inline and clutter the flow.
func mustP2PKH(t *testing.T, params *chaincfg.Params, pkHash []byte) btcutil.Address {
	t.Helper()
	a, err := btcutil.NewAddressPubKeyHash(pkHash, params)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// tssPubKeyToBtcec converts a tss-lib *crypto.ECPoint into a btcec
// *PublicKey via the SEC1 compressed encoding.  The roundtrip
// through ParsePubKey enforces on-curve validation: a TSS
// implementation bug (or a malicious coordinator supplying a
// forged point) would fail here rather than silently construct a
// garbage pubkey via direct field-element assembly.  Downstream
// wallets integrating TSS should follow this pattern — never
// btcec.NewPublicKey(fx, fy) without a curve check.
func tssPubKeyToBtcec(t *testing.T, pub *crypto.ECPoint) *btcec.PublicKey {
	t.Helper()

	// SEC1 compressed: 0x02 if Y is even, 0x03 if Y is odd, then X
	// padded to 32 bytes.
	xBytes := pub.X().Bytes()
	if len(xBytes) > 32 {
		t.Fatalf("TSS pubkey X is %d bytes, expected <= 32", len(xBytes))
	}
	compressed := make([]byte, 33)
	if pub.Y().Bit(0) == 0 {
		compressed[0] = 0x02
	} else {
		compressed[0] = 0x03
	}
	copy(compressed[1+32-len(xBytes):], xBytes)

	pk, err := btcec.ParsePubKey(compressed)
	if err != nil {
		t.Fatalf("ParsePubKey rejected TSS-produced pubkey: %v", err)
	}
	return pk
}

// evidence collects every value the final paste-able block needs.
// Grouping them in a struct keeps the test body flat and lets
// printEvidence be pure output with no logic.
type evidence struct {
	parties   int
	threshold int
	pIDs      tss.SortedPartyIDs

	pubX, pubY *big.Int
	pubKey     *btcec.PublicKey
	addr       btcutil.Address

	fundOutpt   *wire.OutPoint
	inputAmt    int64
	outputAmt   int64
	recipAddr   btcutil.Address
	unsignedHex string

	sighash []byte
	tssR    []byte
	tssS    []byte
	sigDER  []byte

	tx        *wire.MsgTx
	txid      string
	signedHex string

	pkScript    []byte
	recipScript []byte
	p2pkhScript []byte
	pkHash      []byte

	preParams time.Duration
	keygen    time.Duration
	sign      time.Duration
}

// printEvidence renders the paste-able evidence block.  Output-only:
// it performs no assertions or computation beyond hex/decimal
// formatting and script disassembly.  All assertions are in the
// calling test (Phases 9 and 11).
func printEvidence(e evidence) {
	fmt.Println()
	fmt.Println("============================================================")
	fmt.Println("  TSS 2-of-3 BITCOIN SPEND — EVIDENCE BLOCK")
	fmt.Println("============================================================")
	fmt.Println()
	fmt.Println("Committee:")
	for i := 0; i < e.parties; i++ {
		fmt.Printf("  party %d: id=%s  moniker=%s  index=%d\n",
			i, e.pIDs[i].Id, e.pIDs[i].Moniker, e.pIDs[i].Index)
	}
	fmt.Printf("  threshold:  %d (i.e. %d-of-%d)\n",
		e.threshold, e.threshold+1, e.parties)
	fmt.Println("  curve:      secp256k1")
	fmt.Println()
	fmt.Println("Group public key (no single party ever held the priv):")
	fmt.Printf("  X (hex):       %064x\n", e.pubX)
	fmt.Printf("  Y (hex):       %064x\n", e.pubY)
	fmt.Printf("  compressed:    %x\n", e.pubKey.SerializeCompressed())
	fmt.Println()
	fmt.Println("Address (testnet P2WPKH controlled by the committee):")
	fmt.Printf("  %s\n", e.addr.EncodeAddress())
	fmt.Println()
	fmt.Println("Unsigned transaction (testnet):")
	fmt.Printf("  funding outpoint: %s:%d\n",
		e.fundOutpt.Hash.String(), e.fundOutpt.Index)
	fmt.Printf("  funding amount:   %d sat\n", e.inputAmt)
	fmt.Printf("  output amount:    %d sat\n", e.outputAmt)
	fmt.Printf("  fee:              %d sat\n", e.inputAmt-e.outputAmt)
	fmt.Printf("  recipient:        %s\n", e.recipAddr.EncodeAddress())
	fmt.Printf("  raw hex:          %s\n", e.unsignedHex)
	fmt.Println()
	fmt.Println("BIP-143 sighash (the 32 bytes the committee actually signed):")
	fmt.Printf("  %x\n", e.sighash)
	fmt.Println()
	fmt.Println("TSS signature (raw scalars from the 9-round ceremony):")
	fmt.Printf("  R (hex):        %064x\n", new(big.Int).SetBytes(e.tssR))
	fmt.Printf("  S (hex):        %064x\n", new(big.Int).SetBytes(e.tssS))
	fmt.Printf("  DER (%d bytes): %x\n", len(e.sigDER), e.sigDER)
	fmt.Println()
	fmt.Println("Signed transaction (wire format, ready for broadcast):")
	fmt.Printf("  txid:         %s\n", e.txid)
	fmt.Printf("  witness:      [sig||sighashByte=%dB, pubkey=%dB]\n",
		len(e.tx.TxIn[0].Witness[0]), len(e.tx.TxIn[0].Witness[1]))
	fmt.Printf("  raw hex:\n    %s\n", e.signedHex)
	fmt.Println()
	printScripts(e)
	fmt.Println()
	fmt.Println("Independent verification:")
	fmt.Println("  # decode on any machine with Bitcoin Core installed:")
	fmt.Printf("  bitcoin-cli -testnet decoderawtransaction %s\n", e.signedHex)
	fmt.Println("  # note: the funding outpoint is a test-fabricated hash,")
	fmt.Println("  # so the tx will NOT confirm on real testnet -- but the")
	fmt.Println("  # SIGNATURE in the witness is cryptographically valid")
	fmt.Println("  # against the sighash above and the committee's pubkey.")
	fmt.Println()
	fmt.Println("Validation verdicts:")
	fmt.Println("  VerifyECDSA (pre-broadcast gate): ACCEPTED")
	fmt.Println("  btcd script engine (consensus):   ACCEPTED")
	fmt.Println()
	fmt.Println("Timing:")
	fmt.Printf("  Paillier pre-params:   %.2fs\n", e.preParams.Seconds())
	fmt.Printf("  4-round keygen:        %.2fs\n", e.keygen.Seconds())
	fmt.Printf("  9-round signing:       %.2fs\n", e.sign.Seconds())
	fmt.Println()
	fmt.Println("Library versions:")
	fmt.Println("  tss-lib:               github.com/hemilabs/x/tss-lib/v3")
	fmt.Println("  bitcoin primitives:    github.com/btcsuite/btcd")
	fmt.Println("  wallet under test:     github.com/hemilabs/heminetwork/v2/bitcoin/wallet")
	fmt.Println("============================================================")
}

// printScripts renders the script-disassembly and stack-execution
// trace sub-block of the evidence output.  Disassembly errors are
// rendered inline as "<disasm error: ...>" so the block remains
// paste-able even if one decode fails.
func printScripts(e evidence) {
	disasm := func(s []byte) string {
		out, err := txscript.DisasmString(s)
		if err != nil {
			return fmt.Sprintf("<disasm error: %v>", err)
		}
		return out
	}

	witSig := e.tx.TxIn[0].Witness[0]
	witPub := e.tx.TxIn[0].Witness[1]
	witSigDER := witSig[:len(witSig)-1]
	witSigHashType := witSig[len(witSig)-1]

	fmt.Println("Script disassembly:")
	fmt.Println("  Input 0 — prev pkScript (P2WPKH, v0 witness program):")
	fmt.Printf("    hex:    %x\n", e.pkScript)
	fmt.Printf("    asm:    %s\n", disasm(e.pkScript))
	fmt.Println()
	fmt.Println("  Input 0 — scriptSig (empty; all data lives in the witness):")
	fmt.Println("    hex:    (empty)")
	fmt.Println("    asm:    (empty)")
	fmt.Println()
	fmt.Println("  Input 0 — witness stack (bottom -> top of stack):")
	fmt.Printf("    [0] sig+hashType (%d bytes)\n", len(witSig))
	fmt.Printf("        DER sig:  %x\n", witSigDER)
	fmt.Printf("        hashType: 0x%02x (SigHashAll)\n", witSigHashType)
	fmt.Printf("    [1] pubkey       (%d bytes)\n", len(witPub))
	fmt.Printf("        compressed: %x\n", witPub)
	fmt.Println()
	fmt.Println("  Input 0 — BIP-143 script code (what the sighash commits to):")
	fmt.Printf("    hex:    %x\n", e.p2pkhScript)
	fmt.Printf("    asm:    %s\n", disasm(e.p2pkhScript))
	fmt.Println()
	fmt.Println("  Execution trace (witness replayed against script code):")
	fmt.Println("    initial stack: [ sig+hashType, pubkey ]")
	fmt.Println("    OP_DUP            -> [ sig+hashType, pubkey, pubkey ]")
	fmt.Println("    OP_HASH160        -> [ sig+hashType, pubkey, HASH160(pubkey) ]")
	fmt.Printf("    PUSH <pkHash>     -> [ sig+hashType, pubkey, HASH160(pubkey), %x ]\n", e.pkHash)
	fmt.Println("    OP_EQUALVERIFY    -> [ sig+hashType, pubkey ]    (pops top two, asserts equal)")
	fmt.Println("    OP_CHECKSIG       -> [ TRUE ]                    (ECDSA verify against sighash)")
	fmt.Println()
	fmt.Println("  Output 0 — recipient P2WPKH pkScript:")
	fmt.Printf("    hex:    %x\n", e.recipScript)
	fmt.Printf("    asm:    %s\n", disasm(e.recipScript))
}

// ---------------------------------------------------------------------
// tss-lib v3 ceremony drivers — copied verbatim from the canonical
// ecdsa/example_test.go in the module and trimmed to the keygen+sign
// slice this test needs.  See that file for the reshare flow.
// ---------------------------------------------------------------------

// runKeygen drives the 4-round tss-lib v3 ECDSA distributed keygen
// in-process, passing round messages between the n parties directly
// (no network transport).  Round 1 produces VSS commitments and the
// Paillier pubkey.  Round 2 produces per-peer P2P shares and the
// Schnorr/DLN proofs.  Round 3 verifies decommitments and shares.
// Round 4 verifies the Paillier/mod/fac proofs and saves the
// LocalPartySaveData for each party.  Returns the saves slice so the
// caller can drive signing with any threshold+1 subset of them.
func runKeygen(
	t *testing.T, ctx context.Context,
	n, threshold int,
	pIDs tss.SortedPartyIDs, peerCtx *tss.PeerContext,
	preParams []keygen.LocalPreParams,
) []keygen.LocalPartySaveData {
	t.Helper()

	states := make([]*keygen.KeygenState, n)
	r1 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), peerCtx, pIDs[i], n, threshold)
		st, out, err := keygen.Round1(ctx, params, preParams[i])
		if err != nil {
			t.Fatalf("keygen.Round1[%d]: %v", i, err)
		}
		states[i] = st
		r1[i] = out.Messages[0]
	}

	r2p2p := make([][]*tss.Message, n)
	r2bcast := make([]*tss.Message, n)
	for i := range r2p2p {
		r2p2p[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		out, err := keygen.Round2(ctx, states[i], r1)
		if err != nil {
			t.Fatalf("keygen.Round2[%d]: %v", i, err)
		}
		for _, msg := range out.Messages {
			if msg.To == nil {
				r2bcast[i] = msg
			} else {
				for _, to := range msg.To {
					r2p2p[to.Index][i] = msg
				}
			}
		}
		r2p2p[i][i] = states[i].ExportR2P2PSelf()
		if r2bcast[i] == nil {
			r2bcast[i] = states[i].ExportR2BcastSelf()
		}
	}

	r3 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := keygen.Round3(ctx, states[i], r2p2p[i], r2bcast)
		if err != nil {
			t.Fatalf("keygen.Round3[%d]: %v", i, err)
		}
		r3[i] = out.Messages[0]
	}

	saves := make([]keygen.LocalPartySaveData, n)
	for i := 0; i < n; i++ {
		out, err := keygen.Round4(ctx, states[i], r3)
		if err != nil {
			t.Fatalf("keygen.Round4[%d]: %v", i, err)
		}
		saves[i] = *out.Save
	}
	return saves
}

// runSigning drives the 9-round tss-lib v3 ECDSA distributed signing
// plus the finalise step, producing a real threshold signature over
// the message m.  Rounds 1-3 handle the MtA dance (P2P + broadcast);
// rounds 4-9 are all broadcast, assembling R and the partial
// signature shares; Finalise sums the partial sigs and returns the
// combined (R, S) pair in a *signing.SignatureData.  Any party
// failing its round is fatal — this test expects an honest
// committee.
func runSigning(
	t *testing.T, ctx context.Context,
	n, threshold int,
	pIDs tss.SortedPartyIDs, peerCtx *tss.PeerContext,
	saves []keygen.LocalPartySaveData, m *big.Int,
) *signing.SignatureData {
	t.Helper()

	states := make([]*signing.SigningState, n)
	r1p2p := make([][]*tss.Message, n)
	r1bcast := make([]*tss.Message, n)
	for i := range r1p2p {
		r1p2p[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		params := tss.NewParameters(tss.S256(), peerCtx, pIDs[i], n, threshold)
		st, out, err := signing.SignRound1(params, saves[i], m, nil, 0)
		if err != nil {
			t.Fatalf("SignRound1[%d]: %v", i, err)
		}
		states[i] = st
		for _, msg := range out.Messages {
			if msg.To == nil {
				r1bcast[i] = msg
			} else {
				for _, to := range msg.To {
					r1p2p[to.Index][i] = msg
				}
			}
		}
	}

	r2p2p := make([][]*tss.Message, n)
	for i := range r2p2p {
		r2p2p[i] = make([]*tss.Message, n)
	}
	for i := 0; i < n; i++ {
		out, err := signing.SignRound2(ctx, states[i], r1p2p[i], r1bcast)
		if err != nil {
			t.Fatalf("SignRound2[%d]: %v", i, err)
		}
		for _, msg := range out.Messages {
			for _, to := range msg.To {
				r2p2p[to.Index][i] = msg
			}
		}
	}

	r3 := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := signing.SignRound3(ctx, states[i], r2p2p[i])
		if err != nil {
			t.Fatalf("SignRound3[%d]: %v", i, err)
		}
		r3[i] = out.Messages[0]
	}

	r4 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound4(states[i], r3)
	}, "Round4")
	r5 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound5(states[i], r4)
	}, "Round5")
	r6 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound6(states[i])
	}, "Round6")
	r7 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound7(states[i], r5, r6)
	}, "Round7")
	r8 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound8(states[i])
	}, "Round8")
	r9 := bcastRound(t, n, states, func(i int) (*signing.SignRoundOutput, error) {
		return signing.SignRound9(states[i], r7, r8)
	}, "Round9")

	out, err := signing.SignFinalize(states[0], r9)
	if err != nil {
		t.Fatalf("SignFinalize: %v", err)
	}
	return out.Signature
}

// bcastRound runs a single all-broadcast signing round across all n
// parties and collects each party's output into a slice addressable
// by sender index.  Rounds 4-9 of tss-lib v3 ECDSA signing have no
// P2P component; this helper factors their identical invocation
// shape into one place so runSigning reads as a sequence of round
// names rather than six copies of the same loop.
func bcastRound(
	t *testing.T, n int,
	states []*signing.SigningState,
	fn func(int) (*signing.SignRoundOutput, error),
	name string,
) []*tss.Message {
	t.Helper()
	msgs := make([]*tss.Message, n)
	for i := 0; i < n; i++ {
		out, err := fn(i)
		if err != nil {
			t.Fatalf("%s[%d]: %v", name, i, err)
		}
		msgs[i] = out.Messages[0]
	}
	return msgs
}
