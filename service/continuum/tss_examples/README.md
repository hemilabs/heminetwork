# TSS Examples

This directory contains illustrative tests demonstrating the use of tss-lib for:

- Distributed key generation (keygen)
- Threshold signing
- Key resharing between committees

These tests serve as reference implementations using raw tss-lib APIs.

## Running Tests

```bash
# Run all tests (except scale test)
go test ./service/continuum/tss_examples/... -v

# Run scale test (100 parties, slow)
TSS_SCALE=1 go test ./service/continuum/tss_examples/... -v -run TestScaleToHundred -timeout 30m
```

## Tests

| Test | Description |
|------|-------------|
| `TestKeygen` | Basic 3-of-3 keygen, sign, verify |
| `TestSignSubset` | 2-of-3 threshold signing with different party subsets |
| `TestReshareDisjoint` | Reshare to completely new committee |
| `TestReshareWithOverlap` | Reshare with continuing parties (key rotation) |
| `TestReshareGrowCommittee` | Grow from 2-of-3 to 3-of-4 |
| `TestDeadPartyRecovery` | Party goes offline, reshare without them |
| `TestFullLifecycle` | Complete journey: keygen → sign → reshare → sign → reshare → sign |
| `TestScaleToHundred` | 55-of-100 keygen and signing (requires `TSS_SCALE=1`) |

## Key Concepts

### PartyID Structure

tss-lib's `PartyID` has three fields:

```go
type PartyID struct {
    id      string    // Persistent identity (use public key)
    moniker string    // Human-readable name
    key     *big.Int  // Routing key (must be unique per ceremony)
    Index   int       // Position in sorted committee
}
```

### The Overlapping Committee Problem

tss-lib cannot handle parties that appear in both old and new committees during resharing:

```
Old Committee: {Alice, Bob, Charlie}
New Committee: {Bob, Charlie, Dan}  ← Bob and Charlie in both
```

**Root Cause**: The library uses `key` to determine committee membership:

```go
func (rgParams *ReSharingParameters) IsOldCommittee() bool {
    for _, Pj := range rgParams.parties.IDs() {
        if partyID.KeyInt().Cmp(Pj.KeyInt()) == 0 {  // Key comparison!
            return true
        }
    }
    return false
}
```

When Bob is in both committees with the same key:
1. Bob's NEW instance also returns `IsOldCommittee() = true`
2. Bob's NEW instance sends Round1 messages (only OLD should)
3. Protocol state becomes corrupted

### The Solution: Key Rotation

Use `id` for persistent identity and rotate `key` each ceremony:

```
Old Committee                    New Committee
┌─────────┐                      ┌─────────┐
│   Bob   │──── Round1 ────────▶│   Bob   │
│ id: PKb │                      │ id: PKb │ ← SAME ID
│ key: B  │                      │ key: B' │ ← NEW KEY!
└─────────┘                      └─────────┘
```

The library sees disjoint committees `{A,B,C}` vs `{B',C',D}`, but the application maintains identity continuity.

```go
// Before reshare
bob := NewPartyIdentity("02bob_pubkey", "Bob")
oldPids := partiesToPids([]*PartyIdentity{alice, bob, charlie})

// Rotate key for continuing party
bob.RotateKey()

// Now bob appears as "new" party to tss-lib
newPids := partiesToPids([]*PartyIdentity{bob, charlie, dan})
```

### Dead Party Recovery

With threshold `t`, you need `t+1` parties to sign or reshare. If one party dies:

1. **Can still sign** if remaining parties >= `t+1`
2. **Can reshare** to evict dead party and add replacement
3. Only live parties from old committee participate in reshare

```go
// Original: 2-of-3 {Alice, Bob, Charlie}
// Alice dies, Bob and Charlie are still alive (2 parties)
// 2 >= threshold+1, so we can reshare!

liveOldPids := partiesToPids([]*PartyIdentity{bob, charlie})  // Only live parties
bob.RotateKey()
charlie.RotateKey()
newPids := partiesToPids([]*PartyIdentity{bob, charlie, dan})

// Reshare using only live parties' keys
newKeys, _ := doReshare(t, curve, oldThreshold, newThreshold, liveOldPids, newPids, liveOldKeys)
```

### PreParams

tss-lib keygen requires Paillier primes which are slow to generate (~30s each). For the scale test, these are pre-computed and cached in `preparams.json`.

First run of `TestScaleToHundred` generates 100 preparams (parallel, ~5-10 min with multiple cores). Subsequent runs load from cache.

## Cryptographic Notes

### Why Resharing Preserves the Public Key

The resharing protocol uses the actual secret shares, not the routing keys:

```go
// From round_1_old_step_1.go:
xi := round.input.Xi           // The actual secret share
wi := PrepareForSigning(xi)    // Lagrange interpolation
shares := vss.Create(wi)       // New VSS sharing
```

Verification at round 4 confirms correctness:
```go
if !Vc[0].Equals(round.save.ECDSAPub) {
    return error("V_0 != y")  // Public key must match!
}
```

Changing the routing key doesn't affect:
- Secret share values
- Lagrange interpolation
- VSS reconstruction  
- Final ECDSA public key

### Threshold Semantics

In tss-lib, `threshold` means:
- Need `threshold + 1` parties to sign
- A 2-of-3 scheme has `threshold = 1`
- A 55-of-100 scheme has `threshold = 54`
