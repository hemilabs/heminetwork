
# Ordinal Indexer Performance Design

This file documents the performance decisions in the ordinal indexer
and the measured results that justified each one. Every optimization
was profiled before and after — no speculative changes.

## Problem Statement

The ordinal indexer must track sat-level ownership across every
Bitcoin transaction. For each block:
  - Collect sat ranges for all inputs (cache or DB lookup)
  - FIFO-redistribute sats from inputs to outputs
  - Track inscribed sat movement (which output holds each inscribed sat)
  - Detect new inscriptions in witness data
  - Collect fee sats (input - output) for coinbase assignment

Mainnet has ~880K blocks, ~1B transactions, ~70M inscriptions.
Naive implementations hit O(n²) or worse on heavy blocks.

## Optimization 1: Parallel fixupCacheHook

Problem: satRanges() hits LevelDB on cache miss. Sequential reads
bottleneck on I/O latency.

Solution: Pre-fetch all input outpoint sat ranges before windBlock
runs, using 128 concurrent goroutines. Mirrors the proven
fixupCacheChannel pattern from the utxo indexer.

Pattern: semaphore channel (pre-filled with tokens), goroutines
acquire/release tokens, write results to shared map under mutex.

Measured: fixup phase is <1s per batch even on heavy blocks.

## Optimization 2: Block-Level Inscribed-Sat Pre-Scan

Problem: updateInscribedSats called OrdinalInscribedSatsInRange per
input range per transaction. On heavy blocks (500+ inputs), this
was 500 LevelDB range scans per block.

Solution: Collect the min/max sat range across ALL inputs in the
block, then do ONE DB scan for the merged range. Build a sorted
slice of inscribed sats for the entire block.

Measured: inscSat phase dropped from 5m51s to 965ms per batch
(363x speedup). DB scans reduced from O(inputs_per_block) to O(1).

## Optimization 3: Sorted Slice with Binary Search

Problem: The block-level inscribed-sat set had 96K+ entries on
testnet4's heavy blocks. updateInscribedSats iterated ALL entries
for EVERY transaction — O(96K × 1200 txs) = 115M iterations/block.

Solution: Store inscribed sats as a sorted []uint64 instead of
map[uint64]struct{}. For each tx, binary search to find only the
sats in [inputMin, inputMax). Then binary search the merged input
ranges to verify containment.

Measured: Blocks taking 1.7s dropped below 500ms. Dense zone that
took 30+ minutes now processes in 2-3 minutes. Zero blocks exceed
the 500ms threshold across a full testnet4 sync.

## Optimization 4: Min/Max Boundary Tracking

Problem: Every block's pre-scan queries the DB even when no
inscribed sats could possibly be in the input range.

Solution: Track global min/max inscribed sat numbers across batches.
Skip the DB scan entirely when the block's input range falls outside
[minInscribedSat, maxInscribedSat]. On mainnet, inscriptions started
at block 767430 (~sat 1.97 quadrillion). Pre-inscription blocks
(96% of the chain) skip the scan entirely.

## Optimization 5: OrdinalInscribedSatBounds

Problem: On restart, the indexer probed for existing inscribed sats
by calling OrdinalInscribedSatsInRange(0, MaxUint64). On mainnet
with 70M inscriptions, this loads 560MB into memory just to read
the first and last entry.

Solution: Added OrdinalInscribedSatBounds — two LevelDB iterator
seeks to get min and max inscribed sat numbers. O(1) time, O(1)
memory.

## Optimization 6: Fee Sat Conservation (Correctness)

Problem: CoinbaseSatRange only returned subsidy sats. Fee sats
(input - output per tx) vanished from the index. On mainnet where
fees exceed subsidy, this breaks sat conservation.

Solution: Two-pass windBlock — process non-coinbase txs first to
collect fee ranges, then process coinbase with subsidy + fees.
updateInscribedSats returns inscribed sats that became fees for
targeted coinbase 's' entry updates.

## Optimization 7: Zero-Value Output Tracking (Correctness)

Problem: Zero-value outputs (txOut.Value == 0) were skipped entirely.
When later spent, satRanges returned NotFoundError — the UTXO didn't
exist in the index despite being a valid on-chain output.

Solution: Record empty sat ranges for zero-value outputs. Every
on-chain UTXO exists in the index. Root cause traced to testnet4
block 32203 tx 73acc6ca...ff0e output 1 (value=0, v0_p2wpkh).

