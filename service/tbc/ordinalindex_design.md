# Ordinal Indexer Performance Design

This file documents the performance decisions in the ordinal indexer
and the measured results that justified each one. Every optimization
was profiled before and after — no speculative changes.

## Architecture

The indexer is split into two phases:

  1. Index time (windBlock): scan every block's witness data for
     inscription envelopes and record the reveals. This writes
     ownership ('o'), inscription ('i'), predecessor ('p') and the
     'O' point-Get acceleration entries. No sat numbers are computed
     here.
  2. Query time: sat numbers and transfer tracking are derived on
     demand by walking backward through the spending chain to a
     coinbase, using raw blocks and the tx index (see
     computeInscribedSat / computeSatRanges).

Index-time sat computation was removed: the backward walk costs 12+
seconds per inscription at depth, which is far too slow for bulk
indexing. Deferring it keeps windBlock proportional to the witness
data actually present in a block. The query-time walk is opt-in per
request (the `IncludeSat` flag, default false); the two endpoints that
can only be answered by walking sat ranges (SatRangesByOutpoint,
InscriptionsBySat) are disabled until sat ranges are stored per
outpoint.

Mainnet has ~880K blocks, ~1B transactions, ~70M inscriptions. The
optimizations below keep the index-time scan and its DB access off the
O(n²) paths that a naive implementation hits on heavy blocks.

## Optimization 1: 'O' Acceleration Prefetch

Problem: detection needs the committed 'O' entry for every input in a
block. Issuing one serial point-Get per input bottlenecks on I/O
latency on heavy blocks.

Solution: prefetch every input's 'O' entry in one 128-wide parallel
pass before the sequential detection loop runs. The DB is immutable
during a wind — all writes buffer in the OrdinalCache until commit —
so these point-Gets are order-independent pure reads and detection
semantics are unchanged.

## Optimization 2: Parent-Value Warming Pipeline

Problem: reveals reference their parent (commit) transaction. Batch
reveals — N inputs funded by one commit transaction — would race N
duplicate parent lookups through the fan-out.

Solution: a producer/consumer pipeline warms parent values for the
whole block, deduplicating parent transactions before fetching so each
commit transaction is fetched once, and the block's witnesses are
parsed once. The wind log line reports iov_warm (unique parents
warmed) alongside iov_calls. `TBC_ORDINAL_WARM` (default true) toggles
the warm phase while its long-term value is evaluated.

## Optimization 3: Ranged Parent-Transaction Reads

Problem: fetching a parent transaction pulled the whole multi-MB block
from the raw block store just to read one transaction's bytes.

Solution: read only the transaction's bytes via a ranged read
(TxLoc-guided pread). Legacy pre-v6 index entries, which have no
TxLoc, keep the whole-block fallback.

## Optimization 4: Byte-Bounded Chunked Flushes

Problem: an inscription-dense range accumulated an unbounded write
batch, causing unbounded memory growth and quadratic batch-buffer
copying.

Solution: flushes are bounded by bytes (~1 GiB of cached index
payload), not only by entry count, and each flush's records are
written to LevelDB in bounded chunks inside one atomic transaction
(see ordinalBatchChunkSize). Nothing is visible until commit, so the
chunking stays atomic. BlockOrdinalUpdate and OrdinalPopulatorUpdate
share this pattern.

## Optimization 5: 'O' Acceleration Verification (Debug)

Problem: a corrupt 'O' entry would silently return the wrong parent
value and corrupt detection.

Solution: `TBC_ORDINAL_VERIFY_BIGO` (default false) cross-checks every
consumed 'O' value against the tx index. A lookup failure surfaces as
an error; a genuine value mismatch means a corrupt ordinal index and
panics with reindex instructions. It re-does the lookup the fast path
exists to skip, so it is slow — enable it only when soaking changes to
the 'O' write paths.

## Diagnostic: Read-Only Wind Replay

The tbcd database layer supports read-only opens (`Config.SetReadOnly`):
no recovery writes, no background compaction, writes error. The
env-gated `TestWindReplay` diagnostic replays chosen blocks through the
full ordinal wind against a read-only database — all the work, nothing
inserted — for controlled measurement of slow blocks.
