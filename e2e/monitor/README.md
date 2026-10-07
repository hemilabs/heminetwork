# Localnet Monitor

The Localnet Monitor is a small program that simply polls localnet for values
that we want to test against.  

## Prerequisites

* Go 1.26+
* `docker` available in your cli

## Running

You can run the Localnet Monitor like so, this will read from localnet
and print a table that refreshes every 1 second.

Make sure you have localnet running:

from the root of the repo:
```
docker build -f ./e2e/optimism-stack.Dockerfile -t optimism-stack:latest .
docker compose -f ./e2e/docker-compose.yml down -v --remove-orphans
docker compose -f ./e2e/docker-compose.yml up
```

**NOTE:** The `--remove-orphans` flag should remove other containers not defined
in the docker compose file. This is mainly here to help ensure you start with a
clean environment.  It can be omitted.

from this directory:
```
$  go run ./... 
+--------------------------------+------------------------------------------------------------------------+
| refreshing every 1 seconds     |                                                                        |
| bitcoin block count            | 3007                                                                   |
| poptxs mined                   | 11                                                                     |
| first batcher publication hash | 0x2b86a72b48668b7a35dcab99166f9330c884c50d1b19847c3c0569a0d0806465,21  |
| last batcher publication hash  | 0x0d2e805f1180f81dfb3abe97b9edb1894c110a6be58a7cfcd14de65807613670,108 |
| batcher publication count      | 23                                                                     |
| pop miner $HEMI balance        | 4000000000000000000                                                    |
+--------------------------------+------------------------------------------------------------------------+
```

If you would like to print the results as json, you can give the json 
"snapshot" a delay via the env variable `HEMI_E2E_DUMP_JSON_AFTER_MS`, 
after these milliseconds, values will be read and dumped.

```
$ HEMI_E2E_DUMP_JSON_AFTER_MS=10000 go run ./... 
{"bitcoin_block_count":3011,"pop_tx_count":20,"first_batcher_publication_hash":"0x2b86a72b48668b7a35dcab99166f9330c884c50d1b19847c3c0569a0d0806465,21","last_batcher_publication_hash":"0x5ec52eeba46c300e98546de25991c1862ef8dd11c3ee3357ee2a717517e2fe8c,192","batcher_publication_count":34,"pop_miner_hemi_balance":"14000000000000000000"}
```

## L1 Glamsterdam migration tests

The localnet L1 starts before Glamsterdam and activates it while the Hemi
stack is running, so that the stack has to follow the L1 across the fork like
it has to on a live network.  The L2 does not activate Glamsterdam.

The tests in `glamsterdam_migration_test.go` check that the op-nodes keep
recognising L1 blocks (every L1 block they refer to is compared with what the
L1 itself has), that op-batcher and op-proposer keep getting their
transactions included under the L1 gas rules of the time, and that the L2 is
unchanged.  The `EIPNNNN_` functions in the `eipNNNN_test.go` files only show
that the L1 has Glamsterdam active.

The following environment variables are read by `docker compose up`:

* `L1_AMSTERDAM_OFFSET_SECONDS`: seconds after its genesis at which the L1
  activates Glamsterdam, 300 by default.  The op-nodes and the batcher that
  are started with the L1 must be running before that.  With 0 the L1 runs
  Glamsterdam from genesis and the migration tests fail.
* `BATCHER_DA_TYPE`: how op-batcher publishes batches, `calldata` (default)
  or `blobs`.  It must also be set when running the tests.  The L1 has no
  consensus layer node, `e2e/fakebeacon` keeps the blobs and serves them to
  the op-nodes.

The op-nodes do not trust the L1 RPC (no `--l1.trustrpc`) and are not told
when the L1 activates Glamsterdam, as in production.  Each of the four
accesses the L1 in a different way, see `e2e/docker-compose.yml`.

The L1 comes in two flavours, selected with `L1_CONSENSUS`:

* `dev` (default): geth simulates the consensus layer.  It never reorgs on
  its own, its `slotNumber` header field is always 0, and `safe` is its head.
* `prysm`: a Prysm beacon node and validator client drive geth over the
  engine API (`docker compose --profile prysm`, see `e2e/prysm`).  The L1
  has real slots and finality, a real Beacon API that the op-nodes fetch
  blobs from, and activates the Gloas fork on the consensus layer together
  with Amsterdam on the execution layer.  `L1_AMSTERDAM_OFFSET_SECONDS` must
  be a multiple of the 96 second epoch, and `OP_NODE_L1_BEACON`,
  `OP_NODE_FULL_SYNC_L1_BEACON` and `BATCHER_L1_RPC` point the op-nodes at
  the beacon node (`http://prysm-beacon:3500`) and the batcher at geth
  (`http://geth-l1:8545`).  The tests check that the slot numbers in the L1
  headers are the beacon chain's; the L1 reorg test is skipped.

Some tests restart services, reorg the L1 and look at all logs.  They are
skipped unless `HEMI_E2E_POST_RUN=true` is set and are run after everything
else:

```
go test -timeout 30m -v .
HEMI_E2E_POST_RUN=true go test -timeout 30m -v -run '^TestPostRun' .
```
