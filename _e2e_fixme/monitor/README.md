# Localnet Monitor

The Localnet Monitor is a small program that simply polls localnet for values
that we want to test against.  

## Prerequisites

* Go 1.23+
* `docker` available in your cli

## Running

You can run the Localnet Monitor like so, this will read from localnet
and print a table that refreshes every 1 second.

Make sure you have localnet running:

from the root of the repo:
```
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
