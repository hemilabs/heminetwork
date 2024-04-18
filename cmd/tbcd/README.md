# tbcd

## Hemi Tiny Bitcoin Daemon

`tbcd` is a very minimal bitcoin block downloader and indexer daemon. It wraps the `tbc` service which is meant for embedding in other applications that require access to bitcoin data (blocks and txes). The daemon is primarily used as a network RPC endpoint.

The `tbc` downloads all bitcoin blocks and generates various indexes and thus requires a sufficiently large machine. Count on needing >8G of RAM, 4CPUs and using NVME disk.

As of April 18 2024, `testnet3` uses ~40G and `mainnet` >300G (XXX add exact number here)

## Building

tbcd is build with the heminetwork makefile,  To build standalone (requires `go 1.22+`), type:

``` sh
cd heminetwork/cmd/tbcd
go build
```

## Environment

On some systems you may need to increase the number of open files, memory and the maximum stack size.  If you run into open file or OOM errors, in the shell you are going to run tbcd, run:

```sh
ulimit -n 8192
ulimit -s 16384
ulimit -m unlimited
ulimit -d unlimited
```

You can confirm these settings wiht:

```sh
ulimit -a
```
## Runtime settings

`tbcd` is meant to be run in the cloud and as such it only uses environment variables for runtime settings. They can be either be exported or included on the evocation of the binary.

For a full list of runtime settings:

``` sh
./bin/tbcd --help
Hemi Tiny Bitcoin Daemon: v0.1.0-pre+3eb1bab15
Usage:
        help (this help)
Environment:
        TBC_ADDRESS           : address port to listen on (default: localhost:8082)
        TBC_AUTO_INDEX        : enable auto utxo and tx indexes (default: true)
        TBC_BLOCK_SANITY      : enable/disable block sanity checks before inserting (default: false)
        TBC_LEVELDB_HOME      : data directory for leveldb (default: ~/.tbcd)
        TBC_LOG_LEVEL         : loglevel for various packages; INFO, DEBUG and TRACE (default: tbcd=INFO;tbc=INFO;level=INFO)
        TBC_MAX_CACHED_TXS    : maximum cached utxos and/or txs during indexing (default: 1000000)
        TBC_NETWORK           : bitcoin network; mainnet or testnet3 (default: testnet3)
        TBC_PROMETHEUS_ADDRESS: address and port tbcd prometheus listens on 

```

Run with:

``` sh
./bin/tbcd
```

## RPC endpoints

When `TBC_ADDRESS` is specified the daemon listen on the provided URI. The RPC is websockets based that uses a standard request/response driven model.

The RPC endpoints are:
``` Go
XXX point to api or write it in human langiage here?
```

`./cmd/hemictl` is the reference implementation of the websocket RPC.

### License

This project is licensed under the [MIT License](../../LICENSE).

