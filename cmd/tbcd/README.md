# Hemi Tiny Bitcoin Daemon

`tbcd` is a very minimal Bitcoin block downloader and indexer daemon. It wraps the `tbc` service which is meant for
embedding in other applications that require access to Bitcoin data (blocks and TXes). The daemon is primarily used as a
network RPC endpoint.

## System requirements

The `tbc` server downloads all Bitcoin blocks and generates various indexes and thus requires a large amount of
available disk space.

Running `tbc` will likely require at least:
 - 4 CPU cores
 - 8 GiB RAM
 - NVMe disk

As of April 18, 2024, `testnet3` uses ~40 GiB and `mainnet` >300 GiB of disk space. <!-- XXX: add exact number here -->

## Building

To build `tbcd`, you must have the following installed:
 - Go v1.22 or newer

### Makefile

To build `tbcd` with the heminetwork Makefile (requires `make` to be installed):

```shell
cd heminetwork

# Build (output binary will be written to bin/tbcd or bin/tbcd.exe)
make tbcd
```

### Standalone

To build `tbcd` without using the heminetwork Makefile:

```shell
cd heminetwork

# Build (output binary will be called tbcd or tbcd.exe)
go build ./cmd/tbcd/

# Install (output binary will be written to your GOBIN directory)
go install ./cmd/tbcd/
```

## Environment

On some systems, you may need to increase the limits for the number of open files, memory and the maximum stack size.

If you run into open file or OOM errors while running `tbcd`, run the following commands in the shell that you will
run `tbcd` in:

```shell
ulimit -n 8192
ulimit -s 16384
ulimit -m unlimited
ulimit -d unlimited
```

You can confirm these settings with:

```shell
ulimit -a
```

## Runtime settings

`tbcd` is designed to be run in cloud environments, as such it only uses environment variables for runtime settings.
They can be either be exported or included on the evocation of the binary.

To see a full list of runtime settings, execute `tbcd` with the `--help` flag:

```shell
/path/to/tbcd --help
# Hemi Tiny Bitcoin Daemon: v0.1.0-pre+3eb1bab15
# Usage:
#         help (this help)
# Environment:
#         TBC_ADDRESS           : address port to listen on (default: localhost:8082)
#         TBC_AUTO_INDEX        : enable auto utxo and tx indexes (default: true)
#         TBC_BLOCK_SANITY      : enable/disable block sanity checks before inserting (default: false)
#         TBC_LEVELDB_HOME      : data directory for leveldb (default: ~/.tbcd)
#         TBC_LOG_LEVEL         : loglevel for various packages; INFO, DEBUG and TRACE (default: tbcd=INFO;tbc=INFO;level=INFO)
#         TBC_MAX_CACHED_TXS    : maximum cached utxos and/or txs during indexing (default: 1000000)
#         TBC_NETWORK           : bitcoin network; mainnet or testnet3 (default: testnet3)
#         TBC_PROMETHEUS_ADDRESS: address and port tbcd prometheus listens on
```

You can start the `tbcd` server by running:

```shell
/path/to/tbcd
```

## RPC commands

*Last updated April 19th, 2024.*

When the `TBC_ADDRESS` environment variable is set, the `tbcd` daemon listens on the provided address.
The RPC protocol is WebSocket-based and uses a standard request/response model.

[`hemictl`](../../cmd/hemictl) is a reference implementation of an RPC client.

### Protocol

The RPC protocol is WebSocket-based and uses JSON-encoded request/responses.
The JSON data sent over WebSocket connections are called a "messages".

A message has the format:
```json
{
  "header": {
    "command": "command-name",
    "id": "request-id"
  },
  "payload": null
}
```

#### Header

The message header contains metadata:

 - `command` is the name of the command being called.
 - `id` is a string used to uniquely identify each request. Responses will have the same `id` as the request,
    making it possible to match requests to responses. Message IDs should be randomly generated.

#### Payload

The payload type depends on the command being called.

### Block Headers by Height

#### Raw data

| Type     | `command` value                               |
|----------|-----------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-raw-request`  |
| Response | `tbcapi-block-headers-by-height-raw-response` |

Example request message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-raw-request",
    "id": "68656d69"
  }
}
```

Example response message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2182000,
    "block_headers": [
      "0420002075089ac1ab1cab70cf6e6b774a86703a8d7127c0ebed1d3dfa2c00000000000086105509ec4a79457a400451290ad2a019fec4c76b47512623f1bb17a0ced76f38d82662bef4001b07d86700"
    ]
  }
}
```

#### Serialised 

| Type     | `command` value                           |
|----------|-------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-request`  |
| Response | `tbcapi-block-headers-by-height-response` |

Example request message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-request",
    "id": "68656d69"
  }
}
```

Example response message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2587400,
    "block_headers": [
      {
        "version": 536887296,
        "prev_hash": "000000000000002bbbbec8f126dc76a82109d898383bca5013a2386c8675ce34",
        "merkle_root": "b9d74efdafb5436330b47478b2df28251057da5a9bc11c5509410950253d4f0e",
        "timestamp": 1713461092,
        "bits": "192e17d5",
        "nonce": 3365605040
      }
    ]
  }
}
```

### License

This project is licensed under the [MIT License](../../LICENSE).
