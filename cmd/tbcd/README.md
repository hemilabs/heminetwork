# 🌐 Hemi Tiny Bitcoin Daemon (`tbcd`)

`tbcd` is a **minimal Bitcoin block downloader** and **indexer daemon**. It is designed to wrap the `tbc` service, which
provides Bitcoin data **(blocks and transactions)** for other applications. Primarily, **it functions as a network RPC
endpoint.**

## 🖥️ System Requirements

`tbcd` requires significant system resources due to its functionality:

| Requirement   | Specification    |
|---------------|------------------|
| **CPU Cores** | 4 minimum        |
| **RAM**       | 8 GiB minimum    |
| **Disk**      | NVMe recommended |

**As of April 18, 2024:**

- **`testnet3`** requires approximately 40 GiB of disk space.
- **`mainnet`** requires over 300 GiB of disk space. <!-- XXX: add exact number here -->

---

## 🛠️ Building `tbcd` From Source

### 🏁 Prerequisites

Ensure Go v1.23 or newer is installed on your system.

### Using Makefile

To build `tbcd` using the provided Makefile

#### 🏁 Prerequisites

Ensure `make` is installed on your system.

#### Build `tbcd` binary

```shell
cd heminetwork

# Output binary will be written to bin/tbcd or bin/tbcd.exe
make tbcd
```

### Standalone Build

If you prefer not to use the Makefile:

```shell
cd heminetwork

# Build the binary (output will be tbcd or tbcd.exe)
go build ./cmd/tbcd/

# Install the binary (output will be in your GOBIN directory)
go install ./cmd/tbcd/
```

---

## 🌐 Environment Settings

`tbcd` **checks system limits at startup on supported platforms** to ensure that they are set to values that will allow
TBC to run without failing.

> [!WARNING]
> If you see an error similar to the following, you will need to adjust the limits for the number of open files, memory
> and the maximum stack size on your system to run TBC.

```
ulimit: memory: limit too low got X, want X
```

Changing limits is OS-specific, but can usually be done using the `ulimit` command.

## ⚙️ Runtime Settings

`tbcd` is **designed to be run in cloud environments**, as such it uses environment variables for runtime settings.

To see a full list of runtime settings, execute `tbcd` with the **`--help`** flag:

```shell
./bin/tbcd --help
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

Start the server by running:

```shell
/path/to/tbcd
```

## 👉 RPC Commands

The `tbcd` daemon runs an RPC server that listens on the address provided by the `TBC_ADDRESS` environment variable.

The RPC protocol is **WebSocket-based** and **uses a standard request/response model.**

[Read more about the RPC protocol and available commands](../../api/tbcapi/README.md).
