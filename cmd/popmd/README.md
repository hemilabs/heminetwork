# Hemi PoP Miner (`popmd`)

`popmd` is the **lightweight PoP (Proof-of-Proof) miner**, which wraps the `popm` service.

![PoP Miner architecture](images/popminer.svg)

`popmd` will periodically receive information about the current state of the Hemi Network (a keystone), constructs
a Bitcoin transaction embedding the aforementioned keystone, and broadcasts these transactions - resulting in
rewards, once validated.

## System Requirements

The Hemi PoP Miner daemon (`popmd`) is **extremely lightweight**. It will run on almost any system, and only requires
minimal system resources.

By relying on connections to a Bitcoin node with indexed Hemi keystones (such as [`tbcd`](../tbcd/README.md)), and
a [hVM-aware op-geth node](https://github.com/hemilabs/op-geth), `popmd` requires very minimal CPU and RAM to operate,
as most heavy functionality is offloaded to these daemons.

> [!TIP]
> No additional hardware, such as a GPU, is required to run a PoP Miner.

## Running `popmd`

To run `popmd`, you can use Docker, download a pre-built binary, or build the binary from source.

> [!IMPORTANT]
> Running a PoP Miner requires URLs for the following services:
>  - [BTC Gozer](../../bitcoin/wallet/README.md) with indexed keystones, such as [`tbcd`](../tbcd/README.md).
>  - [hVM-aware op-geth node](https://github.com/hemilabs/op-geth)

### Downloading Release Binaries (Recommended)

Pre-built binaries for Linux, macOS, Windows and OpenBSD are available
via [GitHub Releases](https://github.com/hemilabs/heminetwork/releases).

After extracting the archive that matches your system, start `popmd` by running:

```shell
/path/to/popmd
```

### Docker images (Recommended)

Docker images for `popmd` are published to
both [GitHub Container Registry](https://github.com/orgs/hemilabs/packages/container/package/popmd)
and [Docker Hub](https://hub.docker.com/r/hemilabs/popmd).

If using Docker Hub, run the following command:

```shell
# Pull Hemi popmd image from Docker Hub
docker pull hemilabs/popmd

# Run the built image using the correct environment variables
BITCOIN_SECRET=<YOUR_BITCOIN_SECRET>
OPGETH_URL=<YOUR_OPGETH_URL>
BITCOIN_URL=<YOUR_BITCOIN_URL>

docker run \
  -e POPM_BITCOIN_SECRET=$BITCOIN_SECRET \
  -e POPM_OPGETH_URL=$OPGETH_URL \
  -e POPM_BITCOIN_URL=$BITCOIN_URL \
  hemilabs/popmd:latest
```

### Running Local Docker Image

The `heminetwork` repository provides docker files that can be used to run `popmd` using `Docker`.

#### Prerequisites

- `docker` available in your cli

#### Execution

To build and run the provided docker images, run the following on your cli:

```shell
cd heminetwork

# Build the image using the popmd Dockerfile
docker build -t popmd:dev -f ./docker/popmd/Dockerfile .

# Run the built image using the correct environment variables
BITCOIN_SECRET=<YOUR_BITCOIN_SECRET>
OPGETH_URL=<YOUR_OPGETH_URL>
BITCOIN_URL=<YOUR_BITCOIN_URL>

docker run \
  -e POPM_BITCOIN_SECRET=$BITCOIN_SECRET \
  -e POPM_OPGETH_URL=$OPGETH_URL \
  -e POPM_BITCOIN_URL=$BITCOIN_URL \
  popmd:dev
```

NOTE: check the [runtime settings](#runtime-settings) section for a full list of available environment variables.

### Building from Source

#### Prerequisites

- [Go v1.24+](https://go.dev/dl/)
- `make` (optional)

#### Option 1: Using Makefile

If you have `make` installed on your system, you may build the binary by running the following code snippet:

```shell
cd heminetwork

# Output binary will be written to bin/popmd or bin/popmd.exe
make popmd
```

#### Option 2: Standalone Build

If you prefer not to use the Makefile:

```shell
cd heminetwork

# Build the binary (output will be popmd or popmd.exe)
go build ./cmd/popmd/

# Install the binary (output will be in your GOBIN directory)
go install ./cmd/popmd/
```

<br>

Once the `popmd` binary is built using one of the previous two options, you can start it by running:

```shell
/path/to/popmd
```

## Runtime Settings

`popmd` is **designed to be run both locally and in cloud environments**, as such it uses environment variables for
runtime settings.

To see a full list of runtime settings, execute `popmd` with the **`--help`** flag:

```shell
./bin/popmd --h
# Hemi Proof-of-Proof Miner v2.0.0-dev+76217560a (popmd, go1.24.5 linux/amd64)
# Usage:
#         help (this help)
# Environment:
#         POPM_BITCOIN_NETWORK   : bitcoin chain to connect to (ex. "mainnet", "testnet3|testnet4") (default: mainnet)
#         POPM_BITCOIN_SECRET    : bitcoin secret (mnemonic, seed, xpriv) (required) 
#         POPM_BITCOIN_URL       : tbc bitcoin url to connect to (default: ws://localhost:8082/v1/ws)
#         POPM_LOG_LEVEL         : loglevel for various packages; INFO, DEBUG and TRACE (default: popmd=INFO;popm=INFO)
#         POPM_OPGETH_URL        : URL for opgeth (default: localhost:9999)
#         POPM_PPROF_ADDRESS     : address and port popm pprof listens on (open <address>/debug/pprof to see available profiles) 
#         POPM_PROMETHEUS_ADDRESS: address and port popm prometheus listens on 
#         POPM_REMINE_THRESHOLD  : the number of L2 Keystones behind the latest seen that we are willing to remine, this is handy for re-orgs (default: 0)
#         POPM_STATIC_FEE        : static fee amount in sats/byte; overrides fee estimation if greater than 0. Can be decimal (ex. 1.5 sats/byte) (default: 0)
```

Namely, ensure the following variables are properly set:

- `POPM_BITCOIN_NETWORK`: This determines what bitcoin network `popmd` should connect to. This defaults to `mainnet`,
  but `testnet3` and `localnet` are also available for test environments.

- `POPM_BITCOIN_SECRET`: A funded bitcoin address is necessary in order to sign, broadcast, and get rewarded for the
  transactions constructed by `popmd`.

- *`POPM_BITCOIN_URL`: URL to the bitcoin source of truth used in order to transmit data to and from the bitcoin
  network. [Read more on how to run your own `tbcd` instance here](../tbcd/README.md).

- `POPM_OPGETH_URL`: URL to a public HVM-aware opgeth instance, used to retrieve keystones from the Hemi network.

\* **NOTE**: `TBC` is the only functional bitcoin source of truth _currently_ available.

## FAQ

### How much does it cost to run `popmd`?

L2 Blocks are generated rougly every 12 seconds, and a keystone is generated every 25 blocks. As such:

- 12 * 25 = `300 seconds (5 minutes) between keystones`
- 86400 / 300 = `288 keystones per day`

Considering that each transaction created by the PoP Miner has a size of `284 vB` and presuming an average bitcoin
transaction fee of `3 sats/vB`:

- 284 * 3 = `852 sats per PoP Tx`
- 852 * 288 = `245376 sats` or `0.00245376 BTC` per day

The value of BTC can fluctuate heavily, but presuming a cost of `110 000 USD / BTC`, it would cost `~270 USD` per day to
run `popmd` on mainnet.

_**DISCLAIMER:**_ These are example values ONLY. The presented values are not guaranteed, and may not be up-to-date.
Different versions of the network's protocols and daemons may incur higher costs and fees. You should get up-to-date
values yourself to determine if PoP mining makes sense for you.

### How many HEMI tokens will I be awarded for mining?

Each keystone has a total payout of `100 HEMI`, which is divided by the number of PoP Txs that mine said keystone. As
such, you can expect rewards of `28800 HEMI` per day, divided by the number of PoP miners (assuming a consistent
number of PoP Miners).
