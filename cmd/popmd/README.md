# Hemi PoP Miner (`popmd`)

`popmd` is a **lightweight PoP (Proof-of-Proof) miner**, which wraps the `popm` service.

![Depiction of L1 Profile](images/popminer.svg)

`popmd` will periodically receive information about the current state of the hemi network (a keystone), constructs 
a bitcoin transaction embedding the aforementioned keystone, and broadcasts these transactions - resulting in 
rewards, once validated.

## System Requirements

`popmd` is a **lightweight daemon** and most systems should be able to run popmd over long periods of time without requiring significant resources, as it off-loads most heavy functionality to other daemons it connects to.

Furthermore, a **GPU is neither required nor helpful** to the functioning of `popmd`.

## Running `popmd`

In order to run `popmd`, you may either use _docker_, download a pre-built binary, or build the tool from source.

**NOTE:** URLs for both a [BTC Gozer](../../bitcoin/wallet/README.md) with indexed keystones (such as [`tbcd`]((../tbcd/README.md).)), as well as an [HVM-aware op-geth](https://github.com/hemilabs/op-geth) instance, are required in order to use `popmd`.

### Downloading Release Binaries (Recommended)

Pre-built binaries are available on the [Releases Page](https://github.com/hemilabs/heminetwork/releases).

After extracting the archive that matches your system, start `popmd` by running:

```shell
/path/to/popmd
```

### Running Local Docker Image

The `heminetwork` repository provides docker images that can be used to run `popmd` using `Docker`.

#### Prerequisites

- `docker` available in your cli

####  Execution

To build and run the provided docker images, run the following on your cli:

```shell
cd heminetwork

# build the image using the popmd dockerfile
docker build -t popmd:latest -f ./docker/popmd/Dockerfile .

# run the built image using the correct environment variables
docker run \
-e POPM_BITCOIN_SECRET=<YOUR_BITCOIN_SECRET> \
-e POPM_OPGETH_URL=<YOUR_OPGETH_URL> \
-e POPM_BITCOIN_URL=<YOUR_BITCOIN_URL> \
popmd:latest
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

`popmd` is **designed to be run both locally and in cloud environments**, as such it uses environment variables for runtime settings.

To see a full list of runtime settings, execute `popmd` with the **`--help`** flag:

```shell
./bin/popmd --h
# Hemi Proof-of-Proof Miner v1.1.0-dev+d22973902
# Usage:
#         help (this help)
# Environment:
#         POPM_BITCOIN_NETWORK   : bitcoin chain to connect to (ex. "mainnet", "testnet3") (default: mainnet)
#         POPM_BITCOIN_SECRET    : bitcoin secret (mnemonic, seed, xpriv) (required) 
#         POPM_BITCOIN_URL       : the bitcoin url to connect to; it's either a tbc or blockstream url 
#         POPM_LOG_LEVEL         : loglevel for various packages; INFO, DEBUG and TRACE (default: popmd=INFO;popm=INFO)
#         POPM_OPGETH_URL        : URL for opgeth (default: localhost:9999)
#         POPM_PPROF_ADDRESS     : address and port popm pprof listens on (open <address>/debug/pprof to see available profiles) 
#         POPM_PROMETHEUS_ADDRESS: address and port popm prometheus listens on 
#         POPM_REMINE_THRESHOLD  : the number of L2 Keystones behind the latest seen that we are willing to remine, this is handy for re-orgs (default: 0)
#         POPM_STATIC_FEE        : static fee amount in sats/byte; overrides fee estimation if greater than 0 (default: 0)
```

Namely, ensure the following variables are properly set: 

- `POPM_BITCOIN_NETWORK`: This determines what bitcoin network `popmd` should connect to. This defaults to `mainnet`, but `testnet3` and `localnet` are also available for test environments. 

- `POPM_BITCOIN_SECRET`: A funded bitcoin address is necessary in order to sign, broadcast, and get rewarded for the  transactions constructed by `popmd`. 

- *`POPM_BITCOIN_URL`: URL to the bitcoin source of truth used in order to transmit data to and from the bitcoin network. [Read more on how to run your own `tbcd` instance here](../tbcd/README.md).

- `POPM_OPGETH_URL`: URL to a public HVM-aware opgeth instance, used to retrieve keystones from the hemi network.

\* **NOTE**: `TBC` is the only functional bitcoin source of truth _currently_ available.

## FAQ

### How much does it cost to run `popmd`?

L2 Blocks are generated rougly every 12 seconds, and a keystone is generated every 25 blocks. As such:

- 12 * 25 = `300 seconds (5 minutes) between keystones`
- 86400 / 300 = `288 keystones per day`

Considering that each transaction created by the PoP Miner has a size of `284 vB` and presuming an average bitcoin transaction fee of `3 sats/vB`: 

- 284 * 3 = `852 sats per PoP Tx`
- 852 * 288 = `245376 sats` or `0.00245376 BTC` per day

The value of BTC can fluctuate heavily, but presuming a cost of `110 000 USD / BTC`, it would cost `~270 USD` per day to run `popmd` on mainnet.

_**DISCLAIMER:**_ These are example values ONLY. The presented values are not guaranteed, and may not be up-to-date. Different versions of the network's protocols and daemons may incur higher costs and fees. You should get up-to-date values yourself to determine if PoP mining makes sense for you.

### How many HEMI tokens will I be awarded for mining?

Each keystone has a total payout of `100 HEMI`, which is divided by the number of PoP Txs that mine said keystone. As such, you can expect a "return" of `28800 HEMI` per day, divided by the number of PoP miners (assuming a consistent number of PoP Miners).
