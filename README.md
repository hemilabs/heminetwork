# ⚡️ The Hemi Network

Hemi is an EVM-compatible L2 blockchain that combines the security of Bitcoin with the programmability of Ethereum.

<details>
  <summary>Table of Contents</summary>

<!-- TOC -->
* [⚡️ The Hemi Network](#-the-hemi-network)
  * [🔧 Services](#-services)
  * [🌐 Binaries](#-binaries)
* [⚡️ Getting Started](#-getting-started)
  * [📦 Downloading Release Binaries](#-downloading-release-binaries)
  * [🏗 Building from Source](#-building-from-source)
    * [🏁 Prerequisites](#-prerequisites)
    * [Building with Makefile](#building-with-makefile)
* [🛠 Running the Services](#-running-the-services)
  * [▶️ Running popmd](#-running-popmd)
    * [🏁 Prerequisites](#-prerequisites-1)
    * [CLI](#cli)
    * [Web](#web)
  * [▶️ Running bfgd](#-running-bfgd)
    * [🏁 Prerequisites](#-prerequisites-2)
    * [Running your own Bitcoin Finality Governor (bfgd)](#running-your-own-bitcoin-finality-governor-bfgd)
  * [▶️ Running the Hemi stack](#-running-the-hemi-stack)
  * [▶️ Running the localnet network](#-running-the-localnet-network)
    * [🏁 Prerequisites](#-prerequisites-3)
    * [📚 Tutorial](#-tutorial)
  * [📄 License](#-license)
<!-- TOC -->
</details>

---

## 🔧 Services

The Hemi Network consists of three key services, each serving a unique and important function within the network:

| Service                                                                                               | Description                                                                                                      |
|-------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------|
| [**PoP Miner (popmd)**](https://github.com/hemilabs/heminetwork/blob/main/service/popm)               | **Mines** L2 Keystones into Bitcoin blocks for Proof-of-Proof.                                                   |
| [**Bitcoin Finality Governor (bfgd)**](https://github.com/hemilabs/heminetwork/blob/main/service/bfg) | Acts as the gateway to the Bitcoin network.                                                                      |

## 🌐 Binaries

- [**bfgd (Bitcoin Finality Governor Daemon)**](cmd/bfgd): Manages connections and data transfers between the Hemi
  Network and the Bitcoin blockchain, ensuring finality.
  bridge to the Bitcoin Finality Governor.
- [**extool**](cmd/extool): A utility tool for extracting and processing data from various file formats, tailored for
  blockchain data analysis.
- [**hemictl**](cmd/hemictl): The command-line interface for controlling and managing all Hemi Network services.
- [**keygen**](cmd/keygen): Generates and manages cryptographic keys used within the Hemi network, ensuring secure
  operations.
- [**popmd (Proof-of-Proof Miner Daemon)**](cmd/popmd): Embeds L2 Keystones into Bitcoin blocks for proof-of-proof,
  integral to the network's security.
- [**tbcd (Tiny Bitcoin Daemon)**](cmd/tbcd): A minimal Bitcoin block downloader and indexer daemon.

---

# ⚡️ Getting Started

## 📦 Downloading Release Binaries

Pre-built binaries are available on the [Releases Page](https://github.com/hemilabs/heminetwork/releases).

## 🏗 Building from Source

### 🏁 Prerequisites

- `git`
- `make`
- [Go v1.24+](https://go.dev/dl/)

### Building with Makefile

1. Clone the `heminetwork` repository:
   ```shell
   git clone https://github.com/hemilabs/heminetwork.git
   cd heminetwork
   ```

2. Setup and build binaries:
   ```shell
   make deps    # Download and install dependencies
   make install # Build binaries
   ```

Output binaries will be written to the `bin/` directory.

---

# 🛠 Running the Services

For any service, you can view configuration options by running:

```shell
./bin/popmd --help
./bin/bfgd --help
```

## ▶️ Running popmd

The easiest way to run `popmd` is by using our provided docker images. A list of `popmd` docker images for each major release is available [here](https://hub.docker.com/r/hemilabs/popmd).

Refer to the [dedicated `popmd` README](/cmd/popmd/README.md) for an overview of other installation options and further details.

### Prerequisites

- `docker` available in your cli

### Execution

To build and run the ***latest*** provided docker image, run the following on your cli:

```shell
docker pull hemilabs/popmd

# run the image using the correct environment variables
docker run \
-e POPM_BITCOIN_SECRET=<YOUR_BITCOIN_SECRET> \
-e POPM_OPGETH_URL=<YOUR_OPGETH_URL> \
-e POPM_BITCOIN_URL=<YOUR_BITCOIN_URL> \
hemilabs/popmd:latest
```

## ▶️ Running bfgd

### 🏁 Prerequisites

- A **connection to a Bitcoin network source of truth.

### Running your own Bitcoin Finality Governor (bfgd)

If you'd like to run your own `bfgd` and don't want to rely on Hemi Labs (or any third party) for verifying the finality
of mined keystones, you may run `bfgd` and connect it to a _trusted_ `op-geth` instance, as well as an l2 keystone (l2
keystones represent l2 state and are what are mined in PoP transactions) aware `gozer`, such as TBC. In this case, your
`bfgd` instance will communicate with `op-geth` to verify the _validity_ of l2 keystones, and confirm their _canonicity_
and _finality status_, based on their presence in the bitcoin chain, using the `gozer`.

BFG is very light-weight, thus only requiring `bfgd` in order to be run (provided you have a valid `op-geth` and `gozer`
instance to connect it to).

When running BFG, you'll want the following env variables set:

* `BFG_BITCOIN_URL`: the `TBC`'s websocket url that you will connect to

*More details coming soon!*

## ▶️ Running the Hemi stack

To run the full Hemi stack (non-sequencing), please see [NODE_RUNNING](localnode/NODE_RUNNING.md).

## ▶️ Running the localnet network

> [!WARNING]
> This is designed for use in testing and development environments only.

### 🏁 Prerequisites

- `docker`

### 📚 Tutorial

1. **Start the Network:** Launch the entire Hemi network locally using Docker, which will generate L2 Keystones and BTC
   Blocks at a **high rate**:

   ```shell
   docker compose -f ./e2e/docker-compose.yml build

   # set the hvm phase 0 timestamp slightly in the future, but ensure that all op-geths have the same
   HVM_PHASE0_TIMESTAMP=$(date --date='+120 seconds' +%s) docker compose -f ./e2e/docker-compose.yml up
   ```

> [!NOTE]
> The `--build` flag is optional and should only be used if you want to rebuild the binaries.

2. **Manage Caching:**
   This initial build may take some time, but subsequent builds should benefit from caching.

> [!NOTE]
> During rebuilding, `popmd` and `bfgd` may force a rebuild due to the `COPY` command, which can break the
> cache. If you need to deliberately break the cache for the op-stack, use the following arguments:

- For op-geth + optimism (op-node):
  ```shell
  docker compose -f ./e2e/docker-compose.yml build --build-arg OP_GETH_CACHE_BREAK="$(date)"
  ```

- For optimism cache break only:
  ```shell
  docker compose -f ./e2e/docker-compose.yml build --build-arg OPTIMISM_CACHE_BREAK="$(date)"
  ```

> [!IMPORTANT]
> Make sure you run the cleanup command to remove data and ensure a fresh start.

```shell
docker compose -f ./e2e/docker-compose.yml down -v --remove-orphans
```

**NOTE:** The `--remove-orphans` flag should remove other containers not defined
in the docker compose file. This is mainly here to help ensure you start with a
clean environment. It can be omitted.

---

## 📄 License

This project is licensed under the [MIT License](https://github.com/hemilabs/heminetwork/blob/main/LICENSE).
