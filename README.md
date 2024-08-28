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
  * [▶️ Running bssd](#-running-bssd)
    * [🏁 Prerequisites](#-prerequisites-3)
  * [▶️ Running the localnet network](#-running-the-localnet-network)
    * [🏁 Prerequisites](#-prerequisites-4)
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
| [**Bitcoin Secure Sequencer (bssd)**](https://github.com/hemilabs/heminetwork/blob/main/service/bss)  | Acts as a gateway to the Bitcoin Finality Governor (BFG), managing the consensus mechanisms of the Hemi Network. |

## 🌐 Binaries

- [**bfgd (Bitcoin Finality Governor Daemon)**](cmd/bfgd): Manages connections and data transfers between the Hemi
  Network and the Bitcoin blockchain, ensuring finality.
- [**bssd (Bitcoin Secure Sequencer Daemon)**](cmd/bssd): Coordinates and sequences blockchain operations, serving as a
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
- [Go v1.23+](https://go.dev/dl/)

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
./bin/bssd --help
```

## ▶️ Running popmd

### 🏁 Prerequisites

- A funded BTC private key. This can be a testnet address if configured for test environments.
- A BFG URL to establish a connection.

Once properly configured and running, `popmd` will start mining L2 Keystones by adding them to Bitcoin blocks that make
it into the chain.

### CLI

Set up and start popmd using:

```shell
./bin/popmd
```

### Web

There is also a web interface that can be used to run a PoP miner.
Build and run the web interface with:

> [!NOTE]
> The web PoP Miner is currently a proof-of-concept.

```shell
cd ./web
make
go run ./integrationtest
```

## ▶️ Running bfgd

### 🏁 Prerequisites

- A **PostgreSQL database**, bfgd expects the sql scripts in `./database/bfgd/scripts/` to be run to set up your schema.
- A **connection to an ElectrumX node** on the proper Bitcoin network (testnet or mainnet).

## ▶️ Running bssd

### 🏁 Prerequisites

- Connect to a live [bfgd](#-running-bfgd) instance.

## ▶️ Running the localnet network

> [!WARNING]
> This is designed for use in testing and development environments only.

### 🏁 Prerequisites

- `docker`

### 📚 Tutorial

1. **Start the Network:** Launch the entire Hemi network locally using Docker, which will generate L2 Keystones and BTC
   Blocks at a **high rate**:

   ```shell
   docker compose -f ./e2e/docker-compose.yml up --build
   ```

> [!NOTE]
> The `--build` flag is optional and should only be used if you want to rebuild the binaries.

2. **Manage Caching:**
   This initial build may take some time, but subsequent builds should benefit from caching.

> [!NOTE]
> During rebuilding, `popmd`, `bssd`, and `bfgd` may force a rebuild due to the `COPY` command, which can break the 
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
