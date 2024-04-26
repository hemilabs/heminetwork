# 🌐 The Hemi Network


***Last updated:** April 25th, 2024*

Hemi is an EVM-compatible L2 blockchain that combines the security of Bitcoin with the programmability of Ethereum.

<details>
  <summary style="color: #FF5F00; font-weight: 500; font-size: 1.5rem;"> Table of Contents</summary>

- [🌐 The Hemi Network](#-the-hemi-network)
  - [🔧 Services](#-services)
  - [📜 TL;DR:](#-tldr)
  - [⚡️ Getting Started](#️-getting-started)
    - [🏁 Prerequisites](#-prerequisites)
    - [📚 Tutorial](#-tutorial)
  - [📦 Downloading Binaries from Releases](#-downloading-binaries-from-releases)
- [🛠 Running the Services](#-running-the-services)
  - [▶️ Running popmd](#️-running-popmd)
    - [🏁 Prerequisites:](#-prerequisites-1)
    - [CLI:](#cli)
    - [Web:](#web)
  - [▶️ Running bfgd](#️-running-bfgd)
    - [🏁 Prerequisites:](#-prerequisites-2)
  - [▶️ Running bssd](#️-running-bssd)
    - [🏁 Prerequisites:](#-prerequisites-3)
  - [▶️ Running Network](#️-running-network)
    - [🏁 Prerequisites:](#-prerequisites-4)
    - [📚 Tutorial](#-tutorial-1)
  - [🧪 Running Full Network Tests](#-running-full-network-tests)
    - [🏁 Prerequisites:](#-prerequisites-5)
    - [📚 Tutorial](#-tutorial-2)
  - [📄 License](#-license)
</details>

---
## 🔧 Services

The Hemi Network comprises three key services, each serving a unique function within the network:

| Service | Description |
|---------|-------------|
| [**PoP Miner (popmd)**](https://github.com/hemilabs/heminetwork/blob/main/service/popm) | **Mines** L2 Keystones into Bitcoin blocks for Proof-of-Proof. |
| [**Bitcoin Finality Governor (bfgd)**](https://github.com/hemilabs/heminetwork/blob/main/service/bfg) | Acts as the gateway to the Bitcoin network. |
| [**Bitcoin Secure Sequencer (bssd)**](https://github.com/hemilabs/heminetwork/blob/main/service/bss) | Acts as a gateway to the Bitcoin Finality Governor (BFG) forked from Optimism, managing the consensus mechanisms of the Hemi Network.


---
## 📜 TL;DR:

- **extool**: A utility tool for extracting and processing data from various file formats, tailored for blockchain data analysis.
- **hemictl**: The command-line interface for controlling and managing all Hemi Network services.
- **keygen**: Generates and manages cryptographic keys used within the Hemi network, ensuring secure operations.
- **popmd (Proof of Proof Miner Daemon)**: Embeds L2 Keystones into Bitcoin blocks for proof-of-proof, integral to the network's security.
- **bfgd (Bitcoin Finality Governor Daemon)**: Manages connections and data transfers between the Hemi Network and the Bitcoin blockchain, ensuring finality.
- **bssd (Bitcoin Secure Sequencer Daemon)**: Coordinates and sequences blockchain operations, serving as a bridge to the Bitcoin Finality Governor.


---

## ⚡️ Getting Started

### 🏁 Prerequisites

- `git`
- `make`
- [Go v1.22+](https://go.dev/dl/)

---

### 📚 Tutorial


1. Clone the Repository:
   ```bash
   git clone https://github.com/hemilabs/heminetwork.git
   ```
2. Build:
   ```bash
   cd heminetwork
   make deps
   make
   ```

Binaries will be located in `<path-to-repo>/bin/`.

---

## 📦 Downloading Binaries from Releases

Pre-built binaries are available on the [Releases Page](https://github.com/hemilabs/heminetwork/releases).

---

# 🛠 Running the Services

For any service, you can view configuration options by running:

```bash
./bin/popmd --help
./bin/bfgd --help
./bin/bssd --help
```

## ▶️ Running popmd

### 🏁 Prerequisites:

- A funded BTC private key. This can be a testnet address if configured for test environments.
- A BFG URL to establish a connection.

Once properly configured and running, `popmd` will start **mining** L2 Keystones by adding them to Bitcoin blocks that make it into the chain.

### CLI:

Set up and start popmd using:

```bash
./bin/popmd
```

### Web:

Or initialize the web interface:

```bash
cd ./web
make
go run ./integrationtest
```


## ▶️ Running bfgd

### 🏁 Prerequisites:

- A **PostgreSQL database**, bfgd expects the sql scripts in `./database/bfgd/scripts/` to be run to set up your schema.
- A **connection to an ElectrumX node** on the proper Bitcoin network (testnet or mainnet).



## ▶️ Running bssd

### 🏁 Prerequisites:
-  Connect to a live [bfgd](#running-bfgd) instance.



## ▶️ Running Network

### 🏁 Prerequisites:

- `docker`
### 📚 Tutorial

1. **Start the Network:** Launch the entire Hemi network locally using Docker, which will generate L2 Keystones and BTC Blocks at a **high rate**:

   ```bash
   docker compose -f ./e2e/docker-compose.yml up --build
   ```

    > [!NOTE]
    > The `--build` flag is optional if you wish to rebuild your code.

1. **Manage Caching:**
   This initial build may take some time, but subsequent builds should benefit from caching.

     > [!NOTE]
    > During rebuilding, `popmd`, `bssd`, and `bfgd` may force a rebuild due to the `COPY` command, which can break the cache. If you need to deliberately break the cache for the op-stack, use the following arguments:

- For op-geth + optimism (op-node):
  ```bash
  docker compose -f ./e2e/docker-compose.yml build --build-arg OP_GETH_CACHE_BREAK="$(date)"
  ```

- For optimism cache break only:
  ```bash
  docker compose -f ./e2e/docker-compose.yml build --build-arg OPTIMISM_CACHE_BREAK="$(date)"
  ```

> [!IMPORTANT]
> Make sure you run the cleanup command to remove data and ensure a fresh start.
```bash
docker compose -f ./e2e/docker-compose.yml down -v --remove-orphans
```

**NOTE:** The `--remove-orphans` flag should remove other containers not defined
in the docker compose file. This is mainly here to help ensure you start with a
clean environment.  It can be omitted.

---

## 🧪 Running Full Network Tests

For a comprehensive local test of the Hemi network, this setup uses `bitcoind` in **regtest mode**:

### 🏁 Prerequisites:

- `docker`

### 📚 Tutorial

1. Run the Test Command:
   ```make
   networktest
   ```

---

## 📄 License

This project is licensed under the [MIT License](https://github.com/hemilabs/heminetwork/blob/main/LICENSE).
