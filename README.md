# Hemi Network

<details>
  <summary>Table of Contents</summary>

* [What is the Hemi Network?](#what-is-the-hemi-network)
  * [Services](#services)
  * [License](#license)
* [Getting Started](#getting-started)
  * [Building from Source](#building-from-source)
  * [Downloading Binaries from Releases](#downloading-binaries-from-releases)
  * [Running](#running)
  * [Running popmd](#running-popmd)
    * [CLI](#cli)
    * [Web](#web)
  * [Running bfgd](#running-bfgd)
  * [Running bssd](#running-bssd)

</details>

## What is the Hemi Network?

Hemi is an EVM compatible L2 blockchain that brings Bitcoin security and Ethereum programability together.

### Services

Hemi Network consists of 3 services:

* [PoP Miner (popmd)](service/popm): "mines" L2 Keystones into BTC blocks for proof-of-proof
* [Bitcoin Finality Governor (bfgd)](service/bfg): Hemi's gateway to the BTC network.
* [Bitcoin Secure Sequencer (bssd)](service/bss): Optimism's gateway to BFG, manages Hemi Network's consensus

### License

This project is licensed under the [MIT License](LICENSE).

## Getting Started

### Building from Source

To build, you must have the following installed:

* `git`
* `make`
* `go 1.21+`

First, clone the repository:

```shell
git clone https://github.com/hemilabs/heminetwork.git
```

Then build:

```shell
cd heminetwork
make deps
make
```

This will put built binaries in `<path-to-repo>/bin/`

### Downloading Binaries from Releases

You can find releases on the [Releases Page](https://github.com/hemilabs/heminetwork/releases)

### Running

To view options for any of the services, you may run the following

```shell
./bin/popmd --help
```

```shell
./bin/bfgd --help
```

```shell
./bin/bssd --help
```

### Running popmd

popmd has a few crucial requirements to run:

* a BTC private key that is funded, this can be a testnet address if you configure popmd as such
* a BFG URL to connect to

if configured correctly and running, then popmd will start "mining" L2 Keystones by adding them to btc blocks that make
it into the chain

#### CLI

```shell
./bin/popmd
```

#### Web

```shell
cd ./web
make
go run ./integrationtest
```

### Running bfgd

bfgd has a few crucial requirements to run:

* a postgres database, bfgd expects the sql scripts in `./database/bfgd/scripts/` to be run to set up your schema
* an electrumx node connected to the proper bitcoin network (testnet vs mainnet, etc.)

### Running bssd

bssd has a few crucial requirements to run:

* a bfgd instance running to connect to

### Running Network

Prerequisites: `docker`

To run the full network locally, you can run the following.  Note that this will create
L2Keystones and BTC Blocks at a high rate.  

note: the `--build` flag is optional if you want to rebuild your code

```
docker compose -f ./e2e/docker-compose.yml up --build
```

This will take a while upon first build, but following builds should be cached.  
When rebuilding, popmd, bssd, and bfgd will rebuild (due to `COPY` command breaking
 the cache).  However if you want to break the cache for the op-stack, use the following args:

For op-geth + optimism (op-node)
```
docker compose -f ./e2e/docker-compose.yml build --build-arg OP_GETH_CACHE_BREAK="$(date)"
```

For optimism cache break only:
```
docker compose -f ./e2e/docker-compose.yml build --build-arg OPTIMISM_CACHE_BREAK="$(date)"
```

**IMPORTANT:** make sure you run the following to tear down, this will remove
data and give you a fresh start

```
docker compose -f ./e2e/docker-compose.yml down -v --remove-orphans
```



### Running the full network tests

This runs a test with an entirely local heminet, it uses bitcoind in regtest
mode for the bitcoin chain

Prerequisites: `docker`

```
make networktest
```
