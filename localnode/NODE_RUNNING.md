# Running the Hemi stack

This document details how to run the full Hemi stack with P2P nodes and RPC access. *This does NOT run a batcher or sequencer.*

> [!TIP]
> This setup is only for users looking to run a full node on the Hemi network, and is not required to use a wallet (Metamask, Rabby, etc.) to interact with dApps on Hemi or run a PoP Miner.


<details>
  <summary>Table of Contents</summary>

<!-- TOC -->
* [Running the Hemi Stack](#running-the-hemi-stack)
  * [Prerequisites](#prerequisites)
    * [System Requirements](#system-requirements)
      * [CPU, RAM, and Disk](#cpu-ram-and-disk)
      * [ulimits](#ulimits)
  * [Setup and Installation](#setup-and-installation)
    * [Checking Prerequisites](#checking-prerequisites)
    * [Cloning the heminetwork Repository](#cloning-the-heminetwork-repository)
    * [Hemi Components](#hemi-components)
    * [⚠️ Important Note on Security](#important-note-on-security)
  * [Running With Docker Compose](#running-with-docker-compose)
  * [Accessing the Nodes](#accessing-the-nodes)
  * [Peer-to-Peer (P2P)](#peer-to-peer-p2p)
  * [Mainnet](#mainnet)
  * [Running Without Docker](#running-without-docker)
<!-- TOC -->
</details>


## Prerequisites

This guide assumes you are running [Docker](https://docs.docker.com/get-started/get-docker/)
and [Docker Compose](https://docs.docker.com/compose/) on Ubuntu 24.04 (the latest LTS). Running on other setups is
possible, but may not be fully supported.

Docker images for each Hemi Network component is published to [Docker Hub](https://hub.docker.com/u/hemilabs).

### System Requirements

#### CPU, RAM, and Disk

You can choose to run several different configurations (implemented as [Docker Profiles](#docker-profiles)), each with their own requirements:
| Profile    | CPU Cores | Memory | Disk (NVMe Recommended) |
| ---------- | --------- | ------ | ----------------------- |
| full       | 8         | 40GB   | 6TB                     |
| hemi       | 2         | 16GB   | 3TB                     |
| hemi-min   | 2         | 12GB   | 2TB                     |
| L1         | 6         | 24GB   | 3TB                     |

Do note that over time disk space requirements will grow. The above values represent the current requirements (as of Q1 2025) with a buffer that should be sufficient for at least an additional year.

#### ulimits

Certain components of the network require a very large number of open files. The startup will attempt to set the `ulimits` properly, however it will exit quickly with an error if your system does not allow high enough ulimits.

## Setup and Installation

### Checking Prerequisites

Check that your system matches the [prerequisites](#prerequisites) for the profile you want to run. Make sure that the following are installed and setup:

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/)

### Cloning The heminetwork Repository

To get started, clone this repository:

```sh
# Clone with HTTP
git clone https://github.com/hemilabs/heminetwork.git
cd heminetwork

# OR Clone with SSH
git clone ssh://git@github.com/hemilabs/heminetwork.git
cd heminetwork
```

### Hemi Components

> [!TIP]
> You do not have to run all of the daemons, depending on your use-case. See the [Docker Profiles](#docker-profiles) section to determine which configuration is appropriate for your use-case(s) and trust tolerance. 

The following daemons comprise the Hemi stack. They are all run under Docker Compose:

1. bitcoind
2. electrs
3. geth
4. prysm
5. op-geth
6. op-node
7. bssd
8. bfgd
9. postgres (used by bfgd)

![Depiction of Hemi Network Stack](images/hemi-network-components-v2.svg)


### Docker Profiles

There are four different docker profiles you can choose from, depending on your use case.

> [!TIP]
> This docker profile setting is independent from the [Node Synchronization Type](#node-synchronization-type) which determines how the `op-geth` instance performs it's one-time **initial** sync regardless of the stack setup. Any of the profiles that include an op-geth instance can be configured with either of the initial synchronization types.

The following table provides details on which components are run locally as part of each profile:

| Profile  | [HEMI]<br> op-geth | [HEMI]<br> op-node | [HEMI]<br> bssd    | [HEMI]<br> bfgd    | [ETH]<br> prysm    | [ETH]<br> geth     | [BTC]<br> electrs  | [BTC]<br> bitcoind |
| -------- | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ | ------------------ |
| full     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: |
| hemi     | :white_check_mark: | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                | :x:                | :white_check_mark: | :x:                |
| hemi-min | :white_check_mark: | :white_check_mark: | :white_check_mark: | :x:                | :x:                | :x:                | :x:                | :x:                |
| L1       | :x:                | :x:                | :x:                | :x:                | :white_check_mark: | :white_check_mark: | :x:                | :white_check_mark: |


> [!TIP]
> The "L1" profile does not run any Hemi-specific infrastructure; it is provided to allow users to run the L1 components separately from the Hemi components.


Different node configurations support different Hemi use cases:

| Profile  | Standard RPC<br>(Wallets, most dApps, etc.) | Consensus RPC<br>(State Roots, Sync Status, etc.) | Extended Consensus RPC<br>(BTC Finality) | Fully Local PoP Mining | Trustless ETH Derivation | Trustless BTC Indexing |
| -------- | ------------------------------------------- | ------------------------------------------------- | ---------------------------------------- | ---------------------- | ------------------------ | ---------------------- |
| full     | :white_check_mark:                          | :white_check_mark:                                | :white_check_mark:                       | :white_check_mark:     | :white_check_mark:       | :white_check_mark:     |
| hemi     | :white_check_mark:                          | :white_check_mark:                                | :white_check_mark:                       | :white_check_mark:     | :x:                      | :x:                    |
| hemi-min | :white_check_mark:                          | :white_check_mark:                                | :x:                                      | :x:                    | :x:                      | :x:                    |
| L1       | :x:                                         | :x:                                               | :x:                                      | :x:                    | :white_check_mark: <br>(for paired hemi/hemi-min stack) | :white_check_mark: <br> (for paired hemi/hemi-min stack) |


#### Profile: full
This profile includes everything: full Bitcoin and Ethereum (L1) nodes, as well as a full Hemi node.

It supports all ways of interacting with the Hemi network (Standard RPC + Extended Consensus RPC, Fully Local PoP Mining).

With this mode, your Hemi node is synchronized entirely from ETH DA data trustlessly synchronized from the Ethereum network, Bitcoin finality information is calculated based on BTC data trustlessly synchronized from the Bitcoin network, and PoP miners connecting to the BFG endpoint are interfacing with the Bitcoin network (fetching UTXOs and sending transactions) completely trustlessly.

![Depiction of Full Profile](images/hemi-network-docker-profile-full-v2.svg)


#### Profile: hemi
This profile runs all components of the Hemi stack, but relies on external Bitcoin and Ethereum RPC endpoints.

It supports all ways of interacting with the Hemi network (Standard RPC + Extended Consensus RPC, Fully Local PoP Mining).

However, your Hemi node is synchronized from ETH DA data provided by external Ethereum (Execution + Beacon) RPC nodes, Bitcoin finality information is calculated based on BTC data provided by an external Bitcoin RPC node, and PoP miners connecting to the BFG endpoint are also interfacing with the Bitcoin network (fetching UTXOs and sending transactions) through this external Bitcoin RPC node.

![Depiction of Hemi Profile](images/hemi-network-docker-profile-hemi-v2.svg)


#### Profile: hemi-min
This profile only runs the minimum components of the Hemi stack required to interact with dApps on the Hemi network, and relies on external Bitcoin and Ethereum RPC endpoints.

It supports the primary ways of interacting with the Hemi network (Standard RPC + Consensus RPC), but does not support the Extended Consensus RPC (Bitcoin Finality statistics from BFG/op-node) or Fully Local PoP Mining.

Similarly to the `hemi` profile, a node running the `hemi-min` profile your Hemi node is synchronized from ETH DA data provided by external Ethereum (Execution + Beacon) RPC nodes. However, no Bitcoin finality information is available to external services, and there is no local BFG node to run a Fully Local PoP Miner.

![Depiction of Hemi-Min Profile](images/hemi-network-docker-profile-hemi-min-v2.svg)

### ⚠️ Important Note on Security

> [!WARNING]
> **Many of the required credentials are hard-coded in this directory, as the assumption is you are not exposing the
services' ports to the outside world.** This allows communication between the services locally.
**In setups where you plan to expose the ports, ensure that you change any credential values (e.g. JWT token, cookie).**

## Running with Docker Compose

### Node Synchronization Type

Nodes can perform initial synchronization in two modes, `archive` or `snap`.  `archive` rederives the entire Hemi chain from L1 data and stores historical information while `snap` only indexes data coming from ethereum blobs starting at the time sync begins.  Most users will only need `snap` which is must faster and smaller. After performing an initial `snap` sync, a node will switch to performing full L1 derivation and storing historical information after the point in the chain where the `snap` sync occurred.

To run an `archive` sync, you will need access to an ethereum Beacon API rpc provider that has all historical blob data (the optional ethereum node in the compose file will NOT work for that). Hemi uses EIP-4844 blobs for data availability, and so performing a full sync from scratch requires access to an Ethereum node which has retained all of these historical blobs. By default, Etherem Consensus-Layer nodes (like Prysm) prune blobs after 4096 Ethereum epochs (49152 ETH blocks, or ~18.2 days).

Additionally, a fully-synced Hemi node that is offline for longer than the blob pruning period (~18.2 days) will either have to be `snap` synced again, or will have to be connected to an Ethereum node that has historical blobs available.

Possible providers for full blob data can be found at:
https://docs.arbitrum.io/run-arbitrum-node/l1-ethereum-beacon-chain-rpc-providers

Once you have choosen your network and sync type, run the command:
```
cd localnode
./gen-files.sh NETWORK SYNCMODE
```

For example, to prepare to run a mainnet snap mode:
```
./gen-files.sh mainnet snap
```

### Run the compose files.

Run the following to start each of the required daemons as Docker containers:

```sh
cd localnode
docker compose -f docker-compose.yml --profile full up --build
```

## Accessing the Nodes

To access the nodes, you can use JSON-RPC or WebSockets exposed on the following ports:

| Name                  | Port    |
|:----------------------|:--------|
| op-node JSON-RPC      | `8547`  |
| op-geth JSON-RPC      | `18546` |
| op-geth WebSocket RPC | `28546` |

## Peer-to-Peer (P2P)

The current version gets data from the Ethereum network. For fastest access to blocks, direct P2P connections to the
Hemi network will be necessary. This is coming soon.

## Mainnet

Run the file:
```sh
docker compose -f docker-compose_mainnet.yml --profile full up --build
```

## Bring your own L1s

Several of the containers (the Bitcoin and Ethereum L1 containers) here can be replaced with nodes or API endpoints of your own.

To run just the L1 containers, start with this command:
```sh
docker compose -f localnode/docker-compose_mainnet.yml --profile L1 up --build
```

To run only the Hemi containers, add your endpoints to `.env`:
```sh
OPSYNCMODE=consensus-layer
BITCOINENDPOINT=
BITCOINCREDS=
GETHL1ENDPOINT=
PRYSMENDPOINT=
```
and run:
```sh
docker compose -f localnode/docker-compose_mainnet.yml --profile hemi up --build
```

and similarly for testnet.

## Monitoring

A simple bash script setup to monitor all the running daemons is
provided as well for mainnet or testnet (just run the docker compose
command in the first pane).  This requires tmux and is primarily for
interactive use/debugging, not production running.

```sh
./heminode.sh
```

For testnet:
```sh
./heminode.sh testnet
```

## Running Without Docker

Steps to run the Hemi stack without Docker will be detailed at a later date.
