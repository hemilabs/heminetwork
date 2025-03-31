# Running the Hemi stack

This document details how to run the full Hemi stack with P2P nodes and RPC access. *This does NOT run a batcher or
sequencer.*

<details>
  <summary>Table of Contents</summary>

<!-- TOC -->
* [Running the Hemi stack](#running-the-hemi-stack)
  * [Prerequisites](#prerequisites)
    * [System requirements](#system-requirements)
      * [CPU and RAM](#cpu-and-ram)
      * [Disk](#disk)
      * [ulimits](#ulimits)
  * [Setup](#setup)
    * [Check prerequisites](#check-prerequisites)
    * [Clone the heminetwork repository](#clone-the-heminetwork-repository)
    * [Required components](#required-components)
    * [⚠️ Important Note on Security](#-important-note-on-security)
  * [Running with Docker Compose](#running-with-docker-compose)
  * [Accessing the nodes](#accessing-the-nodes)
  * [Peer-to-Peer (P2P)](#peer-to-peer-p2p)
  * [Mainnet](#mainnet)
  * [Running without Docker](#running-without-docker)
<!-- TOC -->
</details>

## Prerequisites

This guide assumes you are running [Docker](https://docs.docker.com/get-started/get-docker/)
and [Docker Compose](https://docs.docker.com/compose/) on Ubuntu 24.04 (the latest LTS). Running on other setups is
possible, but may not be fully supported.

Docker images for each Hemi Network component is published to [Docker Hub](https://hub.docker.com/u/hemilabs).

### System requirements

#### CPU and RAM

At least 8 CPU cores and 32GB RAM is required to run the Hemi stack.  This does NOT Include requirements for the L1
nodes (Bitcoin and Ethereum).

#### Disk

At this time (Q1 2025) 4.5TB of disk space is required for mainnet or testnet.  NVMe disk is highly recommended.
This will of course grow with time.

#### ulimits

Certain components of the network require a very large number of open files. The startup will attempt to set
the `ulimits` properly, however it will exit quickly with an error if your system does not allow high enough ulimits.

## Setup

### Check prerequisites

Check that your system matches the [prerequisites](#prerequisites). Make sure that the following are installed and
setup:

- [Docker](https://docs.docker.com/get-started/get-docker/)
- [Docker Compose](https://docs.docker.com/compose/)

### Clone the heminetwork repository

To get started, clone this repository:

```sh
# Clone with HTTP
git clone https://github.com/hemilabs/heminetwork.git
cd heminetwork

# OR Clone with SSH
git clone ssh://git@github.com/hemilabs/heminetwork.git
cd heminetwork
```

### Required components

The following daemons are needed as part of the Hemi stack. They are all run under Docker Compose:

1. bitcoind
2. electrs
3. geth
4. prysm
5. op-geth
6. op-node
7. bssd
8. bfgd
9. postgres (used by bfgd)

### ⚠️ Important Note on Security

**Many of the required credentials are hard-coded in this directory, as the assumption is you are not exposing the
services' ports to the outside world.** This allows communication between the services locally.

**In setups where you plan to expose the ports, ensure that you change any credential values (e.g. JWT token, cookie).**

## Running with Docker Compose

### Choose node type

Nodes can run in two modes, `archive` or `snap`.  `archive` has all data while `snap` only indexes data coming from ethereum blobs starting at the time sync begins.  Most users will only need `snap` which is must faster and smaller.

To run an `archive` sync, you will need access to an ethereum rpc provider that has blob data (the optional ethereum node in the compose file will NOT work for that).

So possible providers for full blob data can be found at:
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

## Accessing the nodes

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

## Running without Docker

Steps to run the Hemi stack without Docker will be detailed at a later date.
