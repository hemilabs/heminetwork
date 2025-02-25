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

At least 16 CPU cores and 64GB RAM is required to run the stack.

#### Disk

As running the full Hemi stack requires running full Bitcoin and Ethereum nodes, a large amount of high performance
storage is required. **As of November 2024, testnet currently requires a minimum of 3TB of storage.**

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

Run the following to start each of the required daemons as Docker containers:

```sh
docker compose -f localnode/docker-compose.yml up --build
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

To run a mainnet node, you must obtain a rollup config and genesis block file from Hemi Labs.  Place those files in:
```sh
localnode/mainnet-genesis.json
localnode/mainnet-rollup.json
```

Then run the file:
```sh
docker compose -f localnode/docker-compose_mainnet.yml up --build
```

## Running without Docker

Steps to run the Hemi stack without Docker will be detailed at a later date.
