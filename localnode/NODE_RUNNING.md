# Running a full node

The following document describes how to run a full p2p node with rpc access.  This does NOT run a batcher or sequencer.

## Prerequisites

This assumes you are running on docker + docker compose on Ubuntu 24.04 (the latest LTS).  Other systems are possible but may not be fully supported.

Docker files are already provided for all of the [Hemi software](https://hub.docker.com/u/hemilabs).

## System requirements

### CPU/RAM

16 vCPUS and 64GB RAM.

### DISK

Due to the need for a full bitcoin and ethereum node, a large amount of SSD or NVME disk space is needed.

Currently, testnet needs a minimum of 3TB storage.

### install pre-reqs

docker

docker-compose

### Get the hemi software

```sh
git clone git@github.com:hemilabs/heminetwork.git
cd heminetwork
```

## Required components

The following daemons are needed as part of the hemi software.  They are all controlled by the docker compose file:

1. bitcoind
2. electrs
3. geth
4. prysm
5. op-geth
6. op-node
7. bssd
8. bfgd
9. postgres

## Running the network

```sh
docker compose -f localnode/docker-compose.yml up --build
```

## Accessing the node

To access the node, you can use rpc or websockets at the following ports:

XXX (clayton, please add in)

## p2p

The current version gets data from the ethereum network.  For fastest access to block, direct p2p connection to the hemi network will be necessary.  This is coming soon.

## Mainnet

Mainnet support coming soon.

## Running without docker

Running without docker will be described at a later date.

