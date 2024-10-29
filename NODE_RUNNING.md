# Running a full node

The following document describes how to run a full p2p node with rpc access.  This does NOT run a batcher or sequencer.

## Prerequisites

This assumes you are running on Ubuntu 24.04 (the latest LTS).  Other systems are possible but may not be fully supported.

### install pre-reqs

go1.23

## Build Hemi software

```sh
git clone git@github.com:hemilabs/heminetwork.git
cd heminetwork
make all
```

## Download the additional required software

TODO: check hashes

### bitcoind:

```sh
mkdir bin
wget \
https://bitcoincore.org/bin/bitcoin-core-28.0/bitcoin-28.0-x86_64-linux-gnu.tar.gz
tar xzf bitcoin-28.0-x86_64-linux-gnu.tar.gz
mv bitcoin-28.0/bin/bitcoind ~/bin/
mv bitcoin-28.0/bin/bitcoin-cli ~/bin/
```

### geth:

```sh
wget \
https://gethstore.blob.core.windows.net/builds/geth-linux-amd64-1.14.11-f3c696fa.tar.gz
tar xzf geth-linux-amd64-1.14.11-f3c696fa.tar.gz
mv geth-linux-amd64-1.14.11-f3c696fa/geth ~/bin/
```

### prysm

```sh
wget \ https://github.com/prysmaticlabs/prysm/releases/download/v5.1.2/beacon-chain-v5.1.2-linux-amd64
chmod + beacon-chain-v5.1.2-linux-amd64
mv beacon-chain-v5.1.2-linux-amd64 ~/bin/beacon-chain
```

## Run the daemons

### bitcoind

```sh
./bitcoind \
-testnet=1 \
-rpcuser=user \
-rpcpassword=password \
-rpcallowip=0.0.0.0/0 \
-rpcbind=0.0.0.0:18443 \
-txindex=1
```

### geth-L1

### op-geth-L2

### op-node
### bssd
### bfgd
### electrs
### bfgd-postgres
### prysm

## Docker

Docker files are already provided for all of the [Hemi software](https://hub.docker.com/u/hemilabs).  Compose files for a full node will be provided at a future time.

