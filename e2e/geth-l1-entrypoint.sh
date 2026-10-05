#!/bin/sh
# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Starts the localnet L1 execution client, geth, in one of two ways:
#   L1_CONSENSUS=dev (default): geth's dev mode, which simulates a consensus
#     layer inside geth (a block every 3 seconds, no real slots, no reorgs)
#   L1_CONSENSUS=prysm: a real proof-of-stake L1 driven by the Prysm beacon
#     node of the localnet over the engine API, see e2e/prysm

set -ex

case "${L1_CONSENSUS:-dev}" in
dev)
	MODE="--dev --dev.period 3 --nodiscover --maxpeers=0"
	;;
prysm)
	MODE="--authrpc.addr=0.0.0.0 --authrpc.port=8551 --authrpc.jwtsecret=/tmp/jwt.hex --nodiscover --maxpeers=0"
	;;
*)
	echo "unknown L1_CONSENSUS: $L1_CONSENSUS (expected dev or prysm)" >&2
	exit 1
	;;
esac

# the dev API only exists in dev mode (the tests use it to add withdrawals)
APIS="web3,debug,eth,txpool,net,engine,miner"
if [ "${L1_CONSENSUS:-dev}" = "dev" ]; then
	APIS="$APIS,dev"
fi

exec geth \
	$MODE \
	--keystore /tmp/keystore \
	--password /tmp/passwords.txt \
	--http --http.port=8545 --http.addr 0.0.0.0 --http.vhosts '*' --http.api="$APIS" \
	--ws --ws.addr=0.0.0.0 --ws.port=8546 --ws.origins='*' --ws.api="$APIS" \
	--syncmode=full \
	--authrpc.vhosts='*' \
	--rpc.allow-unprotected-txs \
	--datadir /shared-dir/gethl1datadir \
	--gpo.percentile=0 \
	--rpc.txfeecap=0 \
	--miner.gaslimit=200000000 \
	--rpc.gascap=200000000
