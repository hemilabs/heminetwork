#!/bin/sh
# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

if [ -d "/tmp/datadir/geth" ]; then
  echo "geth data dir exists, skipping genesis."
else
	geth init --datadir /tmp/datadir/geth /tmp/testnet-genesis.json
fi

geth \
	--config=/tmp/l2-config.toml \
	--http \
	--http.corsdomain=* \
	--http.vhosts=* \
	--http.addr=0.0.0.0 \
	--http.api=web3,eth,txpool,net \
	--http.port=18546 \
	--ws \
	--ws.rpcprefix=/ \
	--ws.addr=0.0.0.0 \
	--ws.port=28546 \
	--ws.origins=* \
	--ws.api=eth,txpool,net \
	--syncmode=snap \
	--gcmode=archive \
	--maxpeers=100 \
	--networkid=743111 \
	--authrpc.vhosts=* \
	--authrpc.addr=0.0.0.0 \
	--authrpc.port=8551 \
	--authrpc.jwtsecret=/tmp/jwt/jwt.hex \
	--rollup.disabletxpoolgossip=false \
	--datadir=/tmp/datadir/geth \
	--nodiscover \
	--override.ecotone=1715865630 \
	--override.canyon=1715865630 \
	--override.cancun=1715865630 \
	--tbc.leveldbhome=/tbcdata \
	--override.hvm0=1733930401 \
    --hvm.headerdatadir=/tbcdata/headers \
	--tbc.network=testnet3 \
    --hvm.genesisheader=00c05732cdc3e0d654efe86351f0cbfc6c79325e9f9fa7886a39b552f5c4d90700000000dae4079485e26f1f77425b84a13760038a352d07a0fef92b5188bd04c2999162afca58679121011962b9d0a5 \
    --hvm.genesisheight=3522419
