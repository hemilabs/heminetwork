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
	--syncmode=full \
	--gcmode=archive \
	--maxpeers=100 \
	--networkid=743111 \
	--authrpc.vhosts=* \
	--authrpc.addr=0.0.0.0 \
	--authrpc.port=8551 \
	--authrpc.jwtsecret=/tmp/jwt/jwt.hex \
	--rollup.disabletxpoolgossip=false \
	--datadir=/tmp/datadir/geth \
	--override.ecotone=1715865630 \
	--override.canyon=1715865630 \
	--override.cancun=1715865630 \
	--override.hvm0=1733930401 \
 	--override.isthmus=1748963425 \
 	--override.holocene=1748963425 \
 	--override.granite=1748963425 \
 	--override.fjord=1748963425 \
	--tbc.leveldbhome=/tbcdata/data \
    --hvm.headerdatadir=/tbcdata/headers \
	--tbc.network=testnet3 \
    --hvm.genesisheader=00c05732cdc3e0d654efe86351f0cbfc6c79325e9f9fa7886a39b552f5c4d90700000000dae4079485e26f1f77425b84a13760038a352d07a0fef92b5188bd04c2999162afca58679121011962b9d0a5 \
    --hvm.genesisheight=3522419 \
	--verbosity=3 \
	--bootnodes=enode://545da2b44f197091c0ca9283c9c1dd5ffc8562a3cd4a37709a7cd83ca725ecacdb4571dacd916a1455e9dd9f2260e5bc5dddf9fd40ba4601a71b401adbaeec21@34.147.95.117:30303
