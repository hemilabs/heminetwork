#!/bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

geth init --datadir /tmp/datadir/geth /tmp/testnet-genesis.json

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
	--maxpeers=2 \
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
	--tbc.initheight=0 \
	--tbc.leveldbhome=/tbcdata
