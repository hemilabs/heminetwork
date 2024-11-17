#!/bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

geth init --datadir /tmp/datadir/geth /tmp/genesis.json

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
	--networkid=43111 \
	--authrpc.vhosts=* \
	--authrpc.addr=0.0.0.0 \
	--authrpc.port=8551 \
	--authrpc.jwtsecret=/tmp/jwt/jwt.hex \
	--rollup.disabletxpoolgossip=false \
	--datadir=/tmp/datadir/geth \
	--override.ecotone=1725868497 \
	--override.canyon=1725868497 \
	--override.cancun=1725868497 \
	--tbc.initheight=0 \
	--tbc.leveldbhome=/tbcdata \
	--bootnodes=enode://f591af0f0c25b794f008254262da082df23282f946c397128f4ca13f53842a09867cff8d8b68a39fddcfee885abc5b60ba21b98f88dcf7983a834c3ebc5b0254@34.13.162.152:30303,enode://e7970a29d89f8b158371a8d4aca909ee8c1c759e711547b797a6a6f01513c1e7c85121dd2600397ca20cebf3cea21025001be7c0f577b496caf32ea0433a1cfd@34.90.21.246:30303,enode://8eedf09af5bd8bb14479dfeabf522e6d80ac624d272d5ea87779121960c3f8fe4f16e6f1d344e92369a7e855e9e96bc003c8a31f82b73305b74684edc72ac90e@34.13.171.139:30303,enode://ebb5c1de8e66c27e57ddafbf9ef8d9da81e25dc68a5ff9d901a45e970671dd93f46d7b19b33624c23813281c924d27b4f8865d2c2daec858561a69706b04be7e@34.91.216.121:30303,enode://0a9d3aaadbc403d9034fc587836969ae14ca096a86bef7330f9c4da7a68113f07e70b9bc543b966ff545f0a4c5408d498b6105d0f37fd1f173599d6ac2baefd8@34.141.148.19:30303
