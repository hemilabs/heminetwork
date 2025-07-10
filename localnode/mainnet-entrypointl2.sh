#!/bin/sh
# Copyright (c) 2024-2025 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

if [ -d "/tmp/datadir/geth" ]; then
	echo "geth data dir exists, skipping genesis."
else
	geth init --datadir /tmp/datadir/geth /tmp/genesis.json
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
	--override.hvm0=1739286001 \
	--override.isthmus=1751554801 \
	--override.holocene=1751554801 \
	--override.granite=1751554801 \
	--override.fjord=1751554801 \
	--tbc.leveldbhome=/tbcdata/data \
    --hvm.headerdatadir=/tbcdata/headers \
	--tbc.network=mainnet \
    --hvm.genesisheader=0000003efaaa2ba65de684c512bb67ef115298d1d16bcb49b16c02000000000000000000ed31a56788c4488afc4ee69e0791ad6aeeb9ea05f069e0fdde6159068765ad3f4128a96726770217e7f41c86 \
    --hvm.genesisheight=883092 \
	--bootnodes=enode://e7970a29d89f8b158371a8d4aca909ee8c1c759e711547b797a6a6f01513c1e7c85121dd2600397ca20cebf3cea21025001be7c0f577b496caf32ea0433a1cfd@34.90.21.246:30303,enode://70877d3aa6c4ccc09d960c269846215d5dcc8bf47013ac532c1ccc3d9cfe61434c96b9d6cad88a96c3f91187fb00214d903a6be6d8e93140ac4a3c099684ce34@34.13.162.152:30303,enode://27f75e68a8c14cae2f4e12f060477c150767e98149e16a448baddc25d800c008edf8b1fefd13b206c27e5473ac9234ba1958a8267fe5272e9de3819ac080bf22@34.13.171.139:30303,enode://588ffb65f841aede8d8f69a3175f9cfed1b79d20d40a7feb8a70e574b5610fb4049bf02f3170f1ae25bff806b2c823653b28af711e1962ea3f45d99d58608191@34.91.216.121:30303,enode://ba86a76186268948bc34b7fa1c2f08c24ed60cda61346cf1a1cca278b0ef1de49e567039952e06e4887a0252974401a6d6729bfc12945c6d8c65eacbf3b11ca7@34.141.148.19:30303
