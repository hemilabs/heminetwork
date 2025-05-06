#!/bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

/bin/geth init --datadir /tmp/datadir /l2configs/genesis.json

BESTBLOCKHASH=$(curl --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getbestblockhash", "params": []}' -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq '.result')

echo "best block hash $BESTBLOCKHASH"

curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/

BLOCKHEIGHT=$(curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq '.result.height')

BLOCKHEADER=$(curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH, false]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq -r '.result')

echo "setting hvm genesis to $BLOCKHEADER:$BLOCKHEIGHT"

/bin/geth \
 --keystore \
 /tmp/keystore \
 --password \
 /tmp/passwords.txt \
 --http \
 --http.port=8546 \
 --http.addr \
 '0.0.0.0' \
 --http.vhosts \
 '*' \
 --ws  \
 --ws.addr=0.0.0.0  \
 --ws.port=28546  \
 --ws.origins="*"  \
 --http.api=web3,debug,eth,txpool,net,engine,miner \
 --ws.api=debug,eth,txpool,net,engine,miner \
 --syncmode=full  \
 --nodiscover  \
 --maxpeers=0 \
 --networkid=901 \
 --authrpc.vhosts="*"  \
 --rpc.allow-unprotected-txs \
 --allow-insecure-unlock \
 --datadir \
 /tmp/datadir \
 --authrpc.vhosts="*" \
 --authrpc.addr=0.0.0.0 \
 --authrpc.port=8551 \
 --authrpc.jwtsecret=/tmp/jwt.hex \
 --tbc.network=localnet \
 --tbc.seeds='bitcoind:18444' \
 --override.ecotone=1725868497 \
 --override.canyon=1725868497 \
 --override.cancun=1725868497 \
 --hvm.headerdatadir=/tbc/headers \
 --tbc.leveldbhome=/tbc/tbcdatadir \
 --hvm.genesisheader=$BLOCKHEADER \
 --hvm.genesisheight=$BLOCKHEIGHT \
 --hvm.enabled \
 --override.hvm0=$HVM_PHASE0_TIMESTAMP \
 --tbc.network=localnet \
 --override.isthmus=$HVM_PHASE0_TIMESTAMP \
 --override.holocene=$HVM_PHASE0_TIMESTAMP \
 --override.granite=$HVM_PHASE0_TIMESTAMP \
 --override.fjord=$HVM_PHASE0_TIMESTAMP \
 --verbosity=5 \
 --unlock='78697c88847dfbbb40523e42c1f2e28a13a170be' \
 --rpc.enabledeprecatedpersonal
 # Clayton note: this fixes the mismatched state.scheme, but is it the correct
# thing to do?
#  --gcmode=archive  \
