#!/bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -xe

sleep 10

JSON_RPC=http://geth-l1:8545

curl -H 'Content-Type: application/json' -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x0", true],"id":1}' $JSON_RPC > /tmp/blockl1.json

echo $(jq -r '.result.hash' /tmp/blockl1.json) > /tmp/l1genesisblockhash.txt

cat /tmp/l1genesisblockhash.txt

echo "$(jq ".genesis.l1.hash = \"$(cat /tmp/l1genesisblockhash.txt)\"" /shared-dir/rollup.json)" > /shared-dir/rollup.json

BESTBLOCKHASH=$(curl --data-binary '{"jsonrpc": "1.0", "id": "curltest", "method": "getbestblockhash", "params": []}' -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq '.result')

echo "best block hash $BESTBLOCKHASH"

curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/

BLOCKHEIGHT=$(curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq '.result.height')

BLOCKHEADER=$(curl --data-binary "{\"jsonrpc\": \"1.0\", \"id\": \"curltest\", \"method\": \"getblockheader\", \"params\": [$BESTBLOCKHASH, false]}" -H 'content-type: text/plain;' http://user:password@bitcoind:18443/ | jq -r '.result')




genesis_header_file=/shared-dir/genesis-header.txt
if [ -f "$genesis_header_file" ]; then
    BLOCKHEADER="$(cat $genesis_header_file)"
else
    echo $BLOCKHEADER > $genesis_header_file
fi

genesis_height_file=/shared-dir/genesis-height.txt
if [ -f "$genesis_height_file" ]; then
    BLOCKHEIGHT="$(cat $genesis_height_file)"
else
    echo $BLOCKHEIGHT > $genesis_height_file
fi

echo "setting hvm genesis to $BLOCKHEADER:$BLOCKHEIGHT"

# The L2 execution client is op-reth (Hemi hVM ported from hemilabs/op-geth).
# hVM Phase 0 activates at HVM_PHASE0_TIMESTAMP (hemilabs/op-geth hvm0Time).
# The other L2 forks follow the genesis created by op-deployer: op-reth
# derives the genesis block from the chain configuration, so moving forks that
# are active at genesis would change the genesis hash in rollup.json.
jq --argjson hvm "$HVM_PHASE0_TIMESTAMP" '.config.hvm0Time = $hvm' \
  /shared-dir/genesis.json > /tmp/genesis-l2.json

/bin/op-reth init --datadir /tmp/datadir --chain /tmp/genesis-l2.json

# the sequencer keeps the node key it had with op-geth so its enode stays the same
P2P_KEY_ARGS=""
if [ -n "$GETH_NODEKEYHEX" ]; then
  echo -n "$GETH_NODEKEYHEX" > /tmp/nodekey
  P2P_KEY_ARGS="--p2p-secret-key /tmp/nodekey"
fi

exec /bin/op-reth node \
 --datadir /tmp/datadir \
 --chain /tmp/genesis-l2.json \
 --http \
 --http.addr 0.0.0.0 \
 --http.port 8546 \
 --http.corsdomain '*' \
 --http.api web3,debug,eth,txpool,net,miner \
 --ws \
 --ws.addr 0.0.0.0 \
 --ws.port 28546 \
 --ws.origins '*' \
 --ws.api web3,debug,eth,txpool,net,miner \
 --ipcpath /tmp/datadir/geth.ipc \
 --authrpc.addr 0.0.0.0 \
 --authrpc.port 8551 \
 --authrpc.jwtsecret /tmp/jwt.hex \
 --port 30303 \
 --disable-discovery \
 --max-outbound-peers 50 \
 --trusted-peers 'enode://a121ecb08858c9e681f0414d079953ec233ffd667acaf66abebad310df3dd4a025a89fe25c3b79a148083cd93c639108cb5b0193a591ee20bd362a7258a3e8d1@192.169.199.8:30303' \
 $P2P_KEY_ARGS \
 --rpc.gascap 200000000 \
 --rpc.eth-proof-window 1209600 \
 --hvm.enabled \
 --hvm.genesisheader=$BLOCKHEADER \
 --hvm.genesisheight=$BLOCKHEIGHT \
 --hvm.headerdatadir=/tbc/headers \
 --tbc.leveldbhome=/tbc/tbcdatadir \
 --tbc.network=localnet \
 --tbc.prometheusaddress='0.0.0.0:5555' \
 --tbc.seeds="${TBC_SEEDS:-bitcoind:18444}" \
 --override.hvm0=$HVM_PHASE0_TIMESTAMP \
 -vvv
