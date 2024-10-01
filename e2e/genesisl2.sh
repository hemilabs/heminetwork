#! /bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -ex

JSON_RPC=$OP_GETH_L1_RPC

# start geth in a local container
# wait for geth to become responsive
until curl --silent --fail $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"net_version\", \"params\": []}"; do sleep 3; done

sleep 3

# extract the variables we need from json output
MY_ADDRESS="0x78697c88847dfbbb40523e42c1f2e28a13a170be"
ONE_TIME_SIGNER_ADDRESS="0x$(cat output/deployment.json | jq --raw-output '.signerAddress')"
GAS_COST="0x$(printf '%x' $(($(cat output/deployment.json | jq --raw-output '.gasPrice') * $(cat output/deployment.json | jq --raw-output '.gasLimit'))))"
TRANSACTION="0x$(cat output/deployment.json | jq --raw-output '.transaction')"
DEPLOYER_ADDRESS="0x$(cat output/deployment.json | jq --raw-output '.address')"


sleep 3

# send gas money to signer
curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendTransaction\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$ONE_TIME_SIGNER_ADDRESS\",\"value\":\"$GAS_COST\"}]}"

sleep 3

# deploy the deployer contract
curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendRawTransaction\", \"params\": [\"$TRANSACTION\"]}"

sleep 3

# deploy our contract
# contract: pragma solidity 0.5.8; contract Apple {function banana() external pure returns (uint8) {return 42;}}
BYTECODE="6080604052348015600f57600080fd5b5060848061001e6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063c3cafc6f14602d575b600080fd5b6033604f565b604051808260ff1660ff16815260200191505060405180910390f35b6000602a90509056fea165627a7a72305820ab7651cb86b8c1487590004c2444f26ae30077a6b96c6bc62dda37f1328539250029"
MY_CONTRACT_ADDRESS=$(curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --silent --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_call\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$DEPLOYER_ADDRESS\", \"data\":\"0x0000000000000000000000000000000000000000000000000000000000000000$BYTECODE\"}, \"latest\"]}" | jq --raw-output '.result')

sleep 3

curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendTransaction\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$DEPLOYER_ADDRESS\", \"gas\":\"0xf4240\", \"data\":\"0x0000000000000000000000000000000000000000000000000000000000000000$BYTECODE\"}]}"

sleep 3

# call our contract (NOTE: MY_CONTRACT_ADDRESS is the same no matter what chain we deploy to!)
MY_CONTRACT_METHOD_SIGNATURE="c3cafc6f"
curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_call\", \"params\": [{\"to\":\"$MY_CONTRACT_ADDRESS\", \"data\":\"0x$MY_CONTRACT_METHOD_SIGNATURE\"}, \"latest\"]}"
# expected result is 0x000000000000000000000000000000000000000000000000000000000000002a (hex encoded 42)

cd /git/optimism/packages/contracts-bedrock

forge script ./scripts/Deploy.s.sol:Deploy --non-interactive --private-key=$ADMIN_PRIVATE_KEY --broadcast --rpc-url $JSON_RPC

curl -H 'Content-Type: application/json' -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x2", true],"id":1}' $JSON_RPC > /tmp/blockl1.json

echo $(jq '.result' /tmp/blockl1.json) > /tmp/blockl1.json

cat /tmp/blockl1.json

/git/optimism/op-node/bin/op-node \
    genesis \
    l2 \
    --deploy-config  \
    /git/optimism/packages/contracts-bedrock/deploy-config/devnetL1.json \
    --l1-deployments  \
    /git/optimism/packages/contracts-bedrock/deployments/devnetL1/.deploy \
    --outfile.l2  \
    /l2configs/genesis.json \
    --outfile.rollup  \
    /l2configs/rollup.json \
    --l1-starting-block \
    /tmp/blockl1.json
