#! /bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -ex

# JSON_RPC=$OP_GETH_L1_RPC

# # start geth in a local container
# # wait for geth to become responsive
# until curl --silent --fail $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"net_version\", \"params\": []}"; do sleep 3; done

# sleep 3

# # extract the variables we need from json output
MY_ADDRESS="0x78697c88847dfbbb40523e42c1f2e28a13a170be"
# MY_OTHER_ADDRESS="0x06f0f8ee8119b2a0b7a95ba267231be783d8d2ab"
# ONE_TIME_SIGNER_ADDRESS="0x$(cat output/deployment.json | jq --raw-output '.signerAddress')"
# GAS_COST="0x$(printf '%x' $(($(cat output/deployment.json | jq --raw-output '.gasPrice') * $(cat output/deployment.json | jq --raw-output '.gasLimit'))))"
# TRANSACTION="0x$(cat output/deployment.json | jq --raw-output '.transaction')"
# DEPLOYER_ADDRESS="0x$(cat output/deployment.json | jq --raw-output '.address')"

# echo $DEPLOYER_ADDRESS

# sleep 3

# # send gas money to signer
# curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendTransaction\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$ONE_TIME_SIGNER_ADDRESS\",\"value\":\"$GAS_COST\"}]}"

# sleep 3

# curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendTransaction\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$MY_OTHER_ADDRESS\",\"value\":\"0x10000\"}]}"

# sleep 3

# # deploy the deployer contract
# curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendRawTransaction\", \"params\": [\"$TRANSACTION\"]}"

# sleep 3

# # deploy our contract
# # contract: pragma solidity 0.5.8; contract Apple {function banana() external pure returns (uint8) {return 42;}}
# BYTECODE="6080604052348015600f57600080fd5b5060848061001e6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063c3cafc6f14602d575b600080fd5b6033604f565b604051808260ff1660ff16815260200191505060405180910390f35b6000602a90509056fea165627a7a72305820ab7651cb86b8c1487590004c2444f26ae30077a6b96c6bc62dda37f1328539250029"
# MY_CONTRACT_ADDRESS=$(curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --silent --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_call\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$DEPLOYER_ADDRESS\", \"data\":\"0x0000000000000000000000000000000000000000000000000000000000000000$BYTECODE\"}, \"latest\"]}" | jq --raw-output '.result')

# echo $MY_CONTRACT_ADDRESS

# sleep 3

# curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_sendTransaction\", \"params\": [{\"from\":\"$MY_ADDRESS\",\"to\":\"$DEPLOYER_ADDRESS\", \"gas\":\"0xf4240\", \"data\":\"0x0000000000000000000000000000000000000000000000000000000000000000$BYTECODE\"}]}"

# sleep 3

# # call our contract (NOTE: MY_CONTRACT_ADDRESS is the same no matter what chain we deploy to!)
# MY_CONTRACT_METHOD_SIGNATURE="c3cafc6f"
# curl $JSON_RPC -X 'POST' -H 'Content-Type: application/json' --data "{\"jsonrpc\":\"2.0\", \"id\":1, \"method\": \"eth_call\", \"params\": [{\"to\":\"$MY_CONTRACT_ADDRESS\", \"data\":\"0x$MY_CONTRACT_METHOD_SIGNATURE\"}, \"latest\"]}"
# # expected result is 0x000000000000000000000000000000000000000000000000000000000000002a (hex encoded 42)

cd /git/optimism/packages/contracts-bedrock

# forge install

# just build

# forge script ./scripts/deploy/Deploy.s.sol:Deploy --sender $MY_ADDRESS --sig 'deploySuperchain()' --slow --unlocked --non-interactive --broadcast --rpc-url $JSON_RPC

# forge script ./scripts/deploy/Deploy.s.sol:Deploy --sender $MY_ADDRESS --sig 'deployOpChain()' --slow --unlocked --non-interactive --broadcast --rpc-url $JSON_RPC


# forge create ./src/L1/OPContractsManager.sol:OPContractsManager --rpc-url $JSON_RPC --private-key $ADMIN_PRIVATE_KEY

# /git/optimism/op-deployer/bin/op-deployer init --help




cd /git/optimism/packages/contracts-bedrock


forge build --deny-warnings --skip test --out .artifacts
/git/optimism/op-deployer/bin/op-deployer init --l1-chain-id 1337 --l2-chain-ids 901 --workdir .deployer --intent-type custom

ARTIFACTS_AT="file://$(pwd)/.artifacts"
# ARTIFACTS_AT="tag://op-contracts/v3.0.0-rc.2"

# /git/optimism/op-deployer/bin/op-deployer bootstrap proxy \
#   --l1-rpc-url $JSON_RPC \
#   --private-key $ADMIN_PRIVATE_KEY \
#   --artifacts-locator $ARTIFACTS_AT \
#   --proxy-owner $MY_ADDRESS \
#   --outfile proxy-output.json


# cat proxy-output.json

# /git/optimism/op-deployer/bin/op-deployer bootstrap superchain \
#   --l1-rpc-url $JSON_RPC \
#   --private-key $ADMIN_PRIVATE_KEY \
#   --artifacts-locator $ARTIFACTS_AT \
#   --superchain-proxy-admin-owner $MY_ADDRESS \
#   --protocol-versions-owner $MY_ADDRESS \
#   --guardian $MY_ADDRESS \
#   --paused false \
#   --outfile superchain-output.json \
#   --superchain-proxy-admin-owner $MY_ADDRESS \
#   --guardian $MY_ADDRESS

# ls -a

# cat > superchain-output.json <<EOL
# {
#   "proxyAdminAddress": "0x06118d32f4473c01f969238fb1c08c695be9643d",
#   "superchainConfigImplAddress": "0xbdc8ca17f9d94efafcc25b28a07c41a71f59338b",
#   "superchainConfigProxyAddress": "0x3c54ad3aa68c00e53e053e30e130618b6d9efcdb",
#   "protocolVersionsImplAddress": "0x37e15e4d6dffa9e5e320ee1ec036922e563cb76c",
#   "protocolVersionsProxyAddress": "0x0875bb7930651b28557c4fe0944cfd64cfae033b"
# }
# EOL

# /git/optimism/op-deployer/bin/op-deployer bootstrap implementations \
#   --l1-rpc-url $JSON_RPC \
#   --private-key $ADMIN_PRIVATE_KEY \
#   --artifacts-locator $ARTIFACTS_AT \
#   --outfile .deployer/bootstrap_implementations.json \
#   --protocol-versions-proxy 0x0875bb7930651b28557c4fe0944cfd64cfae033b \
#   --superchain-config-proxy 0x3c54ad3aa68c00e53e053e30e130618b6d9efcdb \
#   --superchain-proxy-admin $MY_ADDRESS \
#   --upgrade-controller $MY_ADDRESS

# cat > upgrade-config.json <<EOL
# {
#   "prank": "$MY_ADDRESS",
#   "opcmAddress": $(jq '.opcmAddress' .deployer/bootstrap_implementations.json),
#   "chainConfigs": [
#     {
#       "systemConfigProxy": "0x3c54ad3aa68c00e53e053e30e130618b6d9efcdb",
#       "protocolVersionsProxy": "0x0875bb7930651b28557c4fe0944cfd64cfae033b",
#       "absolutePrestate": "0x0000000000000000000000000000000000000000000000000000000000000000"
#     }
#   ]
# }
# EOL

# cat upgrade-config.json

# /git/optimism/op-deployer/bin/op-deployer upgrade v3.0.0 \
#   --l1-rpc-url $JSON_RPC \
#   --override-artifacts-url $ARTIFACTS_AT \
#   --config upgrade-config.json \
#   --log.format json

# cast call --trace $MY_ADDRESS '0xff2dd5a1000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000003c54ad3aa68c00e53e053e30e130618b6d9efcdb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' --private-key $ADMIN_PRIVATE_KEY  --rpc-url $JSON_RPC

# cast send $MY_ADDRESS '0xff2dd5a1000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000000000000000010000000000000000000000003c54ad3aa68c00e53e053e30e130618b6d9efcdb00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000' --private-key $ADMIN_PRIVATE_KEY  --rpc-url $JSON_RPC

# cat .deployer/bootstrap_implementations.json

apt-get install -y yq


echo "$(tomlq -t ".chains[0].roles.systemConfigOwner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.unsafeBlockSigner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.l1ProxyAdminOwner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.l2ProxyAdminOwner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.batcher = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.proposer = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].roles.challenger = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].eip1559Denominator = 1" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].eip1559DenominatorCanyon = 1" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].eip1559Elasticity = 1" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].baseFeeVaultRecipient = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].l1FeeVaultRecipient = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".chains[0].sequencerFeeVaultRecipient = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml

echo "$(tomlq -t ".l1ContractsLocator = \"$ARTIFACTS_AT\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".l2ContractsLocator = \"$ARTIFACTS_AT\"" .deployer/intent.toml)" > .deployer/intent.toml

echo "$(tomlq -t ".superchainRoles.proxyAdminOwner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".superchainRoles.protocolVersionsOwner = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".superchainRoles.guardian = \"$MY_ADDRESS\"" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.l2BlockTime = 1" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.proofMaturityDelaySeconds = 10" .deployer/intent.toml)" > .deployer/intent.toml

# echo "$(tomlq -t "del(.superchainRoles)" .deployer/intent.toml)" > .deployer/intent.toml


# echo "$(tomlq -t ".opcmAddress = $(jq '.opcmAddress' .deployer/bootstrap_implementations.json)" .deployer/intent.toml)" > .deployer/intent.toml

# echo "$(jq --argjson implDeps "$(cat .deployer/bootstrap_implementations.json)" '.implementationsDeployment = $implDeps' .deployer/state.json)" > .deployer/state.json
# echo "$(jq --argjson implDeps "$(cat superchain-output.json)" '.superchainDeployment = $implDeps' .deployer/state.json)" > .deployer/state.json
# echo "$(jq '.create2Salt = "0xb080c6ee4463bd9b316689feedc48eab73e6cf3e78a036533de77decb0430135"' .deployer/state.json)" > .deployer/state.json

# echo "$(jq ".implementationsDeployment.opcmAddress = $(jq '.opcmAddress' .deployer/bootstrap_implementations.json)" .deployer/state.json)" > .deployer/state.json

cat .deployer/intent.toml
cat .deployer/state.json


# echo '{
#   "opcm": null,
#   "prank": null,
#   "chainConfigs": {
#     "systemConfigProxy": null,
#     "proxyAdmin": null
#   }
# }' > someconfig.json

# /git/optimism/op-deployer/bin/op-deployer upgrade v2.0.0 --config someconfig.json --deployment-target live \
# --l1-rpc-url $JSON_RPC


/git/optimism/op-deployer/bin/op-deployer apply --workdir .deployer --deployment-target genesis --

ls -a .deployer

cat .deployer/state.json

# forge script ./scripts/Deploy.s.sol:Deploy --non-interactive --private-key=$ADMIN_PRIVATE_KEY --broadcast --rpc-url $JSON_RPC

# /git/optimism/op-deployer/bin/op-deployer --log.level=trace inspect genesis --workdir /tmp/output/deployment 901

# curl -H 'Content-Type: application/json' -X POST --data '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x2", true],"id":1}' $JSON_RPC > /tmp/blockl1.json

# echo $(jq '.result' /tmp/blockl1.json) > /tmp/blockl1.json

# cat /tmp/blockl1.json

/git/optimism/op-deployer/bin/op-deployer inspect genesis --workdir .deployer 901 > /l2configs/genesis.json
/git/optimism/op-deployer/bin/op-deployer inspect rollup --workdir .deployer 901 > /l2configs/rollup.json
/git/optimism/op-deployer/bin/op-deployer inspect deploy-config --workdir .deployer 901 > /l2configs/deploy-config.json

echo "$(jq '.l1CancunTimeOffset = "0x0"' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json
echo "$(jq '.disputeGameFinalityDelaySeconds = 10' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json
echo "$(jq '.faultGameWithdrawalDelay = 10' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json
echo "$(jq '.sequencerWindowSize = 200' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json
echo "$(jq '.l1BlockTime = 3' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json
echo "$(jq '.proofMaturityDelaySeconds = 10' /l2configs/deploy-config.json)" > /l2configs/deploy-config.json

/git/optimism/op-deployer/bin/op-deployer inspect l1 --workdir .deployer 901 > /l2configs/l1deployments.json

echo "$(jq -r '.l1StateDump' .deployer/state.json)" > /l2configs/l1StateDump.bin

cat /l2configs/l1StateDump.bin

cat /l2configs/deploy-config.json
cat /l2configs/l1deployments.json

cat l1allocs.json

/git/optimism/op-node/bin/op-node \
    genesis \
    l1 \
    --deploy-config  \
    /l2configs/deploy-config.json \
    --l1-deployments /l2configs/deploy-config.json \
    --outfile.l1 /l2configs/l1genesis.json \
    --l1-allocs ./l1allocs.json

echo "$(jq '.alloc."0x78697c88847dfbbb40523e42c1f2e28a13a170be".balance = "0x999999999999999999"' /l2configs/l1genesis.json)" > /l2configs/l1genesis.json

echo "$(jq --argjson timestamp "$(jq '.timestamp' /l2configs/genesis.json)" '.timestamp = $timestamp' /l2configs/l1genesis.json)" > /l2configs/l1genesis.json

cat /l2configs/l1genesis.json

cp .deployer/state.json /l2configs/state.json


# # HACK TO REMOVE old fields to make the generated genesis file compatible for 
# # after newer version
# cat /tmp/rollup.json | jq ".genesis.l1.hash = $(cat /tmp/blockl1.json | jq '.hash' )" | jq 'del(.da_resolve_window,.da_challenge_window,.da_challenge_address,.use_plasma)' | jq '. += {"chain_op_config": {"eip1559Elasticity": 6,"eip1559Denominator": 50,"eip1559DenominatorCanyon": 250}}' | jq ". += { \"holocene_time\": $HVM_PHASE0_TIMESTAMP, \"granite_time\": $HVM_PHASE0_TIMESTAMP, \"fjord_time\": $HVM_PHASE0_TIMESTAMP, \"ecotone_time\": 1725868497, \"delta_time\": 1725868497, \"canyon_time\": 1725868497, \"regolith_time\": 1725868497, \"isthmus_time\": $HVM_PHASE0_TIMESTAMP }" > /l2configs/rollup.json