#! /bin/sh
# Copyright (c) 2024 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -ex

MY_ADDRESS="0x78697c88847dfbbb40523e42c1f2e28a13a170be"

# need an older version of op-deployer here, need to update the repo
# to use the new one but this will do for our purposes now
# this should only affect the op-geth-l2-setup container (no others)
cd /git/optimism
git checkout 12dba15e5e3fdc48620a81872b381b2e79fcb62b
git submodule update --init --recursive
cd /git/optimism/op-deployer
just build

cd /git/optimism/packages/contracts-bedrock

forge build --deny never --skip test --out .artifacts

/git/optimism/op-deployer/bin/op-deployer init --l1-chain-id 1337 --l2-chain-ids 901 --workdir .deployer --intent-type custom

ARTIFACTS_AT="file://$(pwd)/.artifacts"

# the generated intent.toml file generated from init will need to be modified 
# below, there isn't a way to do this other than just modifying the file
# directly 

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
echo "$(tomlq -t ".globalDeployOverrides.preimageOracleChallengePeriod = 10" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.faultGameClockExtension = 10" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.faultGameMaxClockDuration = 100" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.dangerouslyAllowCustomDisputeParameters = true" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.disputeGameFinalityDelaySeconds = 10" .deployer/intent.toml)" > .deployer/intent.toml
echo "$(tomlq -t ".globalDeployOverrides.enableGovernance = true" .deployer/intent.toml)" > .deployer/intent.toml

cat .deployer/intent.toml
cat .deployer/state.json

/git/optimism/op-deployer/bin/op-deployer apply --workdir .deployer --deployment-target genesis

ls -a .deployer

cat .deployer/state.json

/git/optimism/op-deployer/bin/op-deployer inspect genesis --workdir .deployer 901 > /shared-dir/genesis.json
/git/optimism/op-deployer/bin/op-deployer inspect rollup --workdir .deployer 901 > /shared-dir/rollup.json
/git/optimism/op-deployer/bin/op-deployer inspect deploy-config --workdir .deployer 901 > /shared-dir/deploy-config.json

echo "$(jq '.l1CancunTimeOffset = "0x0"' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.disputeGameFinalityDelaySeconds = 10' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.faultGameWithdrawalDelay = 10' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.sequencerWindowSize = 200' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.l1BlockTime = 3' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.proofMaturityDelaySeconds = 10' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.preimageOracleChallengePeriod = 10' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq 'del(.customGasTokenAddress)' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.operatorFeeVaultRecipient = "0x78697c88847dfbbb40523e42c1f2e28a13a170be"' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json
echo "$(jq '.operatorFeeVaultWithdrawalNetwork = 1' /shared-dir/deploy-config.json)" > /shared-dir/deploy-config.json

/git/optimism/op-deployer/bin/op-deployer inspect l1 --workdir .deployer 901 > /shared-dir/l1deployments.json

echo "$(jq -r '.l1StateDump' .deployer/state.json)" > /shared-dir/l1StateDump.bin

cat /shared-dir/l1StateDump.bin

cat /shared-dir/deploy-config.json
cat /shared-dir/l1deployments.json

cat l1allocs.json

/git/optimism/op-node/bin/op-node \
    genesis \
    l1 \
    --deploy-config  \
    /shared-dir/deploy-config.json \
    --l1-deployments /shared-dir/deploy-config.json \
    --outfile.l1 /shared-dir/l1genesis.json \
    --l1-allocs ./l1allocs.json


# this adds an allocation line to fund our address on L1, this allows us
# to transact with the L1
echo "$(jq '.alloc."0x78697c88847dfbbb40523e42c1f2e28a13a170be".balance = "0x999999999999999999"' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.alloc."0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc".balance = "0x999999999999999999"' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json


echo "$(jq --argjson timestamp "$(jq '.timestamp' /shared-dir/genesis.json)" '.timestamp = $timestamp' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json

cat /shared-dir/l1genesis.json

cp .deployer/state.json /shared-dir/state.json
