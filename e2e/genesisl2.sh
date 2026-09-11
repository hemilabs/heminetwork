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

cat /shared-dir/rollup.json

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
echo "$(jq '.alloc."0xf0faD6E77d55509484F93Ace13AAFa37138bc370".balance = "0x999999999999999999"' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.alloc."0x5663a22EAF74371d1765FdA4635fa81ee1c88fa8".balance = "0x999999999999999999"' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.config.cancunTime = 0' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.config.pragueTime = 0' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.config.osakaTime = 0' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json
echo "$(jq '.config.amsterdamTime = 0' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json

jq \
  --arg addr "0x00000961Ef480Eb55e80D19ad83579A64c007002" \
  --arg code "0x3373fffffffffffffffffffffffffffffffffffffffe1460cb5760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff146101f457600182026001905f5b5f82111560685781019083028483029004916001019190604d565b909390049250505036603814608857366101f457346101f4575f5260205ff35b34106101f457600154600101600155600354806003026004013381556001015f35815560010160203590553360601b5f5260385f601437604c5fa0600101600355005b6003546002548082038060101160df575060105b5f5b8181146101835782810160030260040181604c02815460601b8152601401816001015481526020019060020154807fffffffffffffffffffffffffffffffff00000000000000000000000000000000168252906010019060401c908160381c81600701538160301c81600601538160281c81600501538160201c81600401538160181c81600301538160101c81600201538160081c81600101535360010160e1565b910180921461019557906002556101a0565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff14156101cd57505f5b6001546002828201116101e25750505f6101e8565b01600290035b5f555f600155604c025ff35b5f5ffd" \
  --arg slot0 "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg inhibitor "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  '.alloc[$addr] = {"balance": "0x0", "code": $code, "storage": {($slot0): $inhibitor}}' \
  /shared-dir/l1genesis.json > /tmp/genesis.json.new \
  && mv /tmp/genesis.json.new /shared-dir/l1genesis.json

jq \
  --arg addr "0x0000BBdDc7CE488642fb579F8B00f3a590007251" \
  --arg code "0x3373fffffffffffffffffffffffffffffffffffffffe1460d35760115f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1461019a57600182026001905f5b5f82111560685781019083028483029004916001019190604d565b9093900492505050366060146088573661019a573461019a575f5260205ff35b341061019a57600154600101600155600354806004026004013381556001015f358155600101602035815560010160403590553360601b5f5260605f60143760745fa0600101600355005b6003546002548082038060021160e7575060025b5f5b8181146101295782810160040260040181607402815460601b815260140181600101548152602001816002015481526020019060030154905260010160e9565b910180921461013b5790600255610146565b90505f6002555f6003555b5f54807fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff141561017357505f5b6001546001828201116101885750505f61018e565b01600190035b5f555f6001556074025ff35b5f5ffd0000" \
  --arg slot0 "0x0000000000000000000000000000000000000000000000000000000000000000" \
  --arg inhibitor "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" \
  '.alloc[$addr] = {"balance": "0x0", "code": $code, "storage": {($slot0): $inhibitor}}' \
  /shared-dir/l1genesis.json > /tmp/genesis.json.new \
  && mv /tmp/genesis.json.new /shared-dir/l1genesis.json

jq \
  --arg addr "0x0000F90827F1C53a10cb7A02335B175320002935" \
  --arg code "0x3373fffffffffffffffffffffffffffffffffffffffe14604657602036036042575f35600143038111604257611fff81430311604257611fff9006545f5260205ff35b5f5ffd5b5f35611fff60014303065500" \
  '.alloc[$addr] = {"balance": "0x0", "code": $code}' \
  /shared-dir/l1genesis.json > /tmp/genesis.json.new \
  && mv /tmp/genesis.json.new /shared-dir/l1genesis.json

jq --arg addr "0x0000bFF46984e3725691FA540a8C7589300D8282" \
   --arg code "0x00" \
   '.alloc[$addr] = {"balance": "0x0", "code": $code}' \
   /shared-dir/l1genesis.json > /shared-dir/l1genesis.json.tmp \
   && mv /shared-dir/l1genesis.json.tmp /shared-dir/l1genesis.json

jq --arg addr "0x000064D678505ad48F8cCb093BC65613800E8282" \
   --arg code "0x00" \
   '.alloc[$addr] = {"balance": "0x0", "code": $code}' \
   /shared-dir/l1genesis.json > /shared-dir/l1genesis.json.tmp \
   && mv /shared-dir/l1genesis.json.tmp /shared-dir/l1genesis.json

echo "$(jq --argjson timestamp "$(jq '.timestamp' /shared-dir/genesis.json)" '.timestamp = $timestamp' /shared-dir/l1genesis.json)" > /shared-dir/l1genesis.json

cat /shared-dir/l1genesis.json

cp .deployer/state.json /shared-dir/state.json
