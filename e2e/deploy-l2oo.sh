#!/bin/sh
# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Deploys a (legacy) L2OutputOracle to the running L1 so that op-proposer may
# be run with --l2oo-address, see PROPOSER_MODE in proposer-entrypoint.sh.
# The OptimismPortalProxy is then upgraded to the legacy OptimismPortal which
# proves withdrawals against the L2OutputOracle.
# The addresses are written to /shared-dir/l2oo.json.

set -ex

# the L2OutputOracle parameters are only in the deploy config when
# PROPOSER_MODE=l2oo, see genesisl2.sh
if [ "${PROPOSER_MODE:-fault}" != "l2oo" ]; then
	echo "PROPOSER_MODE is not l2oo, not deploying L2OutputOracle"
	exit 0
fi

L1_RPC="${L1_RPC:-http://geth-l1:8545}"
BEDROCK="/git/optimism/packages/contracts-bedrock"
PROJECT="/tmp/l2oo"

until curl --silent --fail $L1_RPC -X 'POST' -H 'Content-Type: application/json' --data '{"jsonrpc":"2.0", "id":1, "method": "net_version", "params": []}'; do sleep 3; done

# the L2OutputOracle parameters are set in the deploy config by genesisl2.sh
DEPLOY_CONFIG=/shared-dir/deploy-config.json
export L2OO_SUBMISSION_INTERVAL='0x78'
export L2OO_STARTING_TIMESTAMP='0x0'
export L2OO_STARTING_BLOCK_NUMBER='0x0'
export L2OO_L2_BLOCK_TIME='0x1'
export L2OO_PROPOSER=$(jq -r '.l2OutputOracleProposer' $DEPLOY_CONFIG)
export L2OO_CHALLENGER=$(jq -r '.l2OutputOracleChallenger' $DEPLOY_CONFIG)
export L2OO_FINALIZATION_PERIOD_SECONDS=$(jq -r '.finalizationPeriodSeconds' $DEPLOY_CONFIG)

# build in a standalone foundry project that only pulls the few files it needs
# out of contracts-bedrock, compiling all of contracts-bedrock fails at this
# optimism commit due to incompatible solc versions in unrelated contracts
rm -rf $PROJECT
mkdir -p $PROJECT/contracts $PROJECT/deployments
cp /l2oo/L2OutputOracle.sol /l2oo/DeployL2OutputOracle.s.sol \
	/l2oo/OptimismPortal.sol /l2oo/UpgradeOptimismPortal.s.sol \
	$PROJECT/contracts/

cat > $PROJECT/foundry.toml <<TOML
[profile.default]
src = 'contracts'
script = 'contracts'
test = 'contracts'
out = 'out'
libs = []
auto_detect_remappings = false
optimizer = true
optimizer_runs = 999999
remappings = [
  'src/=$BEDROCK/src/',
  'interfaces/=$BEDROCK/interfaces/',
  '@openzeppelin/contracts/=$BEDROCK/lib/openzeppelin-contracts/contracts/',
  '@rari-capital/solmate/=$BEDROCK/lib/solmate/',
  'forge-std/=$BEDROCK/lib/forge-std/src/',
]
allow_paths = ['$BEDROCK']
fs_permissions = [{ access = 'read-write', path = './deployments/' }]
TOML

cd $PROJECT

forge build

# The L1 runs the Glamsterdam fork, which charges contract code deposit as
# state gas (EIP-8037) at a far higher rate than the pinned forge's local EVM.
# By default forge sizes each broadcast transaction from its local simulation,
# so creations would run out of gas on the L1 ("contract creation code storage
# out of gas").  --skip-simulation makes forge ask the L1 to estimate gas for
# every transaction instead.  Note that forge's --gas-limit only sets the
# block gas limit of its local simulation, not the broadcast gas.

# the batcher uses the same key, retry in case we race it for a nonce
for i in 1 2 3 4 5; do
	if forge script contracts/DeployL2OutputOracle.s.sol:DeployL2OutputOracle \
		--broadcast \
		--slow \
		--skip-simulation \
		--rpc-url $L1_RPC; then
		break
	fi

	if [ $i -eq 5 ]; then
		echo "could not deploy L2OutputOracle"
		exit 1
	fi

	sleep 3
done

# the OptimismPortalProxy deployed by op-deployer proves withdrawals against
# dispute games, upgrade it to the legacy OptimismPortal so withdrawals are
# proven against the L2OutputOracle
export L2OO_PROXY=$(jq -r '.l2OutputOracleProxy' deployments/l2oo.json)
export OPTIMISM_PORTAL_PROXY=$(jq -r '.opChainDeployments[0].optimismPortalProxyAddress' /shared-dir/state.json)

# the batcher uses the same key, retry in case we race it for a nonce
for i in 1 2 3 4 5; do
	if forge script contracts/UpgradeOptimismPortal.s.sol:UpgradeOptimismPortal \
		--broadcast \
		--slow \
		--skip-simulation \
		--rpc-url $L1_RPC; then
		break
	fi

	if [ $i -eq 5 ]; then
		echo "could not upgrade OptimismPortal"
		exit 1
	fi

	sleep 3
done

cp deployments/l2oo.json /shared-dir/l2oo.json
cat /shared-dir/l2oo.json
