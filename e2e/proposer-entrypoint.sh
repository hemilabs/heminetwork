set -ex

op-proposer/bin/op-proposer \
    --poll-interval=1s \
    --rpc.port=8560 \
    --game-factory-address=$(jq -r '.opChainDeployments[0].disputeGameFactoryProxyAddress' /shared-dir/state.json) \
    --private-key=${ADMIN_PRIVATE_KEY} \
    --l1-eth-rpc=http://geth-l1:8545 \
    --rollup-rpc=http://op-node:8547 \
    --resubmission-timeout=15s \
    --safe-abort-nonce-too-low-count=1 \
    --proposal-interval=10s \
    --game-type=1
    