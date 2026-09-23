#!/bin/sh
# Copyright (c) 2025-2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

set -ex

# PROPOSER_MODE selects the contract that op-proposer submits output roots to:
#   fault: the DisputeGameFactory deployed by op-deployer (default)
#   l2oo:  the legacy L2OutputOracle deployed by deploy-l2oo.sh
PROPOSER_MODE="${PROPOSER_MODE:-fault}"

case "$PROPOSER_MODE" in
fault)
	op-proposer/bin/op-proposer \
	    --poll-interval=1s \
	    --rpc.port=8560 \
	    --game-factory-address=$(jq -r '.opChainDeployments[0].disputeGameFactoryProxyAddress' /shared-dir/state.json) \
	    --private-key=${ADMIN_PRIVATE_KEY} \
	    --l1-eth-rpc=http://geth-l1:8545 \
	    --rollup-rpc=http://op-node:8548 \
	    --resubmission-timeout=15s \
	    --safe-abort-nonce-too-low-count=3 \
	    --proposal-interval=10s \
	    --game-type=1 \
	    --txmgr.not-in-mempool-timeout=3s \
	    --allow-non-finalized=true
	;;
l2oo)
	op-proposer/bin/op-proposer \
	    --poll-interval=1s \
	    --rpc.port=8560 \
	    --l2oo-address=$(jq -r '.l2OutputOracleProxy' /shared-dir/l2oo.json) \
	    --private-key=${ADMIN_PRIVATE_KEY} \
	    --l1-eth-rpc=http://geth-l1:8545 \
	    --rollup-rpc=http://op-node:8548 \
	    --resubmission-timeout=15s \
	    --safe-abort-nonce-too-low-count=3 \
	    --txmgr.not-in-mempool-timeout=3s \
	    --allow-non-finalized=true
	;;
*)
	echo "unknown PROPOSER_MODE: $PROPOSER_MODE (expected fault or l2oo)"
	exit 1
	;;
esac
