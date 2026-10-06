#!/bin/sh
# Copyright (c) 2026 Hemi Labs, Inc.
# Use of this source code is governed by the MIT License,
# which can be found in the LICENSE file.

# Waits until the L2 can be snap synced from the sequencer.
#
# A node that snap syncs the L2 asks its peers for the hVM light state at
# the pivot block of the sync, which is 64 blocks behind the head.  A peer
# answers by walking back from that block to the last block with a Bitcoin
# Attributes Deposited transaction.  When there is none yet, because hVM
# activated a moment ago and no Bitcoin block was mined since, the peer
# refuses ("do not have previous header") and the node keeps asking for the
# same pivot block without getting anywhere.  On the localnet that is a
# race between the first Bitcoin block after the hVM activation and the
# start of the snap syncing node, which this closes: it returns once the
# sequencer has a block with such a transaction that is far enough behind
# its head to be at or before the pivot block of a sync that starts now.

L2_RPC="${L2_RPC:-http://op-geth-l2:8546}"

# the transaction type of a Bitcoin Attributes Deposited transaction
# (BtcAttributesDepositedTxType in op-geth)
BTC_ATTRIBUTES_TX_TYPE="0x7c"

# how far the pivot block of a snap sync is behind the head
# (fsMinFullBlocks in op-geth), and some more blocks to be sure
PIVOT_DISTANCE=64
MARGIN=16

rpc() {
	curl --silent --fail --max-time 10 -X POST -H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$L2_RPC"
}

echo "waiting for an l2 block with a Bitcoin Attributes Deposited transaction at $L2_RPC"

next=1
first=""
loops=0
while :; do
	head=$(rpc eth_blockNumber '[]' | jq -r '.result // empty')
	if [ -z "$head" ]; then
		echo "the l2 does not answer yet"
		sleep 3
		continue
	fi
	head=$(printf '%d' "$head")

	# look at the blocks that were not looked at yet
	while [ -z "$first" ] && [ "$next" -le "$head" ]; do
		count=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' "$next")\", true]" |
			jq -r --arg type "$BTC_ATTRIBUTES_TX_TYPE" \
				'if .result == null then "missing" else [.result.transactions[] | select((.type // "" | ascii_downcase) == $type)] | length end')
		case "$count" in
		"" | missing)
			# not there yet, or the l2 did not answer: ask again
			break
			;;
		0)
			next=$((next + 1))
			;;
		*)
			first=$next
			echo "l2 block $first has the first Bitcoin Attributes Deposited transaction"
			;;
		esac
	done

	if [ -n "$first" ] && [ "$head" -ge $((first + PIVOT_DISTANCE + MARGIN)) ]; then
		echo "the l2 is at block $head, a snap sync that starts now has its pivot block after l2 block $first"
		exit 0
	fi

	loops=$((loops + 1))
	if [ $((loops % 10)) -eq 0 ]; then
		if [ -z "$first" ]; then
			echo "no Bitcoin Attributes Deposited transaction up to l2 block $((next - 1)) (head: $head)"
		else
			echo "the l2 is at block $head, waiting for block $((first + PIVOT_DISTANCE + MARGIN))"
		fi
	fi
	sleep 1
done
