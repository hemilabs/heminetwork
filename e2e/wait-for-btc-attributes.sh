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
# block DEPTH blocks behind the head of the sequencer has such a
# transaction, which is at or before the pivot block of a sync that starts
# now.
#
# Only one block is looked at per poll, so a block with such a transaction
# can be skipped; this relies on Bitcoin blocks still being mined.

L2_RPC="${L2_RPC:-http://op-geth-l2:8546}"

# the transaction type of a Bitcoin Attributes Deposited transaction
# (BtcAttributesDepositedTxType in op-geth)
BTC_ATTRIBUTES_TX_TYPE="0x7c"

# how far the pivot block of a snap sync is behind the head
# (fsMinFullBlocks in op-geth), and some more blocks to be sure
DEPTH=$((64 + 16))

# makes a JSON-RPC call to the l2 and prints the response; prints nothing
# when the l2 does not answer or answers with an HTTP error
rpc() {
	curl --silent --fail --max-time 10 -X POST -H 'Content-Type: application/json' \
		--data "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":$2}" "$L2_RPC"
}

echo "waiting for an l2 block $DEPTH blocks behind the head with a Bitcoin Attributes Deposited transaction at $L2_RPC"

loops=0
while :; do
	# the head of the sequencer, as hex, or empty when the l2 does not
	# answer yet
	head=$(rpc eth_blockNumber '[]' | jq -r '.result // empty')
	if [ -n "$head" ]; then
		head=$(printf '%d' "$head")

		# the chain must be at least DEPTH blocks long before there is a
		# block DEPTH blocks behind the head
		if [ "$head" -ge "$DEPTH" ]; then
			n=$((head - DEPTH))

			# the number of Bitcoin Attributes Deposited transactions in
			# block n, or empty when the block or an answer is missing
			count=$(rpc eth_getBlockByNumber "[\"$(printf '0x%x' "$n")\", true]" |
				jq -r --arg type "$BTC_ATTRIBUTES_TX_TYPE" \
					'.result.transactions // empty | map(select((.type // "" | ascii_downcase) == $type)) | length')

			# block n is at or before the pivot block of a snap sync that
			# starts now, so the sync can get the hVM light state
			if [ -n "$count" ] && [ "$count" -gt 0 ]; then
				echo "the l2 is at block $head and l2 block $n has a Bitcoin Attributes Deposited transaction"
				exit 0
			fi
		fi
	fi

	# report progress about every 10 seconds
	loops=$((loops + 1))
	if [ $((loops % 10)) -eq 0 ]; then
		echo "still waiting (head: ${head:-none})"
	fi
	sleep 1
done
