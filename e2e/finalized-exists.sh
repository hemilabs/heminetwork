#!/bin/bash
set -ex

echo "will check for finalized block at $ETH_RPC_URL"

if [ -z "$ETH_RPC_URL" ]; then
echo "error: ETH_RPC_URL is not set" >&2
exit 1
fi
                                                                                                                                                                                                                                                                            
response=$(curl -sf -X POST "$ETH_RPC_URL" \
-H "Content-Type: application/json" \
-d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["finalized",false],"id":1}')

echo "received rpc response: $response"

if [ $? -ne 0 ]; then
echo "error: failed to reach RPC endpoint" >&2
exit 1
fi

number=$(printf '%s' "$response" | grep -o '"number":"0x[0-9a-fA-F]*"' | grep -o '0x[0-9a-fA-F]*')

if [ -z "$number" ] || [ "$number" = "0x0" ]; then
echo "error: no finalized block with height > 0 found (got: ${number:-null})" >&2
exit 1
fi

echo "finalized block: $number"
exit 0

