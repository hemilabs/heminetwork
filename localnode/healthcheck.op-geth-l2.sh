#! /bin/sh

set -ex

# example "http://op-geth-l2:18546"
# explicitly do not set default so we don't get false positives if the default is working
# OP_GETH_L2_READINESS_RPC

hextimestamp=$(curl $OP_GETH_L2_READINESS_RPC -X POST -H "Content-Type: application/json" --data '{"method":"eth_getBlockByNumber","params":["latest", false],"id":1,"jsonrpc":"2.0"}' | jq '.result.timestamp')

echo "received timestamp from rpc request: $hextimestamp"

decimaltimestamp=$(echo $hextimestamp | tr -d '"')

echo "decimal timestamp is: $decimaltimestamp"

difference=$(($(date +%s) - $(printf "%d\n" $decimaltimestamp)))

echo "the difference is $difference"

# if the latest block was created within 24 seconds (2 x l2 block time)
# then we're ready
if [ "$difference" -ge "24" ]; then
    echo "not ready"
    exit 1
else
    echo "ready"
    exit 0
fi
