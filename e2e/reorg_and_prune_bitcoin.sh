#!/bin/bash
# reorg_and_prune_bitcoin.sh — walk the EVM chain backwards from "latest", find the
# first Bitcoin attributes deposited transaction (type 0x7c), extract the canonical
# Bitcoin tip hash, and call bitcoind invalidateblock with it.
#
# Required env:
#   ETH_RPC_URL   — EVM JSON-RPC HTTP endpoint (e.g. http://localhost:8545)
#   BTC_RPC_URL   — bitcoind JSON-RPC HTTP endpoint (e.g. http://localhost:8332)
#   BTC_RPC_USER  — bitcoind RPC username
#   BTC_RPC_PASS  — bitcoind RPC password

set -e

err=0
for var in ETH_RPC_URL BTC_RPC_URL BTC_RPC_USER BTC_RPC_PASS; do
  if [ -z "${!var}" ]; then
    echo "error: $var is not set" >&2
    err=1
  fi
done
[ $err -eq 0 ] || exit 1

if ! command -v jq >/dev/null 2>&1; then
  echo "error: jq is required but not found in PATH" >&2
  exit 1
fi


GENESIS_PARENT="0x0000000000000000000000000000000000000000000000000000000000000000"

# Reverse byte order of a hex string (for Bitcoin display convention).
reverse_hex() {
  local hex="$1" result="" i
  for (( i=${#hex}-2; i>=0; i-=2 )); do
    result+="${hex:$i:2}"
  done
  printf '%s' "$result"
}

# Extract CanonicalTip hash from BtcAttributesDepositData (hex-encoded tx input).
# Layout: [32-byte CanonicalTip][N * 80-byte Headers]
canonical_tip_hash() {
  local data="${1#0x}"
  data="${data#0X}"
  reverse_hex "${data:8:64}"
}

eth_rpc() {
  curl -sf -X POST "$ETH_RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$1"
}

btc_rpc() {
  curl --user "$BTC_RPC_USER:$BTC_RPC_PASS" \
    -X POST "$BTC_RPC_URL" \
    -H "Content-Type: application/json" \
    -d "$1"
}

get_block_by_number() {
  eth_rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByNumber\",\"params\":[\"$1\",true],\"id\":1}"
}

get_block_by_hash() {
  eth_rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByHash\",\"params\":[\"$1\",true],\"id\":1}"
}

# Seed with the latest block
block_json=$(get_block_by_number "latest")
block_hash=$(printf '%s' "$block_json" | jq -r '.result.hash')
block_num=$(printf '%s' "$block_json" | jq -r '.result.number')

if [ -z "$block_hash" ] || [ "$block_hash" = "null" ]; then
  echo "error: failed to retrieve latest block" >&2
  exit 1
fi

echo "scanning from block $block_num ($block_hash) downward..." >&2

while true; do
  # jq exits 1 when no match with -e; suppress that so set -e doesn't fire
  found=$(printf '%s' "$block_json" | jq -e '
    .result.transactions[]?
    | select((.type | ascii_downcase) == "0x7c")
  ' 2>/dev/null) || true

  if [ -n "$found" ]; then
    echo "found Bitcoin attributes deposited transaction in block $block_num ($block_hash):"
    printf '%s\n' "$found" | jq .

    tx_input=$(printf '%s' "$block_json" | jq -r '
      [.result.transactions[]? | select((.type | ascii_downcase) == "0x7c")] | .[0].input
    ')

    echo "tx_input = $tx_input"
    canonical_hash=$(canonical_tip_hash "$tx_input")
    echo "CanonicalTip: $canonical_hash"

    echo "calling bitcoind invalidateblock $canonical_hash..."
    result=$(btc_rpc "{\"jsonrpc\":\"1.0\",\"id\":\"invalidateblock\",\"method\":\"invalidateblock\",\"params\":[\"$canonical_hash\"]}")
    echo "bitcoind response: $result"

    exit 0
  fi

  parent_hash=$(printf '%s' "$block_json" | jq -r '.result.parentHash')

  if [ -z "$parent_hash" ] || [ "$parent_hash" = "null" ] || [ "$parent_hash" = "$GENESIS_PARENT" ]; then
    echo "error: reached genesis — no type 0x7c transaction found" >&2
    exit 1
  fi

  block_json=$(get_block_by_hash "$parent_hash")
  block_hash=$(printf '%s' "$block_json" | jq -r '.result.hash')
  block_num=$(printf '%s' "$block_json" | jq -r '.result.number')

  if [ -z "$block_hash" ] || [ "$block_hash" = "null" ]; then
    echo "error: failed to retrieve block for hash $parent_hash" >&2
    exit 1
  fi

  # Progress every 500 blocks (convert hex block number to decimal for modulo)
  block_dec=$(printf '%d' "$block_num")
  if [ $(( block_dec % 500 )) -eq 0 ]; then
    echo "  ...checked down to block $block_num" >&2
  fi
done
