#!/usr/bin/env bash
set -euo pipefail

: "${ETH_RPC_URL:?ETH_RPC_URL environment variable is required}"
: "${BITCOIND_RPC_URL:?BITCOIND_RPC_URL environment variable is required}"
: "${BITCOIND_RPC_USER:?BITCOIND_RPC_USER environment variable is required}"
: "${BITCOIND_RPC_PASS:?BITCOIND_RPC_PASS environment variable is required}"
: "${INVALIDATED_HASHES_FILE:=/shared-dir/invalidated_hashes}"
command -v jq        >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }
command -v xxd       >/dev/null 2>&1 || { echo "error: xxd is required" >&2; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { echo "error: sha256sum is required" >&2; exit 1; }

ZERO_HASH="0x0000000000000000000000000000000000000000000000000000000000000000"

rpc() {
    curl -sf -X POST "$ETH_RPC_URL" \
        -H "Content-Type: application/json" \
        -d "$1"
}

invalidate_block() {
    local btc_hash="$1"
    if grep -qF "$btc_hash" "$INVALIDATED_HASHES_FILE" 2>/dev/null; then
        echo "    skipping duplicate: $btc_hash"
        return
    fi
    echo "    invalidating block: $btc_hash"
    local response
    response=$(curl -sf -X POST "$BITCOIND_RPC_URL" \
        -u "${BITCOIND_RPC_USER}:${BITCOIND_RPC_PASS}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"1.0\",\"id\":\"scan\",\"method\":\"invalidateblock\",\"params\":[\"$btc_hash\"]}")
    local err
    err=$(printf '%s' "$response" | jq -r '.error')
    if [[ "$err" != "null" ]]; then
        echo "error: invalidateblock failed for $btc_hash: $err" >&2
        exit 1
    fi
    printf '%s\n' "$btc_hash" >> "$INVALIDATED_HASHES_FILE"
}

tx_type_name() {
    case "$1" in
        0x0|"null") echo "legacy" ;;
        0x1)        echo "eip-2930" ;;
        0x2)        echo "eip-1559" ;;
        0x3)        echo "eip-4844 blob" ;;
        0x7c)       echo "bitcoin attributes deposited" ;;
        *)          echo "unknown ($1)" ;;
    esac
}

# Reverse a hex string byte-by-byte (for Bitcoin display order).
reverse_hex() {
    printf '%s' "$1" | awk '{
        for (i = length($0) - 1; i >= 1; i -= 2)
            printf "%s", substr($0, i, 2)
    }'
}

# Double SHA-256 of raw bytes encoded as hex; result in Bitcoin display order.
btc_hash() {
    local hex="$1"
    local pass1 pass2
    pass1=$(printf '%s' "$hex" | xxd -r -p | sha256sum -b | cut -d' ' -f1)
    pass2=$(printf '%s' "$pass1" | xxd -r -p | sha256sum -b | cut -d' ' -f1)
    reverse_hex "$pass2"
}

# Parse a 0x7c bitcoin attributes deposited transaction input field.
#
# ABI layout (all multi-byte integers are big-endian 32-byte words):
#   [0:4]        4 B  function selector
#   [4:36]      32 B  canonicalTip (Bitcoin block hash)
#   [36:68]     32 B  initialOffset (uint64, right-aligned)
#   [68:100]    32 B  numHeaders   (uint64, right-aligned)
#   [100:100+32N] 32B × N  per-header ABI offsets
#   then for each header i:
#     [+0:+32]  32 B  header byte-length word
#     [+32:+112] 80 B  raw Bitcoin header
#     [+112:+128] 16 B  ABI padding (80 rounds up to 3×32 = 96 bytes)
parse_btc_deposit_tx() {
    local input="${1#0x}"  # strip leading 0x

    # canonicalTip: bytes 4-35 → nibbles 8-71
    local canonical_tip
    canonical_tip=$(reverse_hex "${input:8:64}")
    echo "    canonical tip: $canonical_tip"
    invalidate_block "$canonical_tip"

    # numHeaders: bytes 68-99 (32-byte ABI word), uint64 in last 16 nibbles
    local num_headers
    num_headers=$(printf "%d" "0x${input:184:16}")

    # first header block starts at byte 100 + 32*N, then +32 for the length word
    local headers_base_nibble=$(( (132 + 32 * num_headers) * 2 ))

    local i=0
    while [[ $i -lt $num_headers ]]; do
        # each header block is 128 bytes = 256 nibbles; data begins after the 32-byte length word (64 nibbles)
        local header_hex="${input:$(( headers_base_nibble + i * 256 )):160}"
        local hdr_hash
        hdr_hash=$(btc_hash "$header_hex")
        echo "    header $i hash: $hdr_hash"
        invalidate_block "$hdr_hash"
        i=$(( i + 1 ))
    done
}

result=$(rpc '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["latest",true],"id":1}')
hash=$(printf '%s' "$result" | jq -r '.result.hash')

if [[ -z "$hash" || "$hash" == "null" ]]; then
    echo "error: failed to fetch latest block" >&2
    exit 1
fi

while true; do
    result=$(rpc "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getBlockByHash\",\"params\":[\"$hash\",true],\"id\":1}")
    block=$(printf '%s' "$result" | jq '.result')
    number=$(printf '%s' "$block" | jq -r '.number')
    parent=$(printf '%s' "$block" | jq -r '.parentHash')

    echo "block $number ($hash)"

    while read -r tx; do
        tx_hash=$(printf '%s' "$tx" | jq -r '.hash')
        tx_type=$(printf '%s' "$tx" | jq -r '.type // "null"')
        echo "  tx $tx_hash  type=$(tx_type_name "$tx_type")"
        if [[ "$tx_type" == "0x7c" ]]; then
            echo "found bitcoin attributes deposited transaction: $tx_hash"
            parse_btc_deposit_tx "$(printf '%s' "$tx" | jq -r '.input')"
            exit 0
        fi
    done < <(printf '%s' "$block" | jq -c '.transactions[]')

    [[ "$parent" == "$ZERO_HASH" ]] && break
    hash="$parent"
done

echo "error: no bitcoin attributes deposited transaction found" >&2
exit 1
