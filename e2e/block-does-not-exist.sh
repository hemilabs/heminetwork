#!/usr/bin/env bash
# Reads invalidated block hashes written by bitcoind-reorg and verifies none
# exist on the target node. Exits 0 if all blocks are absent, 1 if any exist.
set -euo pipefail

: "${BITCOIND_RPC_URL:?BITCOIND_RPC_URL environment variable is required}"
: "${BITCOIND_RPC_USER:?BITCOIND_RPC_USER environment variable is required}"
: "${BITCOIND_RPC_PASS:?BITCOIND_RPC_PASS environment variable is required}"
: "${INVALIDATED_HASHES_FILE:=/shared-dir/invalidated_hashes}"

command -v jq   >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 2; }
command -v curl >/dev/null 2>&1 || { echo "error: curl is required" >&2; exit 2; }

[[ -f "$INVALIDATED_HASHES_FILE" ]] \
    || { echo "error: hashes file not found: ${INVALIDATED_HASHES_FILE}" >&2; exit 2; }

block_exists() {
    local hash="$1"
    local response error_code
    response=$(curl -s -X POST "$BITCOIND_RPC_URL" \
        -u "${BITCOIND_RPC_USER}:${BITCOIND_RPC_PASS}" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"1.0\",\"id\":\"blockcheck\",\"method\":\"getblockheader\",\"params\":[\"${hash}\",false]}") \
        || { echo "error: RPC request failed" >&2; exit 2; }
    error_code=$(printf '%s' "$response" | jq -r '.error.code // empty')
    case "$error_code" in
        "")  return 0 ;;  # no error → block found
        -5)  return 1 ;;  # block not found
        *)
            echo "error: unexpected RPC error (code ${error_code}): $(printf '%s' "$response" | jq -r '.error.message // "unknown"')" >&2
            exit 2
            ;;
    esac
}

while IFS= read -r hash || [[ -n "$hash" ]]; do
    [[ -z "$hash" ]] && continue
    if block_exists "$hash"; then
        echo "block ${hash} still exists on ${BITCOIND_RPC_URL}" >&2
        exit 1
    fi
    echo "block ${hash} confirmed absent"
done < "$INVALIDATED_HASHES_FILE"
