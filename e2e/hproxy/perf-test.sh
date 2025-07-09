#!/bin/sh

SCRIPT_DIR=$(dirname "$0")
BIN_DIR="$SCRIPT_DIR/../../bin/"
TEST_BIN_DIR="$BIN_DIR/test/"

if [ -z "$NODE_COUNT" ]; then
	echo "Missing NODE_COUNT (number of mock geth instances)" >&2
	exit 1
fi

DURATION="${DURATION-15s}"       # loadgen duration
CONCURRENCY="${CONCURRENCY-100}" # loadgen concurrency
LOADGEN_URL="http://localhost:8545"

if ! [ -f "$BIN_DIR/hproxyd" ]; then
	echo "hproxyd binary not found" >&2
	exit 1
fi

# Build mockgeth and loadgen binaries
mkdir -p "$TEST_BIN_DIR/"
if ! [ -f "$TEST_BIN_DIR/mockgeth" ]; then
	go build -o "$TEST_BIN_DIR/mockgeth" "$SCRIPT_DIR/mockgeth"
fi
if ! [ -f "$TEST_BIN_DIR/loadgen" ]; then
	go build -o "$TEST_BIN_DIR/loadgen" "$SCRIPT_DIR/loadgen"
fi

echo "Starting $NODE_COUNT mockgeth nodes..."

# Start mock geth instances
ADDRESSES=""
NODE_PIDS=""
LOGFILES=""
for i in $(seq 1 "$NODE_COUNT"); do
	logfile="$(mktemp)"
	LOGFILES="$LOGFILES $logfile"

	PERFTEST=1 NODE_ID="$i" \
		exec "$TEST_BIN_DIR/mockgeth" -addr ':0' >"$logfile" 2>&1 &
	pid=$!
	NODE_PIDS="$NODE_PIDS $pid"

	# Get listening address
	while :; do
		[ -s "$logfile" ] || sleep 0.05
		port=$(grep -m1 'LISTEN_PORT=' "$logfile" | sed 's/.*=\([0-9]*\)/\1/')
		if [ -n "$port" ]; then
			break
		fi
		sleep 0.05
	done

	ADDRESSES="$ADDRESSES,http://localhost:$port"
done

ADDRESSES="${ADDRESSES#,}"
echo "Running mock geth instances: $ADDRESSES"

# Start hproxy in background
echo "Starting hproxyd..."
HPROXY_PROMETHEUS_ADDRESS=localhost:8555 HPROXY_HVM_URLS="$ADDRESSES" exec "$BIN_DIR/hproxyd" &
hproxy_pid=$!
sleep 5

# Start loadgen in background
echo "Starting load generator..."
exec "$TEST_BIN_DIR/loadgen" \
	-url "$LOADGEN_URL" \
	-c "$CONCURRENCY" \
	-d "$DURATION" &
loadgen_pid=$!

# Wait until half-way through to print stats snapshot
half=$(echo "$DURATION" | sed 's/s$//')
half=$((half / 2))
sleep "$half"

echo ""
echo "------- stats snapshot -------"
for log in $LOGFILES; do
	line=$(grep '\[stats\]' "$log" | tail -1)
	echo "$line"
done
echo "------------------------------"
echo ""

# Wait for loadgen to finish
wait "$loadgen_pid"

# Cleanup
echo "Stopping hproxyd ($hproxy_pid) and geth instances..."
kill "$hproxy_pid"
sleep 2
kill -0 "$hproxy_pid" 2>/dev/null && {
	echo "hproxyd still running, force killing"
	kill -9 "$hproxy_pid"
}
for pid in $NODE_PIDS; do
	kill "$pid" >/dev/null 2>&1
done
for f in $LOGFILES; do
	rm -f "$f"
done
