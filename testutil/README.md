# Testutil Package

The `testutil` package provides centralized utility functions that are commonly used throughout test code in the Hemi Network project. This package aims to reduce code duplication and provide consistent testing utilities across all test files.

## Functions

### Byte Array Generation

- **`FillOutBytes(prefix string, size int) []byte`** - Creates a byte slice of specified size with the given prefix, filling remaining space with underscores
- **`FillOutBytesWith0s(prefix string, size int) []byte`** - Creates a byte slice of specified size with the given prefix, filling remaining space with zero bytes
- **`RandomBytes(size int) []byte`** - Generates a slice of random bytes of the specified size
- **`Bytes32(prefix string) []byte`** - Creates a 32-byte slice filled with a prefix and underscores (commonly used for hashes)
- **`Header80(prefix string) []byte`** - Creates an 80-byte slice filled with a prefix and underscores (commonly used for Bitcoin block headers)
- **`Bytes32Array(data []byte) [32]byte`** - Converts a byte slice to a [32]byte array

### Hex Decoding

- **`DecodeHex(s string) []byte`** - Decodes a hex string to bytes (panics on error)
- **`DecodeTxID(s string) [32]byte`** - Decodes a hex string to a [32]byte txid (panics on error)

### Random Data Generation

- **`CreateRandomBytes(size int) []byte`** - Creates a slice of random bytes of the specified size
- **`CreateRandomHash() []byte`** - Creates a random 32-byte hash
- **`CreateRandomHeader() []byte`** - Creates a random 80-byte header

### Test Data Creation

- **`CreateAddress() string`** - Creates a localhost address with a free port
- **`MustNewJSONRPCRequest(id uint64, method string, params any) interface{}`** - Creates a JSON RPC request and panics on error
- **`AllocateMap[T comparable, V any](size int, key T, value V) map[T]V`** - Creates a map of specified size with test data
- **`PingPeer(ctx context.Context, t *testing.T, p *rawpeer.RawPeer) error`** - Sends a ping message to a peer and waits for pong response
- **`CreateCallback() func(context.Context, any, any)`** - Creates a callback function that decrements a WaitGroup
- **`CreateCallbackPanic() func(context.Context, any, any)`** - Creates a callback function that panics
- **`CreateMockServer(t *testing.T, handler func(net.Conn)) (*httptest.Server, func())`** - Creates a mock server for testing WebSocket connections

### Network Utilities

- **`EnsureCanConnectWS(t *testing.T, url string, timeout time.Duration) error`** - Attempts to connect to a WebSocket URL with exponential backoff
- **`EnsureCanConnectTCP(t *testing.T, addr string, timeout time.Duration) error`** - Checks TCP connectivity to address within timeout
- **`GetFreePort() string`** - Returns a free TCP port as string
- **`GetVerifiedFreePort(ctx context.Context, t *testing.T) int`** - Returns a verified free TCP port

### WebSocket Utilities

- **`AssertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command)`** - Verifies that a WebSocket connection receives the expected ping command

### Database Utilities

- **`CreateTestDB(ctx context.Context, t *testing.T) (bfgd.Database, *sql.DB, func())`** - Creates a temporary Postgres database for tests
- **`CreateTestDBWithURI(ctx context.Context, t *testing.T) (bfgd.Database, string, *sql.DB, func())`** - Creates a temporary Postgres database for tests and returns the database URI
- **`ApplySQLFiles(ctx context.Context, t *testing.T, db *sql.DB, pattern string)`** - Applies SQL files matching the pattern to the database
- **`DefaultTestContext() (context.Context, func())`** - Creates a default test context with timeout

### Bitcoin Utilities

- **`CreateBtcTx(height int, keystone hemi.L2Keystone, key *btcec.PrivateKey) (*btcutil.Tx, error)`** - Creates a Bitcoin transaction for testing
- **`GetBtcTxPkScript(tx *btcutil.Tx) ([]byte, error)`** - Extracts the public key script from a Bitcoin transaction

## Usage Examples

### Creating Test Data

```go
import "github.com/hemilabs/heminetwork/testutil"

// Create a 32-byte hash for testing
hash := testutil.Bytes32("test")

// Create a random hash
randomHash := testutil.CreateRandomHash()

// Decode a hex string
bytes := testutil.DecodeHex("48656c6c6f") // "Hello"
```

### Network Testing

```go
// Check if a service is reachable
err := testutil.EnsureCanConnectTCP(t, "localhost:8080", 5*time.Second)
if err != nil {
    t.Fatalf("Service not reachable: %v", err)
}

// Get a free port for testing
port := testutil.GetFreePort()
```

### Test Data Creation

```go
// Create test addresses and servers
addr := testutil.CreateAddress()
server, cleanup := testutil.CreateMockServer(t, handler)
defer cleanup()

// Create test data structures
m := testutil.AllocateMap(100, "key", "value")

// Create test callbacks
callback := testutil.CreateCallback()
callbackPanic := testutil.CreateCallbackPanic()
```

## Migration Guide

When migrating existing test code to use this package:

1. Replace local helper functions with calls to `testutil` functions
2. Remove duplicate code from test files
3. Update imports to include `"github.com/hemilabs/heminetwork/testutil"`
4. Ensure all test files use consistent utility functions

## Contributing

When adding new utility functions to this package:

1. Ensure the function is commonly used across multiple test files
2. Add comprehensive documentation with examples
3. Include unit tests for the new function
4. Update this README with the new function
5. Consider backward compatibility when modifying existing functions

