# TestUtil Package Usage Guidelines

## Introduction
The `testutil` package provides a set of useful functions for application testing. It consolidates common test utilities, simplifying their use and maintenance.

## Package Structure
- `database_test.go`: contains functions for working with test databases
- `helpers_test.go`: includes useful helper functions
- `json_test.go`: provides tools for working with JSON
- `time_test.go`: contains methods for working with time

## Core Functions

### Database
- `CreateTestDB()`: creates a test database
- `L2KeystonesCount(ctx context.Context, db *sql.DB) (int, error)`: returns the number of records in the l2_keystones table
- `ApplySQLFiles(db *sql.DB, files ...string) error`: applies SQL scripts to the database

### Helper Functions
- `FillOutBytes(prefix string, size int) []byte`: creates a byte slice of specified size with the given prefix and '_' characters
- `FillOutBytesWith0s(prefix string, size int) []byte`: creates a byte slice of specified size with the given prefix and zero bytes
- `RandomBytes(n int) []byte`: generates a random byte slice

### JSON
- `JSONCompare(t *testing.T, expected, actual interface{})`: compares two JSON objects
- `JSONMarshal(value interface{}) ([]byte, error)`: marshals a value into JSON bytes with error checking

### Time
- `SetTestTime(t *testing.T, location *time.Location)`: sets the time zone for tests
- `MockClock(t *testing.T, clock func() time.Time)`: creates mock clocks for time operations

### Network Functions
- `EnsureCanConnectWS(t *testing.T, url string, timeout time.Duration) error`: checks the ability to connect to WebSocket with exponential backoff
- `EnsureCanConnectTCP(t *testing.T, addr string, timeout time.Duration) error`: checks the ability to connect via TCP
- `GetFreePort() string`: returns a free TCP port as a string
- `GetVerifiedFreePort(ctx context.Context, t *testing.T) int`: returns a verified free TCP port
- `AssertPing(ctx context.Context, t *testing.T, c *websocket.Conn, cmd protocol.Command)`: checks for ping receipt from WebSocket connection

## Usage Examples

### Example 1: Creating a Test Database
```go
db := yourAppDB(t)
defer db.Close()
err := testutil.CreateTestDB(db)
if err != nil {
    t.Fatalf("Failed to create test database: %v", err)
}
```

### Example 2: Working with JSON
```go
expected := map[string]interface{}{"id": 1, "name": "test"}
actual := map[string]interface{}{"id": 1, "name": "test"}
testutil.JSONCompare(t, expected, actual)
```

### Example 3: Using Network Functions
```go
// Check WebSocket connection
err := testutil.EnsureCanConnectWS(t, "ws://localhost:8080/ws", 5*time.Second)
if err != nil {
    t.Fatalf("Failed to connect to WebSocket: %v", err)
}

// Get a free port
port := testutil.GetVerifiedFreePort(ctx, t)
addr := fmt.Sprintf(":%d", port)
```

## Recommendations
1. Use `testutil` instead of duplicating code from separate files
2. Create separate test databases for each test
3. Don't forget to clean up resources after tests
4. For complex testing scenarios, use mock objects from the package

## Change History
- 2025-08-08: Package initialization
- 2025-08-08: Added database functions
- 2025-08-08: Added helper functions
- 2025-08-08: Implemented JSON tools
- 2025-08-08: Added time functions
- 2025-08-11: Added FillOutBytesWith0s, GetVerifiedFreePort, EnsureCanConnectWS, EnsureCanConnectTCP, and AssertPing functions
