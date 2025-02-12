# Hemi Network Development Guide

This guide provides practical information for developers working with Hemi Network services, including setup instructions, integration examples, and best practices.

## Development Environment Setup

### Local Development Prerequisites

1. **Required Software**
   - Go 1.23+
   - PostgreSQL
   - Bitcoin Core
   - Electrs
   - Docker (optional, for containerized development)

2. **Environment Variables**
   ```bash
   # BFG Configuration
   export BFG_BTC_PRIVKEY="your-btc-private-key"
   export BFG_POSTGRES_URI="postgresql://user:password@localhost:5432/bfgdb"
   export BFG_BTC_START_HEIGHT=800000  # Adjust based on your needs
   export BFG_EXBTC_ADDRESS="localhost:50001"

   # POPM Configuration
   export POPM_BFG_URL="ws://localhost:8546"
   
   # BSS Configuration
   export BSS_BFG_URL="ws://localhost:8546"
   ```

## Service Integration Examples

### 1. Integrating with BFG (Bitcoin Finality Governor)

```go
package main

import (
    "context"
    "log"
    "github.com/hemilabs/heminetwork/service/bfg"
)

func main() {
    ctx := context.Background()
    
    // Initialize BFG client
    client, err := bfg.NewClient(ctx, "ws://localhost:8546")
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Subscribe to new keystones
    keystoneChan := make(chan *bfg.Keystone)
    sub, err := client.SubscribeKeystones(ctx, keystoneChan)
    if err != nil {
        log.Fatal(err)
    }
    defer sub.Unsubscribe()
    
    // Handle incoming keystones
    for keystone := range keystoneChan {
        log.Printf("New keystone received: %+v", keystone)
    }
}
```

### 2. Working with POPM (Proof-of-Proof Miner)

```go
package main

import (
    "context"
    "log"
    "github.com/hemilabs/heminetwork/service/popm"
)

func main() {
    ctx := context.Background()
    
    // Initialize POPM client
    config := popm.Config{
        BFGEndpoint: "ws://localhost:8546",
        BTCPrivKey: "your-btc-private-key",
    }
    
    client, err := popm.NewClient(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Start mining
    if err := client.StartMining(ctx); err != nil {
        log.Fatal(err)
    }
}
```

### 3. BSS (Bitcoin Secure Sequencer) Integration

```go
package main

import (
    "context"
    "log"
    "github.com/hemilabs/heminetwork/service/bss"
)

func main() {
    ctx := context.Background()
    
    // Initialize BSS client
    config := bss.Config{
        BFGEndpoint: "ws://localhost:8546",
    }
    
    client, err := bss.NewClient(ctx, config)
    if err != nil {
        log.Fatal(err)
    }
    defer client.Close()
    
    // Submit transaction
    tx := &bss.Transaction{
        // Transaction details
    }
    
    txHash, err := client.SubmitTransaction(ctx, tx)
    if err != nil {
        log.Fatal(err)
    }
    
    log.Printf("Transaction submitted: %s", txHash)
}
```

## Development Best Practices

### 1. Error Handling

```go
// Always use proper error wrapping
if err != nil {
    return fmt.Errorf("failed to initialize client: %w", err)
}

// Use custom error types for specific errors
type KeystoneValidationError struct {
    Reason string
}

func (e *KeystoneValidationError) Error() string {
    return fmt.Sprintf("keystone validation failed: %s", e.Reason)
}
```

### 2. Logging and Monitoring

```go
// Structured logging
logger := log.With().
    Str("service", "bfg").
    Str("version", version).
    Logger()

logger.Info().
    Str("keystone_hash", hash).
    Int("block_height", height).
    Msg("New keystone processed")

// Metrics collection
metrics.Counter("keystones_processed").Inc()
metrics.Gauge("block_height").Set(float64(height))
```

### 3. Testing

```go
func TestKeystoneValidation(t *testing.T) {
    tests := []struct {
        name     string
        keystone *Keystone
        wantErr  bool
    }{
        {
            name: "valid keystone",
            keystone: &Keystone{
                // Test data
            },
            wantErr: false,
        },
        // Add more test cases
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateKeystone(tt.keystone)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateKeystone() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}
```

## Common Development Tasks

### 1. Database Migrations

```sql
-- Example migration for BFG database
CREATE TABLE keystones (
    id SERIAL PRIMARY KEY,
    hash BYTEA NOT NULL,
    height INTEGER NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    data JSONB NOT NULL
);

CREATE INDEX idx_keystones_height ON keystones(height);
```

### 2. Configuration Management

```go
type Config struct {
    BTCNetwork    string `env:"BTC_NETWORK" envDefault:"testnet"`
    BTCStartHeight int64  `env:"BTC_START_HEIGHT,required"`
    PostgresURI   string `env:"POSTGRES_URI,required"`
    LogLevel      string `env:"LOG_LEVEL" envDefault:"info"`
}

func LoadConfig() (*Config, error) {
    cfg := &Config{}
    if err := env.Parse(cfg); err != nil {
        return nil, fmt.Errorf("failed to parse config: %w", err)
    }
    return cfg, nil
}
```

## Troubleshooting Development Issues

### 1. Common Issues and Solutions

- **Connection Issues**
  ```bash
  # Check BFG connectivity
  curl -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"bfg_version","params":[],"id":1}' \
    http://localhost:8546
  ```

- **Database Issues**
  ```bash
  # Verify PostgreSQL connection
  psql $BFG_POSTGRES_URI -c "SELECT version();"
  ```

### 2. Debugging Tools

```go
// Debug logging
debug.Printf("Processing keystone: %+v", keystone)

// Trace execution
trace.Start(os.Stderr)
defer trace.Stop()

// Profile CPU usage
pprof.StartCPUProfile(os.Stderr)
defer pprof.StopCPUProfile()
```

## Performance Optimization Tips

1. **Connection Pooling**
   ```go
   pool, err := pgxpool.Connect(context.Background(), postgresURI)
   if err != nil {
       log.Fatal(err)
   }
   defer pool.Close()
   ```

2. **Caching**
   ```go
   cache := ttlcache.NewCache[string, *Keystone]()
   cache.SetTTL(time.Hour)
   ```

3. **Batch Processing**
   ```go
   batch := &pgx.Batch{}
   for _, keystone := range keystones {
       batch.Queue("INSERT INTO keystones ...", keystone.Hash, keystone.Height)
   }
   results := pool.SendBatch(context.Background(), batch)
   defer results.Close()
   ```

## Security Considerations

1. **Input Validation**
   ```go
   func validateInput(input string) error {
       if len(input) > MaxInputLength {
           return ErrInputTooLong
       }
       if !inputPattern.MatchString(input) {
           return ErrInvalidFormat
       }
       return nil
   }
   ```

2. **Rate Limiting**
   ```go
   limiter := rate.NewLimiter(rate.Every(time.Second), 10)
   if !limiter.Allow() {
       return ErrRateLimitExceeded
   }
   ```

Remember to always follow these best practices and guidelines when developing for the Hemi Network. This will ensure consistency, reliability, and security across all services. 
