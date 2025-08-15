# PostgreSQL Setup for Testing

This guide explains how to set up PostgreSQL to run the database tests in the `testutil` package.

## Option 1: Using Docker (Recommended)

### 1. Install Docker Desktop
Download and install Docker Desktop from: https://www.docker.com/products/docker-desktop/

### 2. Start PostgreSQL Container
```bash
docker run --name postgres-test -e POSTGRES_PASSWORD=testpass -e POSTGRES_USER=testuser -e POSTGRES_DB=postgres -p 5432:5432 -d postgres:15
```

### 3. Set Environment Variable
```bash
# Windows PowerShell
$env:PGTESTURI="postgres://testuser:testpass@localhost:5432/postgres?sslmode=disable"

# Windows Command Prompt
set PGTESTURI=postgres://testuser:testpass@localhost:5432/postgres?sslmode=disable
```

### 4. Run Tests
```bash
go test ./testutil -v
```

## Option 2: Local PostgreSQL Installation

### 1. Install PostgreSQL
- Download from: https://www.postgresql.org/download/windows/
- Or use: `winget install PostgreSQL.PostgreSQL`

### 2. Start PostgreSQL Service
```bash
# Check if service is running
Get-Service postgresql*

# Start if needed
Start-Service postgresql*
```

### 3. Create Test User and Database
```bash
# Connect to PostgreSQL as superuser
psql -U postgres

# In psql, create test user and database
CREATE USER testuser WITH PASSWORD 'testpass';
CREATE DATABASE testdb OWNER testuser;
GRANT ALL PRIVILEGES ON DATABASE testdb TO testuser;
\q
```

### 4. Set Environment Variable
```bash
$env:PGTESTURI="postgres://testuser:testpass@localhost:5432/testdb?sslmode=disable"
```

### 5. Run Tests
```bash
go test ./testutil -v
```

## Option 3: Skip Database Tests

If you don't want to set up PostgreSQL, the tests will be skipped automatically:

```bash
go test ./testutil -v
# Output: "PGTESTURI environment variable is not set, skipping..."
```

## Troubleshooting

### Connection Issues
- Ensure PostgreSQL is running on port 5432
- Check firewall settings
- Verify the connection string format

### Permission Issues
- Make sure the test user has sufficient privileges
- Check that the database exists and is accessible

### Schema Issues
- The tests automatically apply SQL schema files from `database/bfgd/scripts/`
- Ensure all required SQL files are present

## Test Functions

The following test functions require PostgreSQL:
- `TestCreateTestDB`
- `TestL2KeystonesCount` 
- `TestApplySQLFiles`
- `TestDatabaseOperations`

These tests will be skipped if `PGTESTURI` is not set.
