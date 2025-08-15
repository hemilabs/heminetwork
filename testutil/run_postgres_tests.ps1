# PostgreSQL Test Runner Script
# This script helps set up and run PostgreSQL tests

param(
    [string]$Method = "skip",
    [string]$PGURI = ""
)

Write-Host "=== PostgreSQL Test Runner ===" -ForegroundColor Green

# Check if Go is available
try {
    $goVersion = go version
    Write-Host "✓ Go found: $goVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Go not found. Please install Go first." -ForegroundColor Red
    exit 1
}

# Method 1: Skip database tests (default)
if ($Method -eq "skip") {
    Write-Host "Running tests without PostgreSQL (database tests will be skipped)..." -ForegroundColor Yellow
    go test ./testutil -v
    exit 0
}

# Method 2: Use provided PostgreSQL URI
if ($Method -eq "uri" -and $PGURI) {
    Write-Host "Using provided PostgreSQL URI..." -ForegroundColor Yellow
    $env:PGTESTURI = $PGURI
    go test ./testutil -v
    exit 0
}

# Method 3: Try to find and use local PostgreSQL
if ($Method -eq "local") {
    Write-Host "Attempting to use local PostgreSQL..." -ForegroundColor Yellow
    
    # Check if PostgreSQL service is running
    try {
        $pgService = Get-Service -Name "postgresql*" -ErrorAction SilentlyContinue
        if ($pgService -and $pgService.Status -eq "Running") {
            Write-Host "✓ PostgreSQL service is running" -ForegroundColor Green
            
            # Try default connection
            $env:PGTESTURI = "postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"
            Write-Host "Testing with default connection..." -ForegroundColor Yellow
            go test ./testutil -v
            exit 0
        } else {
            Write-Host "✗ PostgreSQL service not found or not running" -ForegroundColor Red
        }
    } catch {
        Write-Host "✗ Could not check PostgreSQL service" -ForegroundColor Red
    }
}

# Method 4: Docker (if available)
if ($Method -eq "docker") {
    Write-Host "Attempting to use Docker..." -ForegroundColor Yellow
    
    try {
        $dockerVersion = docker --version
        Write-Host "✓ Docker found: $dockerVersion" -ForegroundColor Green
        
        # Check if postgres-test container exists
        $containerExists = docker ps -a --filter "name=postgres-test" --format "{{.Names}}"
        if ($containerExists -eq "postgres-test") {
            Write-Host "✓ PostgreSQL container exists, starting it..." -ForegroundColor Green
            docker start postgres-test
        } else {
            Write-Host "Creating PostgreSQL container..." -ForegroundColor Yellow
            docker run --name postgres-test -e POSTGRES_PASSWORD=testpass -e POSTGRES_USER=testuser -e POSTGRES_DB=postgres -p 5432:5432 -d postgres:15
        }
        
        # Wait a moment for PostgreSQL to start
        Start-Sleep -Seconds 5
        
        $env:PGTESTURI = "postgres://testuser:testpass@localhost:5432/postgres?sslmode=disable"
        Write-Host "Running tests with Docker PostgreSQL..." -ForegroundColor Yellow
        go test ./testutil -v
        exit 0
        
    } catch {
        Write-Host "✗ Docker not available or failed" -ForegroundColor Red
    }
}

# If we get here, show usage
Write-Host "Usage:" -ForegroundColor Cyan
Write-Host "  .\run_postgres_tests.ps1                    # Skip database tests (default)" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method skip      # Skip database tests" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method local     # Try local PostgreSQL" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method docker    # Use Docker PostgreSQL" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method uri -PGURI 'your-connection-string'" -ForegroundColor White
Write-Host ""
Write-Host "Examples:" -ForegroundColor Cyan
Write-Host "  .\run_postgres_tests.ps1" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method docker" -ForegroundColor White
Write-Host "  .\run_postgres_tests.ps1 -Method uri -PGURI 'postgres://user:pass@localhost:5432/db'" -ForegroundColor White

