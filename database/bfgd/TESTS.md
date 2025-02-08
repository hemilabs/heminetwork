# BFGD Testing Guide

## Prerequisites

Before running the tests, ensure you have:
- PostgreSQL installed and running
- Go development environment set up
- Appropriate database permissions

## Setting Up Test Environment

### 1. Create Test User

First, create a PostgreSQL user with the necessary privileges:

```bash
sudo -u postgres psql -c "CREATE ROLE bfgdtest WITH LOGIN PASSWORD 'password' NOSUPERUSER CREATEDB;"
```

### 2. Configure Environment

Set up your environment variables:

```bash
export PGTESTURI="postgres://bfgdtest:password@localhost/postgres"
```

## Running Tests

### Basic Test Execution

Run all tests with verbose output:

```bash
go test -v ./...
```

### Advanced Testing Options

#### Run Specific Tests
To run specific test cases:
```bash
go test -v -run TestName ./...
```

#### Run with Race Detection
For concurrent code testing:
```bash
go test -race -v ./...
```

#### Run with Coverage
To generate test coverage report:
```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Troubleshooting

Common issues and solutions:

1. **Database Connection Failed**
   - Verify PostgreSQL is running
   - Check user permissions
   - Confirm connection string is correct

2. **Test User Creation Failed**
   - Ensure you have superuser privileges
   - Verify PostgreSQL service status

## Best Practices

- Always clean up test data after tests
- Use meaningful test names
- Write isolated tests that don't depend on each other
- Include both positive and negative test cases

## Contributing

When adding new tests:
1. Follow existing test patterns
2. Add appropriate documentation
3. Ensure all tests are properly isolated
4. Include relevant test data setup and cleanup
