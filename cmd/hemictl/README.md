## hemictl

The `hemictl` command is a generic tool to script commands to various daemons.

### Usage
```bash
hemictl <daemon> <action> [json parameters]
```

### Components

- `daemon`: Determines the default URI `hemictl` connects to (e.g., `bss` connects to `ws://localhost:8081/v1/ws`)
- `action`: Specifies which command will be called (e.g., `ping`)
- `parameters`: JSON encoded parameters for the `action` (e.g., `{"timestamp":1}`)

### Environment Variables

- `LOGLEVEL`: Sets the logging level (e.g., `INFO`, `DEBUG`)
- `PGURI`: Override database connection URI for database operations
- `HEMI_URI`: Override default daemon URI (format: `ws://host:port/v1/ws`)

### Examples

#### Basic Ping Command
```bash
hemictl bss ping '{"timestamp":1}'
```

Response:
```json
{
    "origintimestamp": 1,
    "timestamp": 1701091119
}
```

#### Error Handling Example
```bash
hemictl bss l1tick '{"l1_height":0}'
```

Response:
```json
{
    "error": {
        "timestamp": 1701091156,
        "trace": "804d952f893e686c",
        "error": "L1 tick notification with height zero"
    }
}
```

### Database Operations

`hemictl` provides direct access to the storage layer, currently supporting PostgreSQL.

#### Check Database Version
```bash
hemictl bfgdb version
```

Response:
```json
{"bfgdb_version":1}
```

#### Custom Database Connection
```bash
LOGLEVEL=INFO PGURI="user=username password=secretpassword database=bfgdb" hemictl bfgdb version
```

### Error Handling

The tool provides detailed error messages with:
- Timestamp of the error
- Trace ID for debugging
- Human-readable error message

### Notes
- Always ensure proper JSON formatting in parameters
- Use appropriate environment variables for production deployments
- Check logs when troubleshooting failed commands
