## hemictl

The `hemictl` command is a generic tool to manipulate script commands to various daemons and their internal framework.

### Usage
```bash
hemictl <command> <action> [parameters]
```

### Components

- `command`: Determines the daemon / module to be manipulated (e.g., `tbcdb` is used to manipulated a TBC database)
- `action`: Specifies which command will be called (e.g., `ping`)
- `parameters`: Key-value pair or JSON encoded parameters for the `action` (e.g., `timestamp=1` or `{"timestamp":1}`)

### Environment Variables

- `HEMICTL_LOG_LEVEL`: Sets the logging level (e.g., `INFO`, `DEBUG`)
- `HEMICTL_LEVELDB_HOME`: The tbcdb leveldb home directory (default: `~/.tbcd`)
- `HEMICTL_NETWORK`: Bitcoin network (e.g., `mainnet`, `testnet3`)

### Detailed Overview

For a detailed overview of the available modules, use:
```bash
hemictl -help
```

For a detailed overview of a specific module's subcommands, use:
```bash
hemictl <command> -help
```

### Error Handling

The tool provides detailed error messages with:
- Timestamp of the error
- Trace ID for debugging
- Human-readable error message

### Notes
- Always ensure proper formatting in parameters
- Use appropriate environment variables for production deployments
- Check logs when troubleshooting failed commands
