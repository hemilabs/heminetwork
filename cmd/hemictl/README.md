## hemictl

`hemictl` is a developer CLI for talking directly to Hemi daemons and their underlying databases.
Commands are grouped by subsystem (e.g. `tbcdb` for direct `tbcd` database access, `hproxy` for the
hVM proxy, `p2p` for the Bitcoin p2p network, `api`, `level`), and each group exposes a set of named
actions.

### Usage

```bash
hemictl <command> <action> [key=value...]
```

- `command`: the subsystem to talk to (e.g. `tbcdb`)
- `action`: the action to run within that subsystem (e.g. `blockheaderbyhash`)
- `key=value`: arguments for the action, passed as space-separated `key=value` pairs

Running `hemictl <command>` with no action prints the list of actions for that command, along with
their arguments and whether each is required, optional, or part of a mutually exclusive group (e.g.
`hash=` or `address=`, but not both).

### Help

```bash
hemictl -help               # list all commands
hemictl <command> -help     # list a command's actions and their arguments
```

### Environment Variables

- `HEMICTL_LOG_LEVEL`: logging level for hemictl and the services it drives (default: `hemictl=INFO;protocol=INFO`)
- `HEMICTL_LEVELDB_HOME`: leveldb home directory used by `tbcdb` (default: `~/.tbcd`)
- `HEMICTL_NETWORK`: Bitcoin network to operate on, e.g. `mainnet`, `testnet3`, `testnet4` (default: `mainnet`)

### Adding commands

New commands live in their own file under `cmd/hemictl/` and register themselves with
`registerCommand` from an `init()` function; see `tbcdb.go` or `hproxy.go` for examples.
