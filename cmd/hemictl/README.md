## hemictl

The `hemictl` command is a generic tool to script commands to the various
daemons. The generic use is: `hemictl <daemon> <action> [json parameters]`.

`daemon` determines the default URI `hemictl` connects to. E.g. `bss` is
`ws://localhost:8081/v1/ws`.

TODO: Add environment variable override for the URI.

`action` determines which command will be called. E.g. `ping`.

`parameters` are JSON encoded parameters to the `action`. E.g. `{"timestamp":1}`.

Thus a command to a daemon can be issues as such:
```
hemictl bss ping '{"timestamp":1}'
```

Which will result in something like:
```
{
    "origintimestamp": 1,
    "timestamp": 1701091119
}
```

And example of a call with a failure:
```
hemictl bss l1tick '{"l1_height":0}'
```

```
{
    "error": {
        "timestamp": 1701091156,
        "trace": "804d952f893e686c",
        "error": "L1 tick notification with height zero"
    }
}
```

## database

`hemictl` allows direct access to the storage layer. For now it only supports
`postgres`.


```
hemictl bfgdb version
```
```
{"bfgdb_version":1}
```

Database URI may be overridden. E.g.:
```
LOGLEVEL=INFO PGURI="user=marco password=`cat ~/.pgsql-bfgdb-marco` database=bfgdb" ./bin/hemictl bfgdb version
```
