# tbcd

## Hemi Tiny Bitcoin Daemon

tbcd is a very minimal bitcoin block downloader and indexer meant for embedding in other applications that require access to bitcoin data (blocks and txes).

tbcd requires sufficient disk space for a full download of bitcoin block data on a fast (preferably ssd or better disk.

tbcd is build with the heminetwork makefile,  To build standalone (requires `go 1.21+`), type:

``` sh
cd heminetowkr/cmd/tbcd
go build
```

On some linux systems you may need to increase the number of open files allowed (particularly with slower disks) and the maximum stack size.  If you run into open file or OOM errors, in the shell you are going to run tbcd, run:

```sh
ulimit -n 8192
ulimit -s 8192
```

You can confirm these settings wiht:

```sh
ulimit -a
```

For a full list of options:

``` sh
./bin/tbcd --help
```

You can change the file storage with:

``` sh
export TBC_LEVELDB_HOME=/path/to/files
```

Specify the network with

``` sh
export TBC_NETWORK=mainnet
```

Then run with:

``` sh
./bin/tbcd
```

### License

This project is licensed under the [MIT License](../../LICENSE).

