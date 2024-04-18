# Hemi Tiny Bitcoin Daemon RPC

*Last updated April 19th, 2024.*

When the `TBC_ADDRESS` environment variable is set, the `tbcd` daemon listens on the provided address.
The RPC protocol is WebSocket-based and uses a standard request/response model.

[`hemictl`](../../cmd/hemictl) is a reference implementation of an RPC client.

## Protocol

Please see [protocol/README.md](../protocol/README.md) for more information about the underlying RPC protocol.

## Block Headers by Height

### Raw data

| Type     | `command` value                               |
|----------|-----------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-raw-request`  |
| Response | `tbcapi-block-headers-by-height-raw-response` |

Example request message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-raw-request",
    "id": "68656d69"
  }
}
```

Example response message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2182000,
    "block_headers": [
      "0420002075089ac1ab1cab70cf6e6b774a86703a8d7127c0ebed1d3dfa2c00000000000086105509ec4a79457a400451290ad2a019fec4c76b47512623f1bb17a0ced76f38d82662bef4001b07d86700"
    ]
  }
}
```

### Serialised

| Type     | `command` value                           |
|----------|-------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-request`  |
| Response | `tbcapi-block-headers-by-height-response` |

Example request message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-request",
    "id": "68656d69"
  }
}
```

Example response message:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2587400,
    "block_headers": [
      {
        "version": 536887296,
        "prev_hash": "000000000000002bbbbec8f126dc76a82109d898383bca5013a2386c8675ce34",
        "merkle_root": "b9d74efdafb5436330b47478b2df28251057da5a9bc11c5509410950253d4f0e",
        "timestamp": 1713461092,
        "bits": "192e17d5",
        "nonce": 3365605040
      }
    ]
  }
}
```
