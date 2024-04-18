# Hemi Tiny Bitcoin Daemon RPC

*Last updated April 19th, 2024.*

When the `TBC_ADDRESS` environment variable is set, the `tbcd` daemon listens on the provided address.
The RPC protocol is WebSocket-based and uses a standard request/response model.

[`hemictl`](../../cmd/hemictl) is a reference implementation of an RPC client.

## Protocol

Please see [protocol/README.md](../protocol/README.md) for more information about the underlying RPC protocol.

### Serialised types

#### Block Header

A serialised block header has the following data:

- `version` is the version of the block.
- `prev_hash` is the hash of the previous block header in the blockchain.
- `merkle_root` is the merkle tree reference to hash of all transactions for the block.
- `timestamp` is the time the block was created, represented in Unix seconds.
- `bits` is the difficulty target for the block.
- `nonce` is the nonce used to generate the block.

## Block Headers by Height

### Raw data

| Type     | `command` value                               |
|----------|-----------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-raw-request`  |
| Response | `tbcapi-block-headers-by-height-raw-response` |

#### Request

##### Payload

- `height` is the height to at which block headers should be retrieved.

##### Example

An example request to retrieve block headers at height `43111`:

```json
{
  "header": {
    "command": "tbcapi-block-headers-by-height-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "height": 43111
  }
}
```

#### Response

##### Payload

- `block_headers` is an array of raw block headers encoded as hexadecimal strings.

##### Example

An example response for a request with id `68656d69` and height `43111`:

```json
{
  "header": {
    "command": "tbcapi-block-headers-by-height-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "block_headers": [
      "02000000cf31d5156c8ab752b91874d1072d4673b83ee3ed718d3cb4f461c410000000000ca43abadf59bee614186d30da42f56932dc2a53e6d920169b8577207f7b11fcfec3d750c0ff3f1c4f428f6a"
    ]
  }
}
```

### Serialised

| Type     | `command` value                           |
|----------|-------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-request`  |
| Response | `tbcapi-block-headers-by-height-response` |

#### Request

##### Payload

- `height` is the height to at which block headers should be retrieved.

##### Example

An example request to retrieve the block headers at height `43111`:

```json
{
  "header": {
    "command": "tbcapi-block-headers-by-height-request",
    "id": "68656d69"
  },
  "payload": {
    "height": 43111
  }
}
```

#### Response

##### Payload

- `block_headers` is an array of [block headers](#block-header).

##### Example

An example response for a request with id `68656d69` and height `43111`:

```json
{
  "header": {
    "command": "tbcapi-block-headers-by-height-response",
    "id": "68656d69"
  },
  "payload": {
    "block_headers": [
      {
        "version": 2,
        "prev_hash": "0000000010c461f4b43c8d71ede33eb873462d07d17418b952b78a6c15d531cf",
        "merkle_root": "fc117b7f2077859b1620d9e6532adc3269f542da306d1814e6be59dfba3aa40c",
        "timestamp": 1356317694,
        "bits": "1c3fffc0",
        "nonce": 1787773519
      }
    ]
  }
}
```

## Best Block Headers

### Raw data

| Type     | `command` value                          |
|----------|------------------------------------------|
| Request  | `tbcapi-block-headers-best-raw-request`  |
| Response | `tbcapi-block-headers-best-raw-response` |

#### Request

An example request to retrieve the best block headers:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-raw-request",
    "id": "68656d69"
  }
}
```

#### Response

##### Payload

- `height` is the best known height.
- `block_headers` is an array of the best known block headers encoded as hexadecimal strings.

##### Example

An example response for a request with id `68656d69`, if the best height was `2182000`:

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

| Type     | `command` value                      |
|----------|--------------------------------------|
| Request  | `tbcapi-block-headers-best-request`  |
| Response | `tbcapi-block-headers-best-response` |

#### Request

An example request to retrieve the best block headers:

```json
{
  "header": {
    "command": "tbcapi-block-headers-best-request",
    "id": "68656d69"
  }
}
```

#### Response

##### Payload

- `height` is the best known height.
- `block_headers` is an array of best known [block headers](#block-header).

##### Example

An example response for a request with id `68656d69`, if the best height was `2587400`:

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
