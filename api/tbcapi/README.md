# Hemi Tiny Bitcoin Daemon RPC

*Last updated April 24th, 2024.*

When the `TBC_ADDRESS` environment variable is set, the `tbcd` daemon listens on the provided address.
The RPC protocol is WebSocket-based and uses a standard request/response model.

[`hemictl`](../../cmd/hemictl) is a reference implementation of an RPC client.

[View the raw Go types used in TBC's RPC commands `api/tbcapi/tbcapi.go`](tbcapi.go).

## Protocol

Please see [protocol/README.md](../protocol/README.md) for more information about the underlying RPC protocol.

### Serialised types

#### Block Header

A serialised block header contains the following data:

- `version` is the version of the block.
- `prev_hash` is the hash of the previous block header in the blockchain.
- `merkle_root` is the merkle tree reference to hash of all transactions for the block.
- `timestamp` is the time the block was created, represented in Unix seconds.
- `bits` is the difficulty target for the block.
- `nonce` is the nonce used to generate the block.

#### Address

An address is an encoded Bitcoin address.
Supported address types are P2PKH, P2SH, P2WPKH, P2WSH, and P2TR.

#### UTXO

A serialised UTXO contains the following data:

- `tx_id` is the transaction ID encoded as a hexadecimal string.
- `value` is the value of the UTXO.
- `out_index` is the output index for the UTXO.

#### Transaction

A serialised transaction contains the following data:

- `version` is the transaction version.
- `lock_time` is the block height or timestamp at which the transaction becomes final.
- `tx_in` is an array of [transaction inputs](#transaction-input).
- `tx_out` is an array of [transaction outputs](#transaction-output).

#### Transaction Input

A serialised transaction input contains the following data:

- `outpoint` is the [outpoint](#outpoint) for the previous transaction output.
- `signature_script` is the signature script for the transaction.
- `witness` is an array of the transaction witnesses, encoded as hexadecimal strings.
- `sequence` is the transaction sequence number.

#### Transaction Output

A serialised transaction output contains the following data:

- `value` is the value of the transaction output in satoshis.
- `pk_script` is the pubkey script of the transaction output, encoded as a hexadecimal string.

#### Outpoint

A serialised outpoint contains the following data:

- `hash` is the ID of the transaction holding the output to be spent.
- `index` is the index of the specific output to spend from the transaction.

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

- `height` is the height at which block headers should be retrieved.

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

##### Example

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

##### Example

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

## Balance by Address

Retrieve the balance for an address.

### Raw

| Type     | `command` value                      |
|----------|--------------------------------------|
| Request  | `tbcapi-balance-by-address-request`  |
| Response | `tbcapi-balance-by-address-response` |

#### Request

##### Payload

- `address` is the [address](#address) the balance should be retrieved for.

##### Example

An example request to retrieve the balance for the address `myqzZmRvoXmrhsrM5STiMGtNRxCFArHWRd`:

```json
{
  "header": {
    "command": "tbcapi-balance-by-address-request",
    "id": "68656d69"
  },
  "payload": {
    "address": "mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa"
  }
}
```

#### Response

##### Payload

- `balance` is the known balance of the address, in satoshis.

##### Example

An example response for a request with id `68656d69`, if the address's balance is zero:

```json
{
  "header": {
    "command": "tbcapi-balance-by-address-response",
    "id": "68656d69"
  },
  "payload": {
    "balance": 0
  }
}
```

## UTXOs by Address

### Raw data

| Type     | `command` value                        |
|----------|----------------------------------------|
| Request  | `tbcapi-utxos-by-address-raw-request`  |
| Response | `tbcapi-utxos-by-address-raw-response` |

#### Request

##### Payload

- `address` is the [address](#address) to retrieve the UTXOs for.
- `start` is the start index for the UTXOs that should be included in the response (or the number of UTXOs that should be skipped).
- `count` is the maximum number of UTXOs that should be included in the response.

##### Example

An example request to retrieve five UTXOs for the address `mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa`:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "address": "mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa",
    "start": 0,
    "count": 5
  }
}
```

#### Response

##### Payload

- `utxos` is an array of known UTXOs for the address, encoded as hexadecimal strings, or `null` if there are no UTXOs
  for the address.

##### Example

An example response for a request with id `68656d69`, requesting five UTXOs for the
address `mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa`:

```json
TODO
```

### Serialised

| Type     | `command` value                    |
|----------|------------------------------------|
| Request  | `tbcapi-utxos-by-address-request`  |
| Response | `tbcapi-utxos-by-address-response` |

#### Request

##### Payload

- `address` is the [address](#address) to retrieve the UTXOs for.
- `start` is the start index for the UTXOs that should be included in the response (or the number of UTXOs that should be skipped).
- `count` is the maximum number of UTXOs that should be included in the response.

##### Example

An example request to retrieve five UTXOs for the address `mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa`:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "address": "mhAfMWDjd8YV3RoWcpHSzqjkWi6q5Bfixa",
    "start": 0,
    "count": 5
  }
}
```

#### Response

##### Payload

- `utxos` is an array of known [UTXOs](#utxo). The maximum number of items in this array can be changed
  with `count` in the request.

##### Example

An example response for a request with id `68656d69`, if the best height was `2587400`:

```json
TODO
```

## Transaction by ID

### Raw data

| Type     | `command` value                 |
|----------|---------------------------------|
| Request  | `tbcapi-tx-by-id-raw-request`   |
| Response | `ttbcapi-tx-by-id-raw-response` |

#### Request

##### Payload

- `tx_id` is the ID of the transaction to retrieve, encoded as a hexadecimal string.

##### Example

An example request to retrieve the transaction `ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "tx_id": "ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405"
  }
}
```

#### Response

##### Payload

- `tx` is the transaction, encoded as a hexadecimal string.

##### Example

An example response for a request with id `68656d69`, requesting the
transaction `ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405`:

```json
TODO
```

### Serialised

| Type     | `command` value            |
|----------|----------------------------|
| Request  | `tbcapi-tx-by-id-request`  |
| Response | `tbcapi-tx-by-id-response` |

#### Request

##### Payload

- `tx_id` is the ID of the transaction to retrieve, encoded as a hexadecimal string.

##### Example

An example request to retrieve the transaction `ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-request",
    "id": "68656d69"
  },
  "payload": {
    "tx_id": "ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405"
  }
}
```

#### Response

##### Payload

- `tx` is the requested [transaction](#transaction), if found, otherwise `null`.

##### Example

An example response for a request with id `68656d69`, requesting the
transaction `ac583148a532c94132adc09572ee075dab86c9f72620952b703819bf53ad8405`:

```json
TODO
```
