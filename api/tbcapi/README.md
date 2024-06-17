# 📡 Hemi Tiny Bitcoin Daemon RPC

***Last updated:** May 16th, 2024*

This document provides details on the RPC protocol and available commands for the Hemi Tiny Bitcoin Daemon (`tbcd`).

<details>
  <summary>Table of Contents</summary>

<!-- TOC -->
* [📡 Hemi Tiny Bitcoin Daemon RPC](#-hemi-tiny-bitcoin-daemon-rpc)
  * [⚙️ Implementations](#-implementations)
    * [⚙️ `tbcd` Daemon](#-tbcd-daemon)
    * [👉 RPC Client](#-rpc-client)
  * [📚 Resources](#-resources)
  * [📡 Protocol](#-protocol)
    * [🚫 Errors](#-errors)
    * [🗄️ Serialized Types](#-serialized-types)
      * [Block Header](#block-header)
      * [Address](#address)
      * [UTXO](#utxo)
      * [Transaction](#transaction)
      * [Transaction Input](#transaction-input)
      * [Transaction Output](#transaction-output)
      * [Outpoint](#outpoint)
  * [👉 Block Headers by Height](#-block-headers-by-height)
    * [🗂 Raw Data](#-raw-data)
      * [📤 Request](#-request)
        * [Payload](#payload)
        * [Example Request](#example-request)
      * [📥 Response](#-response)
        * [Payload](#payload-1)
        * [Example Response](#example-response)
    * [🗂 Serialized Data](#-serialized-data)
      * [📤 Request](#-request-1)
        * [Payload](#payload-2)
        * [Example Request](#example-request-1)
      * [📥 Response](#-response-1)
        * [Payload](#payload-3)
        * [Example Response](#example-response-1)
  * [👉 Best Block Header](#-best-block-header)
    * [🗂 Raw Data](#-raw-data-1)
      * [📤 Request](#-request-2)
        * [Example Request](#example-request-2)
      * [📥 Response](#-response-2)
        * [Payload](#payload-4)
        * [Example Response](#example-response-2)
      * [🗂 Serialized Data](#-serialized-data-1)
      * [📤 Request](#-request-3)
        * [Example Request](#example-request-3)
      * [📥 Response](#-response-3)
        * [Payload](#payload-5)
        * [Example Response](#example-response-3)
  * [👉 Balance by Address](#-balance-by-address)
    * [🗂 Raw Data](#-raw-data-2)
      * [📤 Request](#-request-4)
        * [Payload](#payload-6)
        * [Example Request](#example-request-4)
      * [📥 Response](#-response-4)
        * [Payload](#payload-7)
        * [Example Response](#example-response-4)
  * [👉 UTXOs by Address](#-utxos-by-address)
    * [🗂 Raw Data](#-raw-data-3)
      * [📤 Request](#-request-5)
        * [Payload](#payload-8)
        * [Example Request](#example-request-5)
      * [📥 Response](#-response-5)
        * [Payload](#payload-9)
        * [Example Response](#example-response-5)
    * [🗂 Serialized Data](#-serialized-data-2)
      * [📤 Request](#-request-6)
        * [Payload](#payload-10)
        * [Example Request](#example-request-6)
      * [📥 Response](#-response-6)
        * [Payload](#payload-11)
        * [Example Response](#example-response-6)
  * [👉 Transaction by ID](#-transaction-by-id)
    * [🗂 Raw Data](#-raw-data-4)
      * [📤 Request](#-request-7)
        * [Payload](#payload-12)
      * [📥 Response](#-response-7)
        * [Payload](#payload-13)
        * [Example Response](#example-response-7)
    * [🗂 Serialized Data](#-serialized-data-3)
      * [📤 Request](#-request-8)
        * [Payload](#payload-14)
        * [Example Request](#example-request-7)
      * [📥 Response](#-response-8)
        * [Payload](#payload-15)
        * [Example Response](#example-response-8)
<!-- TOC -->
</details>

---

## ⚙️ Implementations

### ⚙️ `tbcd` Daemon

The `tbcd` daemon runs an RPC server that listens on the address provided by the `TBC_ADDRESS` environment variable.
You can run the `tbcd` daemon with the RPC server enabled with the following command:

```shell
TBC_ADDRESS=localhost:8082 /path/to/tbcd
```

### 👉 RPC Client

[`hemictl`](../../cmd/hemictl) serves as a reference implementation of an RPC client tailored for interacting
with the `tbcd` daemon.

---

## 📚 Resources

For developers looking to integrate or extend functionality, view the raw Go types used in TBC's RPC commands:
[View `tbcapi.go`](tbcapi.go).

---

## 📡 Protocol

The **RPC protocol** is WebSocket-based and follows a standard request/response model. For more detailed information,
refer to the [protocol documentation](../protocol/README.md).

### 🚫 Errors

If an error occurs during a request, the response payload will include an `error` value containing the following
details:

| Field       | Description                                                                          |
|-------------|--------------------------------------------------------------------------------------|
| `timestamp` | The time at which the error occurred, in Unix seconds.                               |
| `trace`     | A unique string for tracing errors between server and client (internal errors only). |
| `message`   | The error message. For internal server errors, this will read `internal error`.      |

### 🗄️ Serialized Types

#### Block Header

A serialized block header contains the following data:

| Field         | Description                                                                                                                   |
|---------------|-------------------------------------------------------------------------------------------------------------------------------|
| `version`     | The version of the block.                                                                                                     |
| `prev_hash`   | The hash of the previous block header in the blockchain, in reverse byte order and encoded as a hexadecimal string.           |
| `merkle_root` | The hash derived from the hashes of all transactions in the block, in reverse byte order and encoded as a hexadecimal string. |
| `timestamp`   | The time the miner began hashing the header, represented in Unix seconds.                                                     |
| `bits`        | The difficulty target for the block.                                                                                          |
| `nonce`       | The nonce used to create the hash that is less than or equal to the target threshold.                                         |

#### Address

Represents an encoded Bitcoin address, supporting these types:

- `P2PKH`
- `P2SH`
- `P2WPKH`
- `P2WSH`
- `P2TR`

#### UTXO

A serialized UTXO contains the following data:

| Field       | Description                                                                    |
|-------------|--------------------------------------------------------------------------------|
| `tx_id`     | The transaction ID, in reverse byte order and encoded as a hexadecimal string. |
| `value`     | The value of the UTXO.                                                         |
| `out_index` | The output index of the UTXO.                                                  |

#### Transaction

A serialized transaction contains the following data:

| Field       | Description                                                              |
|-------------|--------------------------------------------------------------------------|
| `version`   | The transaction version.                                                 |
| `lock_time` | The block height or timestamp after which the transaction becomes final. |
| `tx_in`     | An array of [**transaction inputs**](#transaction-input).                |
| `tx_out`    | An array of [**transaction outputs**](#transaction-output).              |

#### Transaction Input

A serialized transaction input contains the following data:

| Field              | Description                                                            |
|--------------------|------------------------------------------------------------------------|
| `outpoint`         | The [**outpoint**](#outpoint) for the previous transaction output.     |
| `signature_script` | The signature script for the transaction.                              |
| `witness`          | An array of the transaction witnesses, encoded as hexadecimal strings. |
| `sequence`         | The transaction sequence number.                                       |

#### Transaction Output

A serialized transaction output contains the following data:

| Field       | Description                                                                   |
|-------------|-------------------------------------------------------------------------------|
| `value`     | The value of the transaction output in satoshis.                              |
| `pk_script` | The pubkey script of the transaction output, encoded as a hexadecimal string. |

#### Outpoint

A serialized outpoint contains the following data:

| Field   | Description                                                                                                          |
|---------|----------------------------------------------------------------------------------------------------------------------|
| `hash`  | The ID of the transaction holding the output to be spent, in reverse byte order and encoded as a hexadecimal string. |
| `index` | The index of the specific output to spend from the transaction.                                                      |

---

## 👉 Block Headers by Height

Retrieve the block headers by height.

### 🗂 Raw Data

| Type     | `command` value                               |
|----------|-----------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-raw-request`  |
| Response | `tbcapi-block-headers-by-height-raw-response` |

#### 📤 Request

##### Payload

- **`height`**: The height at which block headers should be retrieved.

##### Example Request

Retrieve block headers at height `43111`:

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

#### 📥 Response

##### Payload

- **`block_headers`**: An array of raw block headers encoded as hexadecimal strings.

##### Example Response

Response for a request with **id** `68656d69` and **height** `43111`:

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

### 🗂 Serialized Data

| Type     | `command` value                           |
|----------|-------------------------------------------|
| Request  | `tbcapi-block-headers-by-height-request`  |
| Response | `tbcapi-block-headers-by-height-response` |

#### 📤 Request

##### Payload

- **`height`**: The height at which block headers should be retrieved.

##### Example Request

Retrieve block headers at height `43111`:

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

#### 📥 Response

##### Payload

- **`block_headers`**: An array of [block headers](#block-header).

##### Example Response

Response for a request with **id** `68656d69` and **height** `43111`:

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

---

## 👉 Best Block Header

Retrieve the best block headers.

### 🗂 Raw Data

| Type     | `command` value                         |
|----------|-----------------------------------------|
| Request  | `tbcapi-block-header-best-raw-request`  |
| Response | `tbcapi-block-header-best-raw-response` |

#### 📤 Request

##### Example Request

Retrieve the best block headers:

```json
{
  "header": {
    "command": "tbcapi-block-header-best-raw-request",
    "id": "68656d69"
  }
}
```

#### 📥 Response

##### Payload

- **`height`**: The best-known height.
- **`block_header`**: The best-known block header encoded as a hexadecimal string.

##### Example Response

Response for a request with **id** `68656d69` and **best height** `2182000`:

```json
{
  "header": {
    "command": "tbcapi-block-header-best-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2182000,
    "block_header": "0420002075089ac1ab1cab70cf6e6b774a86703a8d7127c0ebed1d3dfa2c00000000000086105509ec4a79457a400451290ad2a019fec4c76b47512623f1bb17a0ced76f38d82662bef4001b07d86700"
  }
}
```

#### 🗂 Serialized Data

| Type     | `command` value                     |
|----------|-------------------------------------|
| Request  | `tbcapi-block-header-best-request`  |
| Response | `tbcapi-block-header-best-response` |

#### 📤 Request

##### Example Request

Retrieve the best block headers:

```json
{
  "header": {
    "command": "tbcapi-block-header-best-request",
    "id": "68656d69"
  }
}
```

#### 📥 Response

##### Payload

- **`height`**: The best-known height.
- **`block_header`**: The best-known [block header](#block-header).

##### Example Response

Response for a request with **id** `68656d69` and **height** `2587400`:

```json
{
  "header": {
    "command": "tbcapi-block-header-best-response",
    "id": "68656d69"
  },
  "payload": {
    "height": 2587400,
    "block_header": {
      "version": 536887296,
      "prev_hash": "000000000000002bbbbec8f126dc76a82109d898383bca5013a2386c8675ce34",
      "merkle_root": "b9d74efdafb5436330b47478b2df28251057da5a9bc11c5509410950253d4f0e",
      "timestamp": 1713461092,
      "bits": "192e17d5",
      "nonce": 3365605040
    }
  }
}
```

## 👉 Balance by Address

Retrieve the balance for an address.

### 🗂 Raw Data

| Type     | `command` value                      |
|----------|--------------------------------------|
| Request  | `tbcapi-balance-by-address-request`  |
| Response | `tbcapi-balance-by-address-response` |

#### 📤 Request

##### Payload

- **`address`**: The [address](#address) for which the balance should be retrieved.

##### Example Request

Retrieve the balance for the address `myqzZmRvoXmrhsrM5STiMGtNRxCFArHWRd`:

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

#### 📥 Response

##### Payload

- **`balance`**: The known balance of the address, in satoshis.

##### Example Response

Response for a request with **id** `68656d69`, if the address's **balance** is `0`:

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

---

## 👉 UTXOs by Address

Retrieve UTXOs by address.

### 🗂 Raw Data

| Type     | `command` value                        |
|----------|----------------------------------------|
| Request  | `tbcapi-utxos-by-address-raw-request`  |
| Response | `tbcapi-utxos-by-address-raw-response` |

#### 📤 Request

##### Payload

- **`address`**: The [address](#address) to retrieve the UTXOs for.
- **`start`**: The start index for the UTXOs that should be included in the response (or the number of UTXOs that should
  be skipped).
- **`count`**: The maximum number of UTXOs that should be included in the response.

##### Example Request

Retrieve five UTXOs for the address `mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk`:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "address": "mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk",
    "start": 0,
    "count": 5
  }
}
```

#### 📥 Response

##### Payload

- **`utxos`**: An array of **known UTXOs** for the address, encoded as hexadecimal strings, or **`null`** if there are *
  *no UTXOs** for the address.

##### Example Response

Response for a request with **id** `68656d69`, **requesting 5 UTXOs** for the
address `mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk`:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "utxos": [
      "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a770000000000000cab00000002",
      "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a770000000000000cab00000002",
      "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a770000000000000cab00000002",
      "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a770000000000000cab00000002",
      "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a770000000000000cab00000002"
    ]
  }
}
```

### 🗂 Serialized Data

| Type     | `command` value                    |
|----------|------------------------------------|
| Request  | `tbcapi-utxos-by-address-request`  |
| Response | `tbcapi-utxos-by-address-response` |

#### 📤 Request

##### Payload

- **`address`**: The [address](#address) to retrieve the UTXOs for.
- **`start`**: The start index for the UTXOs that should be included in the response (or the number of UTXOs that should
  be skipped).
- **`count`**: The maximum number of UTXOs that should be included in the response.

##### Example Request

**Retrieve 5 UTXOs** for the address `mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk`:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-request",
    "id": "68656d69"
  },
  "payload": {
    "address": "mxVFsFW5N4mu1HPkxPttorvocvzeZ7KZyk",
    "start": 0,
    "count": 5
  }
}
```

#### 📥 Response

##### Payload

- **`utxos`**: An array of known [**UTXOs**](#utxo). The maximum number of items in this array can be changed with *
  *`count`** in the request.

##### Example Response

Response for a request with **id** `68656d69`, **showing 5 UTXOs** for the address:

```json
{
  "header": {
    "command": "tbcapi-utxos-by-address-response",
    "id": "68656d69"
  },
  "payload": {
    "utxos": [
      {
        "tx_id": "0012a33f3c301c90427d81f256d8a4848dcbfc289e8325725e7657e9a643d6fd",
        "value": 2026,
        "out_index": 1
      },
      {
        "tx_id": "0066c9f87d012e75e390adb490794a746fefe05eb16d220515788f33d5b6b336",
        "value": 10000,
        "out_index": 1
      },
      {
        "tx_id": "0066c9f87d012e75e390adb490794a746fefe05eb16d220515788f33d5b6b336",
        "value": 10000,
        "out_index": 2
      },
      {
        "tx_id": "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a77",
        "value": 3243,
        "out_index": 1
      },
      {
        "tx_id": "0073700282db1dcc4853dc64e5da5c8595d1204ea7d036b04ea6b8ba41093a77",
        "value": 3243,
        "out_index": 2
      }
    ]
  }
}
```

---

## 👉 Transaction by ID

### 🗂 Raw Data

| Type     | `command` value                 |
|----------|---------------------------------|
| Request  | `tbcapi-tx-by-id-raw-request`   |
| Response | `ttbcapi-tx-by-id-raw-response` |

#### 📤 Request

##### Payload

- **`tx_id`**: The ID of the transaction to retrieve, encoded as a hexadecimal string.

An example request to retrieve the transaction `0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-raw-request",
    "id": "68656d69"
  },
  "payload": {
    "tx_id": "0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac"
  }
}
```

#### 📥 Response

##### Payload

- **`tx`**: The transaction (encoded as a hexadecimal string).

##### Example Response

An example response for a request with id `68656d69`, requesting the
transaction `0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-raw-response",
    "id": "68656d69"
  },
  "payload": {
    "tx": "02000000019554a7eb8bc903ea957c87964ab04a58d177692f15d7271cccb95258202f14b5bd00000000fdffffff014a010000000000002251208ec88237b5978e75e93feaeeb1343ff86ae2f2c348a903c9c9c4ad081926773500000000"
  }
}
```

### 🗂 Serialized Data

| Type     | `command` value            |
|----------|----------------------------|
| Request  | `tbcapi-tx-by-id-request`  |
| Response | `tbcapi-tx-by-id-response` |

#### 📤 Request

##### Payload

- **`tx_id`**: The ID of the transaction to retrieve, in reverse byte order and encoded as a hexadecimal string.

##### Example Request

An example request to retrieve the transaction `0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-request",
    "id": "68656d69"
  },
  "payload": {
    "tx_id": "0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac"
  }
}
```

#### 📥 Response

##### Payload

- **`tx`**: The requested [transaction](#transaction), if found, otherwise **`null`**.

##### Example Response

An example response for a request with id `68656d69`, requesting the
transaction `0584ad53bf1938702b952026f7c986ab5d07ee7295c0ad3241c932a5483158ac`:

```json
{
  "header": {
    "command": "tbcapi-tx-by-id-response",
    "id": "68656d69"
  },
  "payload": {
    "tx": {
      "version": 2,
      "lock_time": 0,
      "tx_in": [
        {
          "outpoint": {
            "hash": "9554a7eb8bc903ea957c87964ab04a58d177692f15d7271cccb95258202f14b5",
            "index": 189
          },
          "signature_script": "",
          "tx_witness": null,
          "sequence": 4294967293
        }
      ],
      "tx_out": [
        {
          "value": 330,
          "pk_script": "51208ec88237b5978e75e93feaeeb1343ff86ae2f2c348a903c9c9c4ad0819267735"
        }
      ]
    }
  }
}
```
