# RPC Protocol

The RPC protocol used by Hemi's daemons is WebSocket-based and uses JSON-encoded request/responses.
The JSON data sent over WebSocket connections are called a "messages".

## Message format

An RPC message has the format:

```json
{
  "header": {
    "command": "command-name",
    "id": "request-id"
  },
  "payload": null
}
```

### Header

The message header contains metadata:

- `command` is the name of the command being called.
- `id` is a string used to uniquely identify each request. Responses will have the same `id` as the request,
  making it possible to match requests to responses. Message IDs should be randomly generated.

### Payload

The payload type depends on the command being called. Please refer to the documentation for specific API you wish to use.
