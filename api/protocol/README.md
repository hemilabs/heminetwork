# 👉 RPC Protocol

The **RPC protocol** used by Hemi's daemons is WebSocket-based and uses **JSON-encoded requests/responses**.

The JSON data sent over WebSocket connections are referred to as **"messages"**.

---
## 📩 Message Format

Every RPC message has the following format:

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

The message header includes metadata crucial for processing the message:

- **`command`**: Specifies the command being executed.
- **`id`**: A string used to uniquely identify each request. Responses will have the same `id` as the request, making it possible to match requests to responses.

  > [!NOTE]
  > Message IDs should be randomly generated.

### Payload

The payload type depends on the command being called. Please refer to the documentation for more details on the specific API you wish to use.

---
## 📄 License

This project is licensed under the [MIT License](../../LICENSE).
