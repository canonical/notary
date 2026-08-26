# Status

## Get the status

This path returns the status.

| Method | Path      |
| :----- | :-------- |
| `GET`  | `/status` |

### Parameters

None

### Sample Response

```json
{
  "data": {
    "initialized": true,
    "version": "0.0.3",
    "sealed": false,
    "node_id": "1234567890",
    "role": "voter",
    "raft_state": "leader"
  }
}
```

`sealed` reports whether this node has unwrapped its data encryption key yet. A
sealed node replicates and participates in Raft normally, but returns `503` on
every route that needs plaintext key material. It unseals itself as soon as its
configured Vault/HSM backend is reachable; there is no unseal endpoint.

`node_id`, `role` (`voter`, `standby` or `spare`) and `raft_state` (`leader`,
`follower`, `no-leader` or `unknown`) describe this node's place in the cluster.
They are omitted when clustering is disabled.
