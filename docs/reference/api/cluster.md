# Cluster

Cluster operations follow the same shape as LXD: named members, a join token from `add`, and `remove`. Listing, adding, and removing members are admin only. Redeeming a join token (`POST /api/v1/cluster/join`) is how a new node collects cluster TLS; it does not use an admin session. The daemon must be running.

## List members

| Method | Path                      |
| :----- | :------------------------ |
| `GET`  | `/api/v1/cluster`         |
| `GET`  | `/api/v1/cluster/members` |

### Sample Response

```json
{
    "data": [
        {
            "name": "node1",
            "id": 1,
            "address": "10.0.0.1:9000",
            "role": "voter",
            "leader": true
        },
        {
            "name": "node2",
            "id": 123456,
            "address": "10.0.0.2:9000",
            "role": "spare",
            "leader": false
        }
    ]
}
```

## Add a member (join token)

Creates a one-time join token for a new member, like `lxc cluster add`.

| Method | Path                      |
| :----- | :------------------------ |
| `POST` | `/api/v1/cluster/members` |

### Sample Request

```json
{
    "server_name": "node2"
}
```

`name` is not accepted; use `server_name`.

### Sample Response

```json
{
    "data": {
        "server_name": "node2",
        "join_token": "eyJ..."
    }
}
```

Start the new node with `notary start --config ... --join <token>`. The token is a one-time ticket. The joiner redeems it at `POST /api/v1/cluster/join` (no admin cookie) over HTTPS, pinning the server with the token fingerprint, and receives cluster TLS there.

## Redeem a join token

| Method | Path                    |
| :----- | :---------------------- |
| `POST` | `/api/v1/cluster/join`  |

Unauthenticated. Body: `{"join_token": "<token>"}`. Consumes the token and returns `cluster_certificate`, `cluster_private_key`, and dqlite `addresses`. Used by `notary start --join`; you should not need to call this by hand. Until redeem or expiry, the token is a bearer credential for that response. Missing, expired, and incorrect tokens all return the same error.

## Remove a member

| Method   | Path                               |
| :------- | :--------------------------------- |
| `DELETE` | `/api/v1/cluster/members/{name}`   |

`{name}` may be the member name or its dqlite address. Cannot remove the last remaining member.

From the host you can also run:

```shell
notary cluster add node2 --config /path/to/config.yaml
notary cluster list --config /path/to/config.yaml
notary cluster remove node2 --config /path/to/config.yaml
```
