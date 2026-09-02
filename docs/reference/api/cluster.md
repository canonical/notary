# Cluster

Cluster operations follow the same shape as LXD: named members, a join token from `add`, and `remove`. Admin only. The daemon must be running.

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
            "role": "voter",
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

`name` is accepted as an alias of `server_name`.

### Sample Response

```json
{
    "data": {
        "server_name": "node2",
        "join_token": "eyJ..."
    }
}
```

Start the new node with `notary start --config ... --join <token>`.

## Remove a member

| Method   | Path                               |
| :------- | :--------------------------------- |
| `DELETE` | `/api/v1/cluster/members/{name}`   |

Cannot remove the last remaining member.

From the host you can also run:

```shell
notary cluster add node2 --config /path/to/config.yaml
notary cluster list --config /path/to/config.yaml
notary cluster remove node2 --config /path/to/config.yaml
```
