# Cluster

These paths manage the dqlite cluster backing a highly available Notary deployment. They return
`404` when clustering is disabled, that is, when `cluster.enabled` is not `true` in the
[configuration file](../config_file.md).

Every path below requires an admin token, with one deliberate exception:
`POST /cluster/members/join` is not authenticated. A node that has not joined yet has no account on
the cluster it is joining, so requiring one would make joining impossible. The single-use,
time-limited, identity-bound join token in the request body is that path's only credential. It
authorizes schema preflight and returns peer addresses; it does not issue certificates and is not
the dqlite membership boundary.

## List the cluster members

This path returns every member of the cluster.

| Method | Path                |
| :----- | :------------------ |
| `GET`  | `/cluster/members`  |

### Parameters

None

### Sample Response

```json
{
  "data": [
    {
      "id": "3297041220608546238",
      "name": "notary-1",
      "address": "10.0.0.1:9000",
      "role": "voter",
      "leader": true,
      "sealed": false,
      "last_seen": 1787569731,
      "status": "ONLINE",
      "message": "Fully operational"
    }
  ]
}
```

`role` is `voter`, `standby` or `spare`, and `leader` marks the member currently leading the Raft
cluster.

`status` is `ONLINE` or `OFFLINE`, and `message` explains it in a form meant to be shown to an
operator. Each member records its own heartbeat and seal state in the replicated database, so a
member is reported `OFFLINE` once its `last_seen` timestamp, in Unix seconds, is older than the
offline threshold; no node polls any other. `sealed` is that member's own last report and is only
as current as `last_seen`.

## Get the cluster status

This path returns the cluster's health as this node sees it.

| Method | Path              |
| :----- | :---------------- |
| `GET`  | `/cluster/status` |

### Parameters

None

### Sample Response

```json
{
  "data": {
    "enabled": true,
    "node_id": "3297041220608546238",
    "address": "10.0.0.1:9000",
    "leader_id": "3297041220608546238",
    "voters": 3,
    "members": []
  }
}
```

`leader_id` is empty while no leader is elected, which is what a client sees during an election or
a loss of quorum. `members` holds the same entries as `GET /cluster/members`.

## Create a join token

This path creates a single-use, time-limited token bound to one joining node's advertise address.
The token is returned once and cannot be retrieved again: only its hash is stored. Transfer it to
the new node out of band. Provision that node's cluster certificates before it joins; the token
does not carry or issue a private key or certificate.

| Method | Path                       |
| :----- | :------------------------- |
| `POST` | `/cluster/members/tokens`  |

### Parameters

- `identity` (string): The `host:port` the joining node will advertise. Required. The token will
  only redeem for a join that presents this address.
- `ttl_seconds` (integer): How long the token stays valid. Defaults to one hour, and may not exceed 24 hours.

### Sample Response

```json
{
  "data": {
    "token": "JXTuoavjt_ELxOVkXU1Qw4PGTqy_tX7Yt3RAcX8tz5o",
    "identity": "10.0.0.4:9000",
    "expires_at": 1787576408
  }
}
```

`expires_at` is in Unix seconds. A token does not carry a Raft role: dqlite assigns roles itself,
keeping the configured number of voters filled and promoting a stand-by whenever one is lost. There
is no promote API in this release.

## Join the cluster

This path runs schema preflight and returns peer addresses in exchange for a valid,
identity-bound join token. It does not sign certificates. It is called by `notary cluster join`
rather than directly. Every member can serve it, so a join does not depend on any one node being
reachable.

| Method | Path                     |
| :----- | :----------------------- |
| `POST` | `/cluster/members/join`  |

### Parameters

- `token` (string): A join token from `POST /cluster/members/tokens`.
- `address` (string): The address the joining node will advertise to its peers. It must match the
  identity the token was issued for, and the provisioned node certificate must be bound to it.
- `schema_version` (integer): The database migration version the joining node's binary was built for.

### Sample Response

```json
{
  "data": {
    "member_addresses": ["10.0.0.1:9000", "10.0.0.2:9000"]
  }
}
```

This path is authenticated only by the single-use token it carries. A certificate that chains to
the cluster CA can still authenticate to dqlite without a Notary token; issuance policy is the
admission boundary, and the token is a Notary preflight check.

This path returns `401` when the token is unknown, expired, already used, or bound to a different
identity; those cases are reported identically so that a caller learns nothing about which tokens
exist. It returns `409` when the joining node's `schema_version` differs from the cluster's.
Database schemas are not upgraded in place: all members must run a build with the exact schema used
to initialize the cluster. The token is verified before the schema check and redeemed only after
that check succeeds, so a version mismatch leaves the token usable, and two concurrent uses of the
same token cannot both succeed.

## Set the designated ACME issuer

This path records which member may run ACME issuance. The previous issuer must already be stopped;
this path does not fence a live process.

| Method | Path                    |
| :----- | :---------------------- |
| `PUT`  | `/cluster/acme-issuer`  |

### Parameters

- `node_id` (string): The member's dqlite node ID, as reported by `GET /cluster/members`.

### Sample Response

```json
{
  "data": {
    "node_id": "3297041220608546238"
  }
}
```

This path returns `404` when no cluster member with that ID is recorded.

## Remove a member

Member removal is disabled and returns `501 Not Implemented`.

| Method   | Path                       |
| :------- | :------------------------- |
| `DELETE` | `/cluster/members/{id}`    |

dqlite authenticates peers with certificates signed by the shared cluster CA and does not authorize
them against current Raft membership. Removing only the Raft record would therefore leave the
removed host able to authenticate with its still-valid certificate. Until Notary implements
revocation or coordinated PKI rotation, isolate the excluded host, rotate cluster trust, wipe stale
dqlite state on retained healthy hosts, restore or bootstrap a new cluster identity, provision new
certificates, and rejoin remaining members.
