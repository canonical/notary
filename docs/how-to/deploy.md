# Deploy

Notary is available as a snap and a Kubernetes charm. Use this guide to deploy Notary with one of these methods.

`````{tab-set}
    
````{tab-item} Snap

Notary is available as a snap. You can see the snap store listing [here](https://snapcraft.io/notary).

Prerequisites:
- A Linux machine that supports snaps

Install Notary:

```shell
sudo snap install notary --channel=0.0/edge
```

````

````{tab-item} Charm

Notary is available as a Kubernetes charm. For more information on using Notary in the Juju ecosystem, see the [Notary charm documentation](https://charmhub.io/notary-k8s).

Prerequisites:
- A Kubernetes cluster
- A Juju controller

Deploy Notary:

```shell
juju deploy notary-k8s --channel 0/stable
```

````

`````

To run several Notary processes as one dqlite cluster, see [Run a Notary cluster](cluster.md). Bootstrap **one** member first, then join the others with tokens. Never start three empty `db_path` directories at the same time.

## Three snaps (example)

Configure each machine with `snap set` rather than editing files. The snap writes `/var/snap/notary/common/notary.yaml` from these options; until you set one, a hand-edited file is left alone.

| Option | Meaning |
| :-- | :-- |
| `cluster.name` | Member name, as in `cluster.name` |
| `cluster.address` | dqlite bind address, `host:port`. Must be reachable by the other members, so not loopback |
| `cluster.join-token` | Token from `notary cluster add`. Read on first start only, then cleared |
| `port` | HTTPS API port |
| `external-hostname` | Address joiners and clients use to reach this member's API |
| `log-level` | `debug`, `info`, `warn` or `error` |
| `encryption-backend` | Encryption backend type. Must match on every member |

On machine 1:

```shell
sudo snap set notary cluster.name=node1 cluster.address=10.0.0.1:9000 external-hostname=10.0.0.1:3000
sudo snap start notary.notaryd
```

On machine 1, mint a token for each joiner:

```shell
sudo notary cluster add node2 --config /var/snap/notary/common/notary.yaml
```

On machine 2, with an empty data directory:

```shell
sudo snap set notary cluster.name=node2 cluster.address=10.0.0.2:9000 external-hostname=10.0.0.2:3000 cluster.join-token='<token>'
sudo snap start notary.notaryd
```

Repeat for machine 3 **one after another**, not in parallel. The Kubernetes charm is a separate project and mounts its own config file; size it the same way (one unit bootstraps, then the rest join).
