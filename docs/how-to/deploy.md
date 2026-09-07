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

On machine 1, install the snap, set `cluster.name` / `cluster.address` in `/var/snap/notary/common/notary.yaml`, and start `notaryd`. On machine 2 and 3, install the snap with empty data directories, run `notary cluster add <name>` on machine 1, then `notary start --join` (or set `cluster.join_token`) on each joiner **one after another**. The Kubernetes charm is a separate project; size it the same way (one unit bootstraps, then join).
