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
