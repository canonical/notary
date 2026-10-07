# Use Vault as the Encryption Backend

In this guide we walk you through the required steps to configure and use Vault as an encryption backend for Notary.

```{note}
Once Notary is initialized it must continue using the encryption backend configured at the time of initialization, at the moment there is no way to switch backends.
```

## Prerequisites

* A Vault that has the Transit secrets engine enabled

## 1. Configure Notary with your Vault Information

For the snap, edit `/var/snap/notary/common/notary.yaml`, remove the
`# notary-config-source: snap` marker, and restrict the file to root (`chmod 600`).
Put any private CA file under `/var/snap/notary/common` so the confined daemon
can read it. Configure this before the first start.

* Add your Vault's information in the config file:
  * Endpoint of your Vault server
  * Mount path of the Transit secrets engine
  * Name of the key to use for encryption
  * Either a Vault token or AppRole credentials (Role ID and Role Secret ID)

```yaml
encryption_backend:
  type: "vault"
  endpoint: "https://vault.example.com"
  mount: "transit"
  key_name: "notary-key"
  token: "<vault-token>"
  tls_ca_cert: "/var/snap/notary/common/vault-ca.crt"
  tls_skip_verify: false
```

Omit `tls_ca_cert` when Vault uses a publicly trusted CA. To use AppRole,
replace `token` with `approle_role_id` and `secret_role_id`. The latter is the
field name currently accepted by Notary for the AppRole secret ID.

## 2. Start Notary

```shell
sudo snap start --enable notary.notaryd
```

Upon successful startup, you should see the following log:

```text
"msg":"Vault backend configured using <method>"
```
