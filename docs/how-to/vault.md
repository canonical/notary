# Use Vault as Notary's Encryption Backend

In this guide we walk you through the required steps to configure and use Vault as an encryption backend for Notary.

```{note}
Once Notary is initialized it must continue using the encryption backend configured at the time of initialization, at the moment there is no way to switch backends.
```

## Prerequisites

* An Vault that has the Transit secrets engine enabled

## 1. Configure Notary with your Vault Information

* Provide a name to your backend (in the following example we call our backend vault-backend)
* Add your Vault's information in the config file:
  * Endpoint of your Vault server
  * Mount path of the Transit secrets engine
  * Name of the key to use for encryption
  * Either a Vault token or AppRole credentials (Role ID and Role Secret ID)

```yaml
encryption_backend:
  vault-backend: # name of the backend
    vault:
      endpoint: "https://vault.example.com"
      mount: "transit"
      key_name: "notary-key"
      token: "s.xxxxxxx" # if you use a token for authentication
      role_id: "xxxxxx" # if you use AppRole for authentication
      role_secret_id: "xxxxxx" # if you use AppRole for authentication
      tls_ca_cert: "/path/to/ca.crt" # optional, if your Vault server uses a CA not in your system's trust store.
      tls_skip_verify: false # optional (defaults to false), if you want to skip TLS certificate verification. It is strongly discouraged to set this to true outside of development environments.
```

## 2. Start Notary

```shell
sudo snap start notary.notaryd
```

Upon successful startup, you should see the following log:

```text
"msg":"Vault backend configured using <method>"
```
