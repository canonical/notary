# Use an HSM as the Encryption Backend

In this guide we walk you through the required steps to configure and use a Hardware Security Module (HSM) as an encryption backend for Notary.

```{note}
Once Notary is initialized it must continue using the encryption backend configured at the time of initialization, at the moment there is no way to switch backends.

YubiHSM2 is the documented hardware integration. This does not establish
compatibility with every PKCS#11 device or certify the snap's hardware
integration; the repository has no confined hardware acceptance test.
```

## Prerequisites

* An HSM that supports the PKCS11 protocol
* AES256 symmetric key created on the HSM with capabilities to encrypt and decrypt using the AES-CBC algorithm
* A Linux PKCS#11 shared library compatible with the runtime and CPU architecture
* The HSM's connector up and running

## Snap confinement

The strict snap cannot load arbitrary libraries from the host's `/usr/lib` or
access USB HSMs directly. It does not bundle a vendor SDK. Adding a path to the
configuration does not grant access to the host library or hardware.

A network connector is a possible integration path: install the vendor connector
on the host, and provision a core24-compatible PKCS#11 library and its dependencies
under `/var/snap/notary/common/hsm`. Configure the vendor library to contact that
connector over TCP. The snap already has network access. Library dependencies,
vendor configuration discovery, and encrypt/decrypt after restart must be tested
with the actual device; merely copying the top-level `.so` is not sufficient.

For the initial stable release, use Vault or a separately validated binary/HSM
deployment unless that snap/device combination has passed hardware acceptance.
Direct USB support would require additional interfaces and device-specific
testing; it is not currently provided.

## 1. Configure Notary with your HSM Information

For a validated snap integration, edit `/var/snap/notary/common/notary.yaml`,
remove the `# notary-config-source: snap` marker, and restrict the file to root
(`chmod 600`). Configure this before first start.

* Add your HSM's information in the config file:
  * Path to the library that is installed with the SDK of your HSM
  * Pin to login on your HSM, this will be in the following format: `<auth key id><password>` 
    (e.g., if the authentication key used has the id 0001, your pin might look like "0001password")
  * ID of the symmetric encryption key that will be used

```yaml
encryption_backend:
  type: "pkcs11"
  lib_path: "/var/snap/notary/common/hsm/yubihsm_pkcs11.so"
  pin: "<auth-key-id><password>"
  aes_encryption_key_id: 0x1234
```

## 2. Start Notary

```shell
sudo snap start --enable notary.notaryd
```

Upon successful startup, you should see the following logs:
```
"msg":"PKCS11 backend configured"
"msg":"Encryption key generated successfully"
"msg":"Encryption key encrypted successfully using the configured encryption backend"
```
