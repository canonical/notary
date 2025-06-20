# Use an HSM as Notary's Encryption Backend

In this guide we walk you through the required steps to configure and use a Hardware Security Module (HSM) as an encryption backend for Notary.

**Note**:
* Once Notary is initialized it must continue using the encryption backend configured at the time of initialization, at the moment there is no way to switch backends.
* This has been tested with YubiHSM2, while this should work with any HSM that supports the PKCS11 protocol please follow any further instruction from the specific HSM vendor.

## Prerequisites

* An HSM that supports the PKCS11 protocol
* AES256 symmetric key created on the HSM with capabilities to encrypt and decrypt using the AES-CBC algorithm
* Access to the HSM's driver/interface library file (.so or .dylib file) installed with the HSM's SDK
* The HSM's connector up and running

## 1. Configure Notary with your HSM Information

* Provide a name to your backend (in the following example we call our backend yubihsm2-backend)
* Add your HSM's information in the config file:
  * Path to the library that is installed with the SDK of your HSM
  * Pin to login on your HSM, this will be in the following format: `<auth key id><password>` 
    (e.g., if the authentication key used has the id 0001, your pin might look like "0001password")
  * ID of the symmetric encryption key that will be used

```yaml
encryption_backend:
  yubihsm2-backend: # name of the backend
    pkcs11:
      lib_path: "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
      pin: "0001password"
      aes_encryption_key_id: 0x1234
```

## 2. Start Notary

```shell
sudo snap start notary.notaryd
```

Upon successful startup, you should see the following logs:
```
"msg":"PKCS11 backend configured"
"msg":"Encryption key generated successfully"
"msg":"Encryption key encrypted successfully using the configured encryption backend"
```