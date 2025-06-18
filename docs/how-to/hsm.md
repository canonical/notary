# Use an HSM as Notary's Encryption Backend

In this guide we show the required configuration to use a Hardware Security Module (HSM) as an encryption backend for Notary.
**Note**: This has been tested with YubiHSM2, while this should work with any HSM that supports the PKCS11 protocol please follow any further instruction from the specific HSM vendor.

## Hardware Security Modules (HSMs)

Prerequisites:
- An HSM that supports the PKCS11 protocol
- AES256 symmetric key created on the HSM with capabilities to encrypt and decrypt using the AES-CBC algorithm
- Access to the HSM's driver/interface library file (.so or .dylib file) installed with the HSM's SDK
- The HSM's connector up and running

Configuration
1. Provide a name to your backend, in the following example we call our backend yubihsm2-backend
2. Provide the path to the library that is installed with the SDK of your HSM
3. Provide the Pin to login on your HSM, this will be in the following format: <auth key id><password>, so if the authentication key used has the id 0001 (default key) your pin might look something like "0001password"
4. Provide the ID of the symmetric encryption key that will be used

```yaml
encryption_backend:
  yubihsm2-backend: # name of the backend
    pkcs11:
      lib_path: "/usr/lib/x86_64-linux-gnu/pkcs11/yubihsm_pkcs11.so"
      pin: "0001password"
      key_id: 0x1234
```
