# Getting started

In this tutorial, you will learn how to install Notary on a Linux machine and access the Notary UI.

## Prerequisites:

- A Linux machine that supports snaps

## 1. Install Notary

Install the snap:

```shell
sudo snap install notary --channel=1/stable
```

The stable channel must be published before installing it. For release testing,
use `1/candidate` only after a candidate has been published.

Keep the HTTPS port restricted to the operator until initialization is complete:
the first account is created without authentication and becomes administrator.

For a local tutorial, generate a certificate and private key:

```shell
sudo openssl req -newkey rsa:2048 -nodes -keyout /var/snap/notary/common/key.pem -x509 -days 1 -out /var/snap/notary/common/cert.pem -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
sudo chmod 600 /var/snap/notary/common/key.pem
```

For production, provision a CA-signed certificate covering the service hostname
at those paths and arrange renewal. Restart Notary after replacing the files.
Choose the encryption backend before first start; the default `none` leaves the
data-encryption key unwrapped in the database. See [Vault](../how-to/vault.md)
and [HSM limitations](../how-to/hsm.md).

Start the service and enable it on subsequent boots:
```shell
sudo snap start --enable notary.notaryd
```

Navigate to `https://localhost:3000` to access the Notary UI.

```{note}
For this local tutorial, a browser warning is expected because the certificate is
self-signed. Verify that it is the certificate you generated. Do not bypass
certificate warnings for a production deployment.
```

You should be prompted to initialize Notary.

```{image} ../images/initialize.png
:alt: Initialize Notary
:align: center
```

## 2. Initialize Notary

Create the initial user:

- **Email**: your administrator email address
- **Password**: a unique password stored in your password manager

Click on "Submit".

You should now be redirected to Notary's Certificate Request page.

```{image} ../images/certificate_requests.png
:alt: Certificate Request
:align: center
```

Congratulations! You have successfully installed Notary and created the initial user. You can now start managing certificates with Notary.

## 3. Remove Notary (optional)

To remove Notary from your machine, run:

```shell
sudo snap remove notary
```
