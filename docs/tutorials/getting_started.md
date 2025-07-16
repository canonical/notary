# Getting started

In this tutorial, you will learn how to install Notary on a Linux machine and access the Notary UI.

## Prerequisites:

- A Linux machine that supports snaps

## 1. Install Notary

Install the snap:

```shell
sudo snap install notary --channel=latest/edge
```

Generate a certificate and private key to the following location:

```shell
sudo openssl req -newkey rsa:2048 -nodes -keyout /var/snap/notary/common/key.pem -x509 -days 1 -out /var/snap/notary/common/cert.pem -subj "/CN=example.com"
```

Start the service:
```shell
sudo snap start notary.notaryd
```

Navigate to `https://localhost:3000` to access the Notary UI.

```{note}
Your browser may display a warning about the connection's security. This warning is displayed because we used a self-signed certificate to start Notary. You can safely ignore this warning.
```

You should be prompted to initialize Notary.

```{image} ../images/initialize.png
:alt: Initialize Notary
:align: center
```

## 2. Initialize Notary

Create the initial user:

- **Email**: `admin@canonical.com`
- **Password**: `NotaryAdmin123!`

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
