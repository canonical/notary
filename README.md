# Notary

Notary is an open-source TLS Certificate Management software. It provides a secure, reliable, and simple way to manage x.509 certificates for your applications and services.

We designed Notary for Enterprise environments where users need to securely manage the lifecycle of a large number of certificates. 

[Get Started Now!](https://canonical-notary.readthedocs-hosted.com/en/latest/tutorials/getting_started/)

## Key features

- **Certificate Authority**: Notary can act as a Certificate Authority (CA) to issue certificates, both as a root and intermediate CA.
- **Secure Intermediary**: Notary acts as an intermediary between your CA and your certificate requests, providing a secure way to distribute certificates.
- **User Management**: Decide who can request and provide certificates.
- **Simple UI**: A simple and intuitive web interface for managing certificates.
- **Extensive HTTP API**: Accomplish all the tasks you can do in the UI via the HTTP API.
- **Metrics**: Monitor the state of your certificates and the health of your Notary instance with Prometheus metrics.
- **Encryption at Rest**: Sensitive data like private keys is encrypted in the database.
- **Encryption Backend Support**: To increase security an external encryption backend can be configured to encrypt Notary's encryption key.

## Quick links

- [Documentation](https://canonical-notary.readthedocs-hosted.com/en/latest/)
- [Snap Store Listing](https://snapcraft.io/notary)
- [Charmhub Listing](https://charmhub.io/notary-k8s)

## Project & Community

Notary is an open source project that warmly welcomes community contributions, suggestions, fixes, and constructive feedback.

- To contribute to the code Please see [CONTRIBUTING.md](/CONTRIBUTING.md) for guidelines and best practices.
- Raise software issues or feature requests in [GitHub](https://github.com/canonical/notary/issues)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com&via=matrix.org&via=mozilla.org)
