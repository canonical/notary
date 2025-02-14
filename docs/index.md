# Notary

Notary is an open-source TLS Certificate Management software. It provides a secure, reliable, and simple way to manage x.509 certificates for your applications and services.

We designed Notary for Enterprise environments where users need to securely manage the lifecycle of a large number of certificates. 

## Key features

- **Certificate Authority**: Notary can act as a Certificate Authority (CA) to issue certificates, both as a root and intermediate CA.
- **Secure Intermediary**: Notary acts as an intermediary between your CA and your certificate requests, providing a secure way to distribute certificates.
- **User Management**: Decide who can request and provide certificates.
- **Simple UI**: A simple and intuitive web interface for managing certificates.
- **Extensive HTTP API**: Accomplish all the tasks you can do in the UI via the HTTP API.
- **Metrics**: Monitor the state of your certificates and the health of your Notary instance with Prometheus metrics.

## In this documentation

````{grid} 1 1 2 2

```{grid-item-card}
:link: tutorials/

Tutorials
^^^

**Start here**: a hands-on introduction to Notary for new users
```

```{grid-item-card}
:link: how-to/

How-to guides
^^^

**Step-by-step guides** covering key operations and common tasks
```

````


````{grid} 1 1 2 2

```{grid-item-card}
:link: reference/

**Reference**
^^^

**Technical information** - specifications, APIs, architecture
```

```{grid-item-card}
:link: explanation/

Explanation
^^^

**Discussion and clarification** of key topics
```

````

## Project and community

Notary is a member of the Ubuntu family. It’s an open source project that warmly welcomes community projects, contributions, suggestions, fixes and constructive feedback.

- [Ubuntu Code of conduct](https://ubuntu.com/community/ethos/code-of-conduct)
- Meet the community and chat with us on [Matrix](https://matrix.to/#/!yAkGlrYcBFYzYRvOlQ:ubuntu.com?via=ubuntu.com)
- [Open a bug](https://github.com/canonical/notary/issues)
- [Contribute](https://github.com/canonical/notary/)

```{toctree}
:hidden:

tutorials/index
how-to/index
reference/index
explanation/index
```
