# API

Notary exposes a RESTful API for managing certificate requests, certificate authorities, users, and more.

## Resources

The API exposes the following Notary-specific resources:

| Resource                                                | Description                                                                                                                                       |
| :------------------------------------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------ |
| [**Certificate Authority**](certificate_authorities.md) | Represents a Notary owned Certificate Authority. Notary users can use Certificate Authorities to sign certificate requests for external entities. |
| [**Certificate Request**](certificate_requests.md)      | Represents a certificate request made by an external entity.                                                                                      |

The API also exposes generic resources with commonly understood definitions (ex.`accounts`, `login`, `metrics`).

## Authentication

Almost every operation requires a client token, in the form of a Bearer Token.

## Responses

Notary's API responses are JSON objects with the following structure:

```json
{
  "result": "Result content",
  "error": "Error message",
}
```

```{note}
GET calls to the `/metrics` endpoint don't follow this rule; they return text response in the [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/#text-format-details).
```

## Table of contents

```{toctree}
:maxdepth: 1

accounts.md
certificate_authorities.md
certificate_requests.md
login.md
metrics.md
status.md
```
