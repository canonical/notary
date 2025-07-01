# API

Notary exposes a RESTful API for managing certificate requests, certificate authorities, users, and more.

## Resources

The API exposes both Notary-specific and generic resources. The Notary-specific resources are described below:

| Resource                                                | Description                                                                                                                                                                                                                                                                                                                                                             |
| :------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Certificate Authority**](certificate_authorities.md) | Represents a Notary-owned Certificate Authority. These authorities can be used by Notary users to sign certificate requests submitted by external entities.                                                                                                                                                                                                             |
| [**Certificate Request**](certificate_requests.md)      | Represents a certificate request made by an external entity. Users can get the certificate request signed in one of two ways:<ul><li>Internally: the request is signed with one of Notary's Certificate Authorities</li><li>Externally: The CSR is retrieved, signed by an external process, and the resulting certificate is then imported back into Notary.</li></ul> |

In addition to the Notary-specific resources, the API also provides access to generic resources (e.g., `accounts`, `login`, `metrics`) with commonly understood definitions.

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
config.md
```
