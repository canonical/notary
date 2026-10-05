# API

Notary exposes a RESTful API for managing certificate requests, certificate authorities, users, and more.

## Resources

The API exposes both Notary-specific and generic resources. The Notary-specific resources are described below:

| Resource                                                | Description                                                                                                                                                                                                                                                                                                                                                             |
| :------------------------------------------------------ | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [**Certificate Authority**](certificate_authorities.md) | Represents a Notary-owned Certificate Authority. These authorities can be used by Notary users to sign certificate requests submitted by external entities.                                                                                                                                                                                                             |
| [**Certificate Request**](certificate_requests.md)      | Represents a certificate request made by an external entity. Users can get the certificate request signed in one of two ways:<ul><li>Internally: the request is signed with one of Notary's Certificate Authorities</li><li>Externally: The CSR is retrieved, signed by an external process, and the resulting certificate is then imported back into Notary.</li></ul> |
| [**Cluster**](cluster.md)                               | Represents dqlite cluster membership. Admins can list members, create a join token for a new named member, and remove a member.                                                                                                                                                                                                                                           |

In addition to the Notary-specific resources, the API also provides access to generic resources (e.g., `accounts`, `login`, `metrics`) with commonly understood definitions.

## Authentication

Authenticated operations require the `user_token` cookie returned by
[`POST /login`](login.md) or OIDC login. Use a cookie jar with API clients;
Bearer authorization headers alone are not accepted. See [Roles](../roles.md)
for permissions. Status, metrics, CA CRLs, login, and first-account creation
are public; cluster join redemption uses a join token.

## Responses

Notary's API responses are JSON objects with the following structure:

```json
{
  "data": {"id": 1},
  "message": "Optional message"
}
```

`data` and `message` are omitted when absent. Successful operations with neither
return `{}`; HTTP 204 responses have no body. Errors use the HTTP status and an
optional top-level `message`, not an `error` field.

```{note}
GET calls to the `/metrics` endpoint don't follow this rule; they return text response in the [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).
```

## Table of contents

```{toctree}
:maxdepth: 1

accounts.md
acme_servers.md
certificate_authorities.md
certificate_requests.md
cluster.md
login.md
metrics.md
status.md
config.md
oidc.md
```
