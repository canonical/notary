# API

Notary exposes a RESTful API for managing certificate requests, certificate authorities, users, and more.

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
GET calls to the `/metrics` endpoint don't follow this rule, it returns text response in the [Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/#text-format-details).
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
