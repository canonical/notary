# ACME Servers

ACME servers configure external certificate issuance with DNS-01 validation.
Admins, certificate managers, and readers can list/read server metadata. Only
admins and certificate managers can create, update, delete, or activate servers.

| Method | Path | Result |
| :-- | :-- | :-- |
| `GET` | `/api/v1/acme_servers` | HTTP 200, `data` array of servers |
| `POST` | `/api/v1/acme_servers` | HTTP 201, created server in `data` |
| `GET` | `/api/v1/acme_servers/{id}` | HTTP 200, server in `data` |
| `PUT` | `/api/v1/acme_servers/{id}` | HTTP 200, updated server in `data` |
| `DELETE` | `/api/v1/acme_servers/{id}` | HTTP 204, no body |
| `PUT` | `/api/v1/acme_servers/{id}/active` | HTTP 200, activated server in `data` |

## Create or update

The required fields are `name`, `directory_url`, `email`, and `dns_provider`.
`env_vars` is a map of strings containing LEGO provider credentials and advanced
settings described in [Sign certificate requests with ACME](../../how-to/acme.md).

```json
{
  "name": "Production CA",
  "directory_url": "https://acme.example.com/directory",
  "email": "admin@example.com",
  "dns_provider": "cloudflare",
  "env_vars": {"CLOUDFLARE_DNS_API_TOKEN": "<token>"}
}
```

On update, omitting `env_vars` preserves all existing entries. Providing a map
replaces the map; an empty value for an existing key preserves that key's old
value. Fields other than `env_vars` remain required on update.

## Response

```json
{
  "data": {
    "id": 1,
    "name": "Production CA",
    "directory_url": "https://acme.example.com/directory",
    "email": "admin@example.com",
    "dns_provider": "cloudflare",
    "active": false,
    "env_var_keys": ["CLOUDFLARE_DNS_API_TOKEN"]
  }
}
```

Credential values are encrypted in storage and never returned by these endpoints.
Activation takes no request body; only one server can be active at a time.