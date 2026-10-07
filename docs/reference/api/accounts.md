# Accounts

This section describes the RESTful API for managing accounts. Except for initial
account creation and the `/accounts/me` endpoints, these operations require an
administrator session.

## List Accounts

This path returns the list of accounts.

| Method | Path               |
| :----- | :----------------- |
| `GET`  | `/api/v1/accounts` |

### Parameters

None

### Sample Response

```json
{
    "data": [
        {
            "id": 1,
            "email": "admin@canonical.com",
            "role_id": 0,
            "has_password": true,
            "has_oidc": false,
            "auth_methods": [
                "local"
            ]
        }
    ]
}
```

## Create an Account

This path creates a new account. The first account can be created without
authentication and is forced to Admin. Restrict network access until it exists.

| Method | Path               |
| :----- | :----------------- |
| `POST` | `/api/v1/accounts` |

### Parameters

- `email` (string): The email of the account. 
- `password` (string): At least eight characters, including an uppercase letter,
  a lowercase letter, and a number or supported symbol.
- `role_id` (integer): The role ID of the account. Valid values are:
  - `0`: Admin
  - `1`: Certificate Manager
  - `2`: Certificate Requestor
  - `3`: Read Only

To view the role definitions, see the [Roles reference](../roles.md).

### Sample Response

```json
{
    "data": {
        "id": 1
    }
}
```

## Change Password for an Account

This path updates an existing account.

| Method | Path                                    |
| :----- | :-------------------------------------- |
| `POST` | `/api/v1/accounts/{id}/change_password` |

### Parameters

- `password` (string): The new password of the account.

### Sample Response

```json
{}
```

## Get an Account

This path returns the details of a specific account.

| Method | Path                    |
| :----- | :---------------------- |
| `GET`  | `/api/v1/accounts/{id}` |

### Parameters

None

### Sample Response

```json
{
    "data": {
        "id": 2,
        "email": "admin@canonical.com",
        "role_id": 0,
        "has_password": true,
        "has_oidc": false,
        "auth_methods": [
            "local"
        ]
    }
}
```

## Delete an Account

This path deletes an account, returning HTTP 202. The last account cannot be
deleted when OIDC is disabled.

| Method   | Path                    |
| :------- | :---------------------- |
| `DELETE` | `/api/v1/accounts/{id}` |

### Parameters

None

### Sample Response

```json
{}
```

## Current account

`GET /api/v1/accounts/me` returns the caller's account in `data` using the same
fields as Get an Account. Any authenticated role can use it. OIDC accounts also
include `oidc_subject`; `auth_methods` lists `local`, `oidc`, or both.

`POST /api/v1/accounts/me/change_password` accepts `{"password":"<new-password>"}`
and returns HTTP 201 with `{}`. The same password rules apply. The administrative
`POST /api/v1/accounts/{id}/change_password` endpoint also returns HTTP 201.

## Change role

`PUT /api/v1/accounts/{id}/role` accepts `{"role_id":1}`. Only administrators
can change roles, and the default administrator account (ID 1) cannot be changed.
