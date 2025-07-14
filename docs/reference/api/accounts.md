# Accounts

This section describes the RESTful API for managing accounts. Accounts are used to authenticate with Notary and manage the system.

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
    "result": [
        {
            "id": 1,
            "username": "admin",
            "role_id": 1
        }
    ]
}
```

## Create an Account

This path creates a new account. The first account can be created without authentication.

| Method | Path               |
| :----- | :----------------- |
| `POST` | `/api/v1/accounts` |

### Parameters

- `username` (string): The username of the account. 
- `password` (string): The password of the account.
- `role_id` (integer): The role ID of the account. Valid values are:
  - `0`: Admin
  - `1`: Certificate Manager
  - `2`: Certificate Requestor
  - `3`: Read Only

To view the role definitions, see the [Roles reference](../roles.md).

### Sample Response

```json
{
    "result": {
        "message": "success",
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
{
    "result": {
        "message": "success"
    }
}
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
    "result": {
        "id": 2,
        "username": "pizza.com",
        "role_id": 0
    }
}
```

## Delete an Account

This path deletes an account.

| Method   | Path                    |
| :------- | :---------------------- |
| `DELETE` | `/api/v1/accounts/{id}` |

### Parameters

None

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```
