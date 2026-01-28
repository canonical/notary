# OIDC Authentication

This section describes the OIDC (OpenID Connect) authentication endpoints for Notary.

## OIDC Login

Initiates the OIDC authentication flow. Redirects the user to the configured OIDC identity provider for authentication.

| Method | Path                   |
| :----- | :--------------------- |
| `GET`  | `/api/v1/oauth/login` |

### Parameters

None

### Response

Redirects to the OIDC provider's authorization endpoint.

### Notes

- If the user successfully authenticates with the OIDC provider, they will be redirected back to `/api/v1/oauth/callback`
- New users are automatically provisioned with the `ReadOnly` role (role_id=3)
- Email is optional - users can be provisioned using only their OIDC subject identifier

## OIDC Callback

Handles the callback from the OIDC provider after authentication. This endpoint is called by the OIDC provider and should not be accessed directly.

| Method | Path                       |
| :----- | :------------------------- |
| `GET`  | `/api/v1/oauth/callback`  |

### Parameters

Query parameters are provided by the OIDC provider:
- `code` (string): Authorization code
- `state` (string): State parameter for CSRF protection

### Response

On success, sets a session cookie and redirects to the main application page.

## Link OIDC Account

Links an OIDC identity to an existing local user account. Requires an authenticated session.

| Method | Path                              |
| :----- | :-------------------------------- |
| `POST` | `/api/v1/accounts/me/link-oidc`  |

### Parameters

None (uses session cookie for authentication)

### Response

Redirects to the OIDC provider for authentication, then returns to `/api/v1/oauth/link-callback`.

### Notes

- User must have a valid session (authenticated with local password)
- Cannot link if the user already has an OIDC account linked
- The OIDC subject cannot be linked to multiple accounts

## Link OIDC Callback

Handles the callback after linking an OIDC account. This endpoint is called by the OIDC provider and should not be accessed directly.

| Method | Path                             |
| :----- | :------------------------------- |
| `GET`  | `/api/v1/oauth/link-callback`   |

### Parameters

Query parameters are provided by the OIDC provider:
- `code` (string): Authorization code
- `state` (string): State parameter for linking flow

### Response

Redirects to account settings with success message.

## Unlink OIDC Account

Removes the OIDC link from a user account. Requires the user to have a local password set (to prevent account lockout).

| Method   | Path                                 |
| :------- | :----------------------------------- |
| `DELETE` | `/api/v1/accounts/me/unlink-oidc`   |

### Parameters

None (uses session cookie for authentication)

### Response

```json
{
    "result": {
        "message": "OIDC account unlinked successfully"
    }
}
```

### Notes

- User must have a local password set before unlinking OIDC
- Prevents account lockout by requiring at least one authentication method
