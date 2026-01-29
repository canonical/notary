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

