# Login

This section describes the RESTful API for system user authentication.

## Login

This path sets the `user_token` session cookie used to authenticate with Notary.
The cookie is Secure, HttpOnly, SameSite=Strict and expires after two hours.

| Method | Path     |
| :----- | :------- |
| `POST` | `/login` |

### Parameters

- `email` (string): The email to authenticate with.
- `password` (string): The password to authenticate with.

### Sample Response

```json
{}
```

HTTP 200 includes a `Set-Cookie` header; the token is not returned in the JSON
body. Store the cookie jar securely and submit it on subsequent requests.

## Logout

`POST /logout` expires the session cookie and returns HTTP 200 with `{}`.
