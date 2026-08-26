# Login

This section describes the RESTful API for system user authentication.

## Login

This path authenticates a user and starts a session.

| Method | Path     |
| :----- | :------- |
| `POST` | `/login` |

### Parameters

- `email` (string): The email to authenticate with.
- `password` (string): The password to authenticate with.

### Sample Response

The session token is returned as a `user_token` cookie, not in the response body:

```
Set-Cookie: user_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...; Path=/; HttpOnly; Secure; SameSite=Strict
```

```json
{}
```

Every authenticated path reads that cookie. Sending the token as an
`Authorization: Bearer` header instead does not authenticate the request.
