# Login

This section describes the RESTful API for system user authentication.

## Login

This path returns a token that can be used to authenticate with Notary.

| Method | Path     |
| :----- | :------- |
| `POST` | `/login` |

### Parameters

- `email` (string): The email to authenticate with.
- `password` (string): The password to authenticate with.

### Sample Response

```json
{
    "result": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwidXNlcm5hbWUiOiJhZG1pbiIsImV4cCI6MTczNTU4NTk0MX0.0BsZVMLCzJ6mzCXlf3qfAR2k6Fk7aUsGfHV7Tj1Dqy4"
    }
}
```
