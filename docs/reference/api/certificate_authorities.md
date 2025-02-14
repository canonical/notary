# Certificate Authorities

## List Certificate Authorities

This path returns the list of certificate authorities.

| Method | Path                              |
| :----- | :-------------------------------- |
| `GET`  | `/api/v1/certificate_authorities` |

### Parameters

None

### Sample Response

```json
TO DO
```

## Create a Certificate Authority

This path creates a new certificate authority.

| Method | Path                              |
| :----- | :-------------------------------- |
| `POST` | `/api/v1/certificate_authorities` |

### Parameters

- `self_signed` (bool): Whether the certificate authority is self-signed.
- `common_name` (string): The common name of the certificate authority.
- `sans_dns` (string): The DNS subject alternative names of the certificate authority.
- `country_name` (string): The country name of the certificate authority.
- `state_or_locality_name` (string): The state or locality name of the certificate authority.
- `locality_name` (string): The locality name of the certificate authority.
- `organization_name` (string): The organization name of the certificate authority.
- `organizational_unit_name` (string): The organizational unit name of the certificate authority.
- `not_valid_after` (string): The expiration date of the certificate authority.

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```

## Get a Certificate Authority

This path returns a single certificate authority.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `GET`  | `/api/v1/certificate_authorities/{id}` |

### Parameters

None

### Sample Response

```json
TO DO
```

## Update a Certificate Authority

This path updates the status of a certificate authority.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `PUT`  | `/api/v1/certificate_authorities/{id}` |

### Parameters

- `status` (string): The status of the certificate authority.

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```

## Delete a Certificate Authority

This path deletes a certificate authority.

| Method   | Path                                   |
| :------- | :------------------------------------- |
| `DELETE` | `/api/v1/certificate_authorities/{id}` |

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

## Post a Certificate for a Certificate Authority

This path uploads a certificate for a certificate authority.

| Method | Path                                               |
| :----- | :------------------------------------------------- |
| `POST` | `/api/v1/certificate_authorities/{id}/certificate` |

### Parameters

- `certificate_chain` (string): The certificate chain in PEM format.

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```
