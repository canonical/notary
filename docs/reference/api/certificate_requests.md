# Certificate Requests

## List Certificate Requests

This path returns the list of certificate requests.

| Method | Path                           |
| :----- | :----------------------------- |
| `GET`  | `/api/v1/certificate_requests` |

### Parameters

None

### Sample Response

```json
{
    "result": [
        {
            "id": 1,
            "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICrjCCAZYCAQAwaTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYD\nVQQHDAlOYXJsaWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\nZDETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAK+vJMxO1GTty09/E4M/RbTCPABleCuYc/uzj72KWaIvoDaanuJ4NBWM\n2aUiepxWdMNTR6oe31gLq4agLYT309tXwCeBLQnOxvBFWONmBG1qo0fQkvT5kSoq\nAO29D7hkQ0gVwg7EF3qOd0JgbDm/yvexKpYLVvWMQAngHwZRnd5vHGk6M3P7G4oG\nmIj/CL2bF6va7GWODYHb+a7jI1nkcsrk+vapc+doVszcoJ+2ryoK6JndOSGjt9SD\nuxulWZHQO32XC0btyub63pom4QxRtRXmb1mjM37XEwXJSsQO1HOnmc6ycqUK53p0\njF8Qbs0m8y/p2NHFGTUfiyNYA3EdkjUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IB\nAQA+hq8kS2Y1Y6D8qH97Mnnc6Ojm61Q5YJ4MghaTD+XXbueTCx4DfK7ujYzK3IEF\npH1AnSeJCsQeBdjT7p6nv5GcwqWXWztNKn9zibXiASK/yYKwqvQpjSjSeqGEh+Sa\n9C9SHeaPhZrJRj0i3NkqmN8moWasF9onW6MNKBX0B+pvBB+igGPcjCIFIFGUUaky\nupMXY9IG3LlWvlt+HTfuMZV+zSOZgD9oyqkh5K9XRKNq/mnNz/1llUCBZRmfeRBY\n+sJ4M6MJRztiyX4/Fjb8UHQviH931rkiEGtG826IvWIyiRSnAeE8B/VzL0GlT9Zq\nge6lFRxB1FlDuU4Blef8FnOI\n-----END CERTIFICATE REQUEST-----",
            "certificate_chain": "",
            "status": "Outstanding"
        }
    ]
}
```

## Create a Certificate Request

This path creates a new certificate request.

| Method | Path                           |
| :----- | :----------------------------- |
| `POST` | `/api/v1/certificate_requests` |

### Parameters

- `csr` (string): The certificate signing request in PEM format.

### Sample Response

```json
{
    "result": {
        "message": "success",
        "id": 1
    }
}
```

## Get a Certificate Request

This path returns the details of a specific certificate request.

| Method | Path                                |
| :----- | :---------------------------------- |
| `GET`  | `/api/v1/certificate_requests/{id}` |

### Parameters

None

### Sample Response

```json
{
    "result": {
        "id": 2,
        "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICrjCCAZYCAQAwaTELMAkGA1UEBhMCVFIxDjAMBgNVBAgMBUl6bWlyMRIwEAYD\nVQQHDAlOYXJsaWRlcmUxITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0\nZDETMBEGA1UEAwwKYmFuYW5hLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC\nAQoCggEBAK+vJMxO1GTty09/E4M/RbTCPABleCuYc/uzj72KWaIvoDaanuJ4NBWM\n2aUiepxWdMNTR6oe31gLq4agLYT309tXwCeBLQnOxvBFWONmBG1qo0fQkvT5kSoq\nAO29D7hkQ0gVwg7EF3qOd0JgbDm/yvexKpYLVvWMQAngHwZRnd5vHGk6M3P7G4oG\nmIj/CL2bF6va7GWODYHb+a7jI1nkcsrk+vapc+doVszcoJ+2ryoK6JndOSGjt9SD\nuxulWZHQO32XC0btyub63pom4QxRtRXmb1mjM37XEwXJSsQO1HOnmc6ycqUK53p0\njF8Qbs0m8y/p2NHFGTUfiyNYA3EdkjUCAwEAAaAAMA0GCSqGSIb3DQEBCwUAA4IB\nAQA+hq8kS2Y1Y6D8qH97Mnnc6Ojm61Q5YJ4MghaTD+XXbueTCx4DfK7ujYzK3IEF\npH1AnSeJCsQeBdjT7p6nv5GcwqWXWztNKn9zibXiASK/yYKwqvQpjSjSeqGEh+Sa\n9C9SHeaPhZrJRj0i3NkqmN8moWasF9onW6MNKBX0B+pvBB+igGPcjCIFIFGUUaky\nupMXY9IG3LlWvlt+HTfuMZV+zSOZgD9oyqkh5K9XRKNq/mnNz/1llUCBZRmfeRBY\n+sJ4M6MJRztiyX4/Fjb8UHQviH931rkiEGtG826IvWIyiRSnAeE8B/VzL0GlT9Zq\nge6lFRxB1FlDuU4Blef8FnOI\n-----END CERTIFICATE REQUEST-----",
        "certificate_chain": "",
        "status": "Outstanding"
    }
}
```

## Delete a Certificate Request

This path deletes a certificate request.

| Method   | Path                                |
| :------- | :---------------------------------- |
| `DELETE` | `/api/v1/certificate_requests/{id}` |

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

## Create a Certificate for a Certificate Request

This path creates a certificate for a certificate request.


| Method | Path                                            |
| :----- | :---------------------------------------------- |
| `POST` | `/api/v1/certificate_requests/{id}/certificate` |

### Parameters

- `certificate` (string): The certificate chain in PEM format.

### Sample Response

```json
{
    "result": {
        "message": "success",
        "id": 1
    }
}
```

## Reject a Certificate Request

This path rejects a certificate request. This is different than revoking a certificate, in that 
this endpoint will reject a CSR that has never had a certificate assigned while revoking requires
an already generated certificate.

| Method | Path                                       |
| :----- | :----------------------------------------- |
| `POST` | `/api/v1/certificate_requests/{id}/reject` |

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

## Revoke a Certificate

This path revokes an existing certificate. This path only works if the certificate request was signed in notary.
Notary will place the certificate's serial number in the CRL of the issuing CA.


| Method | Path                                                   |
| :----- | :----------------------------------------------------- |
| `POST` | `/api/v1/certificate_requests/{id}/certificate/revoke` |

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

## Sign a Certificate Request with a Certificate Authority

This path signs any certificate request with an active root or intermediate certificate authority.

| Method | Path                                               |
| :----- | :------------------------------------------------- |
| `POST` | `/api/v1/certificate_requests/{id}/sign` |

### Parameters

- `certificate_authority_id` (string): The ID of the Certificate Authority that will sign this certificate request.

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```

## Delete a Certificate for a Certificate Request

This path deletes a certificate for a certificate request.

| Method   | Path                                            |
| :------- | :---------------------------------------------- |
| `DELETE` | `/api/v1/certificate_requests/{id}/certificate` |

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
