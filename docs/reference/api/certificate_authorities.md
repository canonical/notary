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
{
    "result": [
        {
            "id": 1,
            "status": "active",
            "certificate": "-----BEGIN CERTIFICATE-----\nMIIFRzCCAy+gAwIBAgIIGCQX6mmQZ14wDQYJKoZIhvcNAQELBQAwNzEJMAcGA1UE\nBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQLEwAw\nHhcNMjUwMjE0MTQwMDUxWhcNMzUwMjE0MTQwMDUxWjA3MQkwBwYDVQQGEwAxCTAH\nBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQKEwAxCTAHBgNVBAsTADCCAiIwDQYJ\nKoZIhvcNAQEBBQADggIPADCCAgoCggIBANQGNZlgVNl/eVympjZyyfCHWG8MmNOf\nnuxZrWYZL5UuD9RWt0wJByeNSbl/rg79PcYoqt5M2/g3w5BFFB+U0RbgFoR5x5Mp\npB4bk8MNxKnn1zF4zalfe0FIjfByByqNY6CSVDOYQywJzIRB85Yt3P8wDqdY94fl\nLM3sm5TVATrwhJJxOredQuQPnznm65nSdB7v5eP7ttv5XRvOkT6W9V/omVHwM+Te\nc2ZwfMuo9iXhmuA+9ldFVZ5NkQGk5VXZt496/4txK3NSvWT3SY+EAdrx1GmQivfl\nHjJiQwHp/akXLrmM5QD79Dm29JEXZY5hLk5oOtOCaEHPI4CSoCjwLCmeRYSmTo1X\nxaJ84Ud+8+brw8pq9Mau7JjVgHuzqoI06/7AZS9so9+GyXzA49HwXp1UtdGncmQ1\ni1vempnzAiOXx/m/g+Y5KTc0klVfFSXEipa2bJ0Gx77ZcaePBrtVn2sX9/SSqMo+\nmSK6lxBukIcE4NxZSGCz2cGZwipK0U0Scs+hbobM1BDufmU7AFgWJliRisWu5+Jy\nncYt+bKKPGJ497OA1PT4AvyJBW7XqtoiTFnCCiR3YckAMxi6J4J3AQQoOOCJUIQr\nQ1UuDy5qI+Pekc2azg0oV1qDQRF/uFAqIY/8n1j/YDMYKEnwKt3Qd+BLo4cAxP5Z\n1TxrKJqFNTtBAgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggr\nBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRmA85Z94R5V0u9Qsci\nodAVM/kgzDANBgkqhkiG9w0BAQsFAAOCAgEAc9sCdpRnwrLDgB0BxQBjEWLJAmbM\ns0SNkqre1PqjMCrGRAcyg32a8hukkkMDpbvrc24LB7R+s0Z/Zso6amTEwubZiky/\nCt7AXudeC47YQjYVaBb6GArIKw4Tzjqlei+C8+zwVbECmb3u7aMyQcyD44Q93nuG\nKG3lOX33hdpm2DuqKRG8tVcHbAqSLiXsFqiDpTtK6geFsa3UFEnCtmY+cPvmztYH\nE8Ve+sSCkG64uMPSGHs7INaMvbZwyOkUVctsEYAqVKL9pV9Hium4LdLRRSu3otzJ\nB7Zh0TT+XC50hjUzc39314dltwkOe8mv0LvkQi8lkTuEwdHajdM0hHVY5vxu8zbw\nvH2rNp71WMgWbcSo+M5DaGmUBQorMOhvEursKVJ37IS/q/d05RrSH/CnFnkhNl8d\no9VTtUkhS7xa4fS0N+hKmp4wZkejLl/xjXXTgBPpgmVDGafmShEni1WML02YoLXt\n+kN8PIUnw7Mn3FHBwHjutBHy9TevvgxuY/RQFYP9CfLT9EHN9GLBPEosq21q2ko+\naaNGmZkL/TTGil1FjrH5QVEj7C1dERW9FZdO7ABp/2Wn79+duuKDBlpwpgrVhpBJ\nKH3fShW0RSRuyY8lTniARmCIFRLCgB/dggzlRZS6w43yHODQ+pN0/TQhYoLSzKfS\nuPF+SZPBClAZo5Y=\n-----END CERTIFICATE-----\n",
            "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIEmjCCAoICAQAwNzEJMAcGA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJ\nMAcGA1UEChMAMQkwBwYDVQQLEwAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDUBjWZYFTZf3lcpqY2csnwh1hvDJjTn57sWa1mGS+VLg/UVrdMCQcnjUm5\nf64O/T3GKKreTNv4N8OQRRQflNEW4BaEeceTKaQeG5PDDcSp59cxeM2pX3tBSI3w\ncgcqjWOgklQzmEMsCcyEQfOWLdz/MA6nWPeH5SzN7JuU1QE68ISScTq3nULkD585\n5uuZ0nQe7+Xj+7bb+V0bzpE+lvVf6JlR8DPk3nNmcHzLqPYl4ZrgPvZXRVWeTZEB\npOVV2bePev+LcStzUr1k90mPhAHa8dRpkIr35R4yYkMB6f2pFy65jOUA+/Q5tvSR\nF2WOYS5OaDrTgmhBzyOAkqAo8CwpnkWEpk6NV8WifOFHfvPm68PKavTGruyY1YB7\ns6qCNOv+wGUvbKPfhsl8wOPR8F6dVLXRp3JkNYtb3pqZ8wIjl8f5v4PmOSk3NJJV\nXxUlxIqWtmydBse+2XGnjwa7VZ9rF/f0kqjKPpkiupcQbpCHBODcWUhgs9nBmcIq\nStFNEnLPoW6GzNQQ7n5lOwBYFiZYkYrFruficp3GLfmyijxiePezgNT0+AL8iQVu\n16raIkxZwgokd2HJADMYuieCdwEEKDjgiVCEK0NVLg8uaiPj3pHNms4NKFdag0ER\nf7hQKiGP/J9Y/2AzGChJ8Crd0HfgS6OHAMT+WdU8ayiahTU7QQIDAQABoB4wHAYJ\nKoZIhvcNAQkOMQ8wDTALBgNVHREEBDACggAwDQYJKoZIhvcNAQELBQADggIBAL56\n1c/yYPHQyWfN9yk/w4f88DLW4Fj1IpAi7+ySIufAed6xOqSuT6rn7wtB/INoYEYB\nLGgWTsRn4lJrpbc+zrkqZx7kzZoB4DqTmqDLvk6E/Rh0fNfha9unto7VAaMNUkGL\nsbIyCrtdUhaKwL5HJb3lrhAEJh+7mGU7J6XrRk1WLnHrDxOOjt35abmNILFz9kOD\nDNsG2zFJnh00axcnKnARc6mn7mXk2P/4dosP+tDLB63qWZu9T9tsygdaDF1d0ISB\nHFuIwdxOryspOG8PKYXeAo6lkLgkYARENsjhTsCeYzh0tW35yK9we5Uxe6N9NODe\nbAmD7/Wci1ZvzungHAyt658bNkkrrZhtD9uwVO+myaIERGLtWEDPZi9xv+oV8yBF\neSiHb3Oon9sFhd80hgdtNgH2+SJOjw1gzGESBF6aRjeLsQj0Rb7yIkI7ZwdwjgUC\nglniY6ES0gOsdFr1crqbb6eb5o0uHzj5gm4r4H2MLFzsurFu2EXi0rWoX+VhK7Vw\n+Lyagou9LNOJcSOGSVAs5ACxz49YC2rea/QkDUKVKHfWLPOQFWZNrbbfBTpc0SDZ\nHsp8R9OsqNLm5Ofajgt/9PPp/DKGl9SbX1KtKE1Jm9oASxLw4m+L3FD/pxi2o1Kg\nqtnsMmgfC22iCuo4Z8WgUbpjMcXqQqnSso8dn1vF\n-----END CERTIFICATE REQUEST-----\n"
        }
    ]
}
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
- `state_or_province_name` (string): The state or province name of the certificate authority.
- `locality_name` (string): The locality name of the certificate authority.
- `organization_name` (string): The organization name of the certificate authority.
- `organizational_unit_name` (string): The organizational unit name of the certificate authority.
- `not_valid_after` (string): The expiration date of the certificate authority.

### Sample Response

```json
{
    "result": {
        "message": "Certificate Authority created successfully",
        "id": 1
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
{
    "result": {
        "id": 1,
        "status": "active",
        "certificate": "-----BEGIN CERTIFICATE-----\nMIIFRzCCAy+gAwIBAgIIGCQX6mmQZ14wDQYJKoZIhvcNAQELBQAwNzEJMAcGA1UE\nBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJMAcGA1UEChMAMQkwBwYDVQQLEwAw\nHhcNMjUwMjE0MTQwMDUxWhcNMzUwMjE0MTQwMDUxWjA3MQkwBwYDVQQGEwAxCTAH\nBgNVBAgTADEJMAcGA1UEBxMAMQkwBwYDVQQKEwAxCTAHBgNVBAsTADCCAiIwDQYJ\nKoZIhvcNAQEBBQADggIPADCCAgoCggIBANQGNZlgVNl/eVympjZyyfCHWG8MmNOf\nnuxZrWYZL5UuD9RWt0wJByeNSbl/rg79PcYoqt5M2/g3w5BFFB+U0RbgFoR5x5Mp\npB4bk8MNxKnn1zF4zalfe0FIjfByByqNY6CSVDOYQywJzIRB85Yt3P8wDqdY94fl\nLM3sm5TVATrwhJJxOredQuQPnznm65nSdB7v5eP7ttv5XRvOkT6W9V/omVHwM+Te\nc2ZwfMuo9iXhmuA+9ldFVZ5NkQGk5VXZt496/4txK3NSvWT3SY+EAdrx1GmQivfl\nHjJiQwHp/akXLrmM5QD79Dm29JEXZY5hLk5oOtOCaEHPI4CSoCjwLCmeRYSmTo1X\nxaJ84Ud+8+brw8pq9Mau7JjVgHuzqoI06/7AZS9so9+GyXzA49HwXp1UtdGncmQ1\ni1vempnzAiOXx/m/g+Y5KTc0klVfFSXEipa2bJ0Gx77ZcaePBrtVn2sX9/SSqMo+\nmSK6lxBukIcE4NxZSGCz2cGZwipK0U0Scs+hbobM1BDufmU7AFgWJliRisWu5+Jy\nncYt+bKKPGJ497OA1PT4AvyJBW7XqtoiTFnCCiR3YckAMxi6J4J3AQQoOOCJUIQr\nQ1UuDy5qI+Pekc2azg0oV1qDQRF/uFAqIY/8n1j/YDMYKEnwKt3Qd+BLo4cAxP5Z\n1TxrKJqFNTtBAgMBAAGjVzBVMA4GA1UdDwEB/wQEAwIBBjATBgNVHSUEDDAKBggr\nBgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRmA85Z94R5V0u9Qsci\nodAVM/kgzDANBgkqhkiG9w0BAQsFAAOCAgEAc9sCdpRnwrLDgB0BxQBjEWLJAmbM\ns0SNkqre1PqjMCrGRAcyg32a8hukkkMDpbvrc24LB7R+s0Z/Zso6amTEwubZiky/\nCt7AXudeC47YQjYVaBb6GArIKw4Tzjqlei+C8+zwVbECmb3u7aMyQcyD44Q93nuG\nKG3lOX33hdpm2DuqKRG8tVcHbAqSLiXsFqiDpTtK6geFsa3UFEnCtmY+cPvmztYH\nE8Ve+sSCkG64uMPSGHs7INaMvbZwyOkUVctsEYAqVKL9pV9Hium4LdLRRSu3otzJ\nB7Zh0TT+XC50hjUzc39314dltwkOe8mv0LvkQi8lkTuEwdHajdM0hHVY5vxu8zbw\nvH2rNp71WMgWbcSo+M5DaGmUBQorMOhvEursKVJ37IS/q/d05RrSH/CnFnkhNl8d\no9VTtUkhS7xa4fS0N+hKmp4wZkejLl/xjXXTgBPpgmVDGafmShEni1WML02YoLXt\n+kN8PIUnw7Mn3FHBwHjutBHy9TevvgxuY/RQFYP9CfLT9EHN9GLBPEosq21q2ko+\naaNGmZkL/TTGil1FjrH5QVEj7C1dERW9FZdO7ABp/2Wn79+duuKDBlpwpgrVhpBJ\nKH3fShW0RSRuyY8lTniARmCIFRLCgB/dggzlRZS6w43yHODQ+pN0/TQhYoLSzKfS\nuPF+SZPBClAZo5Y=\n-----END CERTIFICATE-----\n",
        "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIIEmjCCAoICAQAwNzEJMAcGA1UEBhMAMQkwBwYDVQQIEwAxCTAHBgNVBAcTADEJ\nMAcGA1UEChMAMQkwBwYDVQQLEwAwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIK\nAoICAQDUBjWZYFTZf3lcpqY2csnwh1hvDJjTn57sWa1mGS+VLg/UVrdMCQcnjUm5\nf64O/T3GKKreTNv4N8OQRRQflNEW4BaEeceTKaQeG5PDDcSp59cxeM2pX3tBSI3w\ncgcqjWOgklQzmEMsCcyEQfOWLdz/MA6nWPeH5SzN7JuU1QE68ISScTq3nULkD585\n5uuZ0nQe7+Xj+7bb+V0bzpE+lvVf6JlR8DPk3nNmcHzLqPYl4ZrgPvZXRVWeTZEB\npOVV2bePev+LcStzUr1k90mPhAHa8dRpkIr35R4yYkMB6f2pFy65jOUA+/Q5tvSR\nF2WOYS5OaDrTgmhBzyOAkqAo8CwpnkWEpk6NV8WifOFHfvPm68PKavTGruyY1YB7\ns6qCNOv+wGUvbKPfhsl8wOPR8F6dVLXRp3JkNYtb3pqZ8wIjl8f5v4PmOSk3NJJV\nXxUlxIqWtmydBse+2XGnjwa7VZ9rF/f0kqjKPpkiupcQbpCHBODcWUhgs9nBmcIq\nStFNEnLPoW6GzNQQ7n5lOwBYFiZYkYrFruficp3GLfmyijxiePezgNT0+AL8iQVu\n16raIkxZwgokd2HJADMYuieCdwEEKDjgiVCEK0NVLg8uaiPj3pHNms4NKFdag0ER\nf7hQKiGP/J9Y/2AzGChJ8Crd0HfgS6OHAMT+WdU8ayiahTU7QQIDAQABoB4wHAYJ\nKoZIhvcNAQkOMQ8wDTALBgNVHREEBDACggAwDQYJKoZIhvcNAQELBQADggIBAL56\n1c/yYPHQyWfN9yk/w4f88DLW4Fj1IpAi7+ySIufAed6xOqSuT6rn7wtB/INoYEYB\nLGgWTsRn4lJrpbc+zrkqZx7kzZoB4DqTmqDLvk6E/Rh0fNfha9unto7VAaMNUkGL\nsbIyCrtdUhaKwL5HJb3lrhAEJh+7mGU7J6XrRk1WLnHrDxOOjt35abmNILFz9kOD\nDNsG2zFJnh00axcnKnARc6mn7mXk2P/4dosP+tDLB63qWZu9T9tsygdaDF1d0ISB\nHFuIwdxOryspOG8PKYXeAo6lkLgkYARENsjhTsCeYzh0tW35yK9we5Uxe6N9NODe\nbAmD7/Wci1ZvzungHAyt658bNkkrrZhtD9uwVO+myaIERGLtWEDPZi9xv+oV8yBF\neSiHb3Oon9sFhd80hgdtNgH2+SJOjw1gzGESBF6aRjeLsQj0Rb7yIkI7ZwdwjgUC\nglniY6ES0gOsdFr1crqbb6eb5o0uHzj5gm4r4H2MLFzsurFu2EXi0rWoX+VhK7Vw\n+Lyagou9LNOJcSOGSVAs5ACxz49YC2rea/QkDUKVKHfWLPOQFWZNrbbfBTpc0SDZ\nHsp8R9OsqNLm5Ofajgt/9PPp/DKGl9SbX1KtKE1Jm9oASxLw4m+L3FD/pxi2o1Kg\nqtnsMmgfC22iCuo4Z8WgUbpjMcXqQqnSso8dn1vF\n-----END CERTIFICATE REQUEST-----\n"
    }
}
```

## Get the CRL of a Certificate Authority

This path returns a single certificate authority.

| Method | Path                                   |
| :----- | :------------------------------------- |
| `GET`  | `/api/v1/certificate_authorities/{id}/crl` |

### Parameters

None

### Sample Response

```json
{
    "result": {
        "crl": "-----BEGIN X509 CRL-----
        MIIB8zCB3AIBATANBgkqhkiG9w0BAQsFADByMQswCQYDVQQGEwJUUjEOMAwGA1UE
        CBMFSXptaXIxEjAQBgNVBAcTCU5hcmxpZGVyZTESMBAGA1UEChMJQ2Fub25pY2Fs
        MREwDwYDVQQLEwhJZGVudGl0eTEYMBYGA1UEAxMPVGVzdGluZyBSb290IENBFw0y
        NTAzMjUwMDUwNTVaFw0yNjAzMjUwMDUwNTVaoDYwNDAfBgNVHSMEGDAWgBQF3ex7
        fP5MLxLqm+dYzdPtP0droDARBgNVHRQECgIIGC/lcS7/dH4wDQYJKoZIhvcNAQEL
        BQADggEBAFLrH+1paVPKYr8cRAEBPtSRxp23YbbbcC40irmmYlHoOEooRAJ8+nw3
        ZUX4A527Bjr+Pbu/9klXZhCAS4r8fFT3veJQ1mp/kEZOsBG9h0bCN4Jwpqix2f1W
        6z3AcPiwg636KPaze8pwUcqSfQSwmfzwl3E8vkzD29dy6tXwKTdgaUP7uHrzeHDi
        rtA9e9+8gbbad1I9lwdd2Q4qgt3mUIjwn5SV9sSEaSApT8i/Z72RHLpGJNl3JpO1
        0599PMgFeP6VruT8IYhfj7iEY2lqiyWMXoXsgGwhD8PAqKcJ03vavUNrfhkT+Jl9
        yxat/tt2TxlkcAxv4nrxhR208GXqpE0=
        -----END X509 CRL-----"
    }
}
```

## Update the status of a Certificate Authority

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

## Upload a Certificate for a Certificate Authority

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

## Sign a Certificate Authority with another Certificate Authority

This path signs any intermediate certificate authority with another active root or intermediate certificate authority.

| Method | Path                                               |
| :----- | :------------------------------------------------- |
| `POST` | `/api/v1/certificate_authorities/{id}/sign` |

### Parameters

- `certificate_authority_id` (string): The ID of the Certificate Authority that will sign this Certificate Authority.

### Sample Response

```json
{
    "result": {
        "message": "success"
    }
}
```

## Revoke a Certificate Authority

This path revokes a certificate authority. It will error if the certificate wasn't signed in notary.
Revoking a certificate will place the certificate serial number in the CRL of the issuing CA and set its status back to pending.

| Method  | Path                              |
| :-----  | :-------------------------------- |
| `POST`  | `/api/v1/certificate_authorities/{id}/revoke` |

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