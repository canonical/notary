# Notary's Config


This section describes the RESTful API for getting the current config of Notary.


## Config Endpoint

This path returns the current configuration of Notary excluding sensitive fields.


| Method | Path     |
| :----- | :------- |
| `GET` | `/api/v1/config` |


### Sample Response

```json
{
    "result":{
        "port":3000,
        "pebble_notifications":false,
        "logging_level":"debug",
        "logging_output":"stdout",
        "encryption_backend_type":"none"
    }
}
```