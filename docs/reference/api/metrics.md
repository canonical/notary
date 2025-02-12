# Metrics

## Get metrics

This path returns the metrics of Notary in Prometheus format. For more information about metrics exposed by Notary, see the [Metrics Reference](../metrics.md).

| Method | Path       |
| :----- | :--------- |
| `GET`  | `/metrics` |

### Parameters

None

### Sample Response

```text
# HELP certificate_requests Total number of certificate requests
# TYPE certificate_requests gauge
certificate_requests 1
# HELP certificates Total number of certificates provided to certificate requests
# TYPE certificates gauge
certificates 0
# HELP certificates_expired Number of expired certificates
# TYPE certificates_expired gauge
certificates_expired 0
...
```
