# Metrics

Notary exposes a set of metrics that can be used to monitor the health of the system and the status of certificates.

## Default Go metrics

These metrics are used to monitor the performance of the Go runtime and garbage collector. These metrics start with the `go_` prefix.

## Custom metrics

These metrics are used to monitor the health of the system and the status of certificates. The following custom metrics are exposed by Notary:

- `certificate_requests`: Total number of certificate requests.
- `outstanding_certificate_requests`: Number of outstanding certificate requests.
- `certificates`: Total number of certificates provided to certificate requests.
- `certificates_expired`: Number of expired certificates.
- `certificates_expiring_in_1_day`: Number of certificates that will expire in the next day.
- `certificates_expiring_in_7_days`: Number of certificates that will expire in the next 7 days.
- `certificates_expiring_in_30_days`: Number of certificates that will expire in the next 30 days.
- `certificates_expiring_in_90_days`: Number of certificates that will expire in the next 90 days.
- `http_requests_total`: Total number of HTTP requests.
- `http_request_duration_seconds`: Duration of HTTP requests in seconds.
