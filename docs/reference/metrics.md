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
- `certificates_validity_consumed{threshold="0.65|0.90|0.95"}`: Number of currently valid certificates at or above each consumed-validity threshold. Counts are cumulative and exclude expired certificates.
- `certificate_not_before_timestamp_seconds{csr_id="..."}`: Start of a certificate's validity period as a Unix timestamp in seconds.
- `certificate_not_after_timestamp_seconds{csr_id="..."}`: End of a certificate's validity period as a Unix timestamp in seconds.
- `certificate_validity_consumed_ratio{csr_id="..."}`: Fraction of a certificate's validity period that has elapsed.
- `http_requests_total`: Total number of HTTP requests.
- `http_request_duration_seconds`: Duration of HTTP requests in seconds.

In a cluster, scrape **one** member only. Custom gauges are filled from the replicated database on a ticker, so scraping every node counts the same certificates multiple times.

## Certificate validity and identification

Certificate validity metrics describe the leaf certificate stored against each certificate request, not whether that certificate is currently deployed. The `csr_id` label identifies the request in Notary. It is only unique within a Notary deployment; preserve deployment and scrape labels when combining these metrics in PromQL.

The consumed-validity ratio is calculated as:

```text
(now - NotBefore) / (NotAfter - NotBefore)
```

A value of `0.95` means 95% of the validity period has elapsed. The ratio is not clamped: future certificates have negative values, and expired certificates have values of at least `1`. A certificate at 96% contributes to all three threshold counts. Future and expired certificates do not contribute to those counts.

Rejected and revoked requests, requests without certificates, and malformed leaf certificates have no per-certificate series. Certificates with zero or negative validity periods expose timestamps but no ratio and do not contribute to threshold counts. Series for removed or excluded requests disappear on the next collection. These metrics are collected at startup and every 120 seconds.

The three per-certificate metrics add three time series per request with a valid certificate. Certificate domains and subjects are not exported as labels. Consider inventory size and Prometheus retention when sizing monitoring storage.

### Time remaining and expiry dates

The timestamps provide the original validity dates. A dashboard can format the `certificate_not_after_timestamp_seconds` value as a date. Calculate hours remaining with:

```promql
(certificate_not_after_timestamp_seconds - time()) / 3600
```

Negative values indicate that the certificate has expired. For a ratio calculated at query time rather than at the last collection, use:

```promql
(time() - certificate_not_before_timestamp_seconds)
/
(certificate_not_after_timestamp_seconds - certificate_not_before_timestamp_seconds)
```

Only use this division for certificates with a positive validity period.

### Alert example

The following rule identifies unexpired certificates at or above 95% consumed validity. Its value is seconds remaining, so the notification includes a readable duration. It uses default vector matching to retain and match all labels, including deployment identity.

```yaml
groups:
  - name: notary-certificate-validity
    rules:
      - alert: NotaryCertificateValidity95Percent
        expr: |
          (certificate_not_after_timestamp_seconds - time() > 0)
          and
          (certificate_validity_consumed_ratio >= 0.95)
        for: 10m
        labels:
          severity: critical
        annotations:
          summary: "Certificate request {{ $labels.csr_id }} has consumed at least 95% of its validity"
          description: "The stored certificate expires in {{ $value | humanizeDuration }}."
```

Use thresholds of `0.65` or `0.90` for earlier warnings. Keep a separate expired-certificate alert: this rule intentionally stops matching once a certificate expires. The charm must supply the alert rules to its monitoring integration; Notary only exports the metrics.
