# Sign certificate requests with ACME

Notary can obtain certificates from an external ACME certificate authority using
DNS-01 validation. Configure an ACME server and DNS provider, then use it to sign
an existing certificate signing request (CSR).

## Configure an ACME server

Sign in as an administrator or certificate manager. You need an ACME directory
URL and DNS provider credentials that allow Notary to create the DNS records
needed to validate the domains in your CSR.

1. Open **ACME Servers** and select **Add ACME Server**.
2. Enter a display **Name**, the certificate authority's **Directory URL**, and
   the **Email** to use for ACME account registration.
3. Enter the **DNS Provider** identifier supported by LEGO, such as `cloudflare`,
   `hetzner`, or `route53`.
4. Under **Provider Environment Variables**, add the credential keys and values
   required by that provider.
5. Save the server, then select **Set Active** for it. Only one ACME server can
   be active at a time.

Notary registers an account on first use and reuses it for the same email and
directory URL. Registration automatically agrees to the certificate authority's
terms of service, so review those terms before signing.

## Sign a request

Open **Certificate Requests**, choose **Sign with ACME** for the request, and
confirm. This action is available when an ACME server is active. Notary uses the
configured DNS provider to complete DNS-01 validation and stores the issued
certificate with the request. Issuance can take time while DNS changes propagate.

To sign through the API, send `POST /api/v1/certificate_requests/{id}/sign` with
this JSON body:

```json
{
  "signing_method": "acme"
}
```

See the [certificate requests API](../reference/api/certificate_requests.md)
for details.

In a cluster, ACME signing must reach the dqlite leader directly. A follower
returns HTTP 409 with the leader address when known; retry against that member.
See [ACME signing in a cluster](cluster.md#acme-signing).
