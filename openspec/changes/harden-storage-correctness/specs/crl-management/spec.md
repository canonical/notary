## ADDED Requirements

### Requirement: Revocations are never lost under concurrency
Updating a certificate authority's CRL (adding a revoked certificate, re-signing, or replacing the CRL) SHALL be performed with concurrency control such that concurrent revocations against the same CA are all reflected in the final stored CRL. A read-modify-write that silently discards a concurrent writer's revocation entry MUST NOT be possible.

#### Scenario: Two certificates revoked concurrently
- **WHEN** two API requests revoke two different certificates issued by the same CA at the same time
- **THEN** the stored CRL ultimately contains both revoked serial numbers

#### Scenario: Conflicting update is retried or rejected
- **WHEN** a CRL update detects that the stored CRL changed since it was read
- **THEN** the update is retried against the current CRL or fails with a retryable error — it does not overwrite the newer CRL

### Requirement: CRL monotonicity
A successfully stored CRL SHALL never remove a previously published revocation entry for a certificate that has not been reissued, and successive CRLs for a CA MUST have non-decreasing CRL numbers.

#### Scenario: CRL regenerated after revocation
- **WHEN** a CA's CRL is re-signed for any reason after certificate X was revoked
- **THEN** the new CRL still lists certificate X and carries a CRL number greater than the previous CRL's
