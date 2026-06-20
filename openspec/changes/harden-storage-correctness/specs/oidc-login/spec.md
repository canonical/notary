## ADDED Requirements

### Requirement: OIDC state is stateless and node-independent
The OIDC login flow's CSRF state parameter SHALL be self-authenticating (signed with a key derived from the JWT secret) rather than stored in process memory. Any Notary process holding the same JWT secret MUST be able to validate a state parameter issued by any other process.

#### Scenario: Callback lands on a different node
- **WHEN** the login redirect is issued by one Notary process and the OIDC provider's callback is handled by a different process sharing the same database
- **THEN** state validation succeeds and login completes

#### Scenario: Tampered state is rejected
- **WHEN** a callback carries a state parameter whose signature does not verify
- **THEN** the login attempt is rejected

### Requirement: State expiry and single-use properties are preserved
Signed state parameters SHALL embed an issuance timestamp and MUST be rejected after the validity window (5 minutes). The existing binding of state to the initiating client (user agent) SHALL be preserved or consciously replaced by an equivalent or stronger CSRF protection.

#### Scenario: Expired state
- **WHEN** a callback presents a state parameter older than 5 minutes
- **THEN** the login attempt is rejected

#### Scenario: State replay
- **WHEN** the same valid state parameter is presented in two callback requests
- **THEN** at most one login attempt succeeds, or the design documents why replay within the validity window is acceptable
