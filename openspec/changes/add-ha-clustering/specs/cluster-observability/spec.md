## ADDED Requirements

### Requirement: Status endpoint exposes cluster state
`GET /cluster/status` SHALL extend the existing status response with a `cluster-state` listing every member's node-id, address, raft role (voter/standby/spare), and status (leader/follower/down), plus whether the queried node currently has quorum access. The response MUST be usable as a health/readiness signal by load balancers and automation.

#### Scenario: Healthy cluster status
- **WHEN** the status endpoint is queried on any member of a healthy 3-node cluster
- **THEN** the response lists 3 members with their roles and identifies the leader

#### Scenario: Degraded cluster status
- **WHEN** the status endpoint is queried on a surviving node after quorum loss
- **THEN** the response indicates quorum is unavailable while the endpoint itself still responds

### Requirement: Cluster state is inspectable from the CLI
`notary cluster list` SHALL display membership and roles in human-readable and JSON formats, matching the status endpoint's content.

#### Scenario: Operator inspects the cluster
- **WHEN** `notary cluster list --format json` runs on any member
- **THEN** it outputs the member list with names, addresses, roles, and leader designation
