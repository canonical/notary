## ADDED Requirements

### Requirement: Schema changes apply exactly once per cluster
In a cluster, each schema migration (Notary's and the embedded OpenFGA's) SHALL be applied exactly once cluster-wide, coordinated through the cluster's schema-upgrade mechanism — not independently by each starting node.

#### Scenario: Concurrent node startup
- **WHEN** all members of a cluster start simultaneously against a database with pending migrations
- **THEN** the migrations are applied once and every node ends up serving the upgraded schema

### Requirement: Rolling upgrades gate schema changes on cluster readiness
During a rolling binary upgrade, a schema migration introduced by the new version SHALL NOT be applied until all members run a binary that supports it. Upgraded members MUST wait (reporting their status) rather than break not-yet-upgraded members.

#### Scenario: Rolling upgrade of a 3-node cluster
- **WHEN** members are upgraded one at a time to a version carrying a new migration
- **THEN** the migration is applied only after the last member upgrades, and the cluster serves requests throughout

#### Scenario: Waiting member reports why
- **WHEN** an upgraded member is waiting for the rest of the cluster before applying migrations
- **THEN** its status endpoint and logs indicate it is waiting for cluster schema convergence
