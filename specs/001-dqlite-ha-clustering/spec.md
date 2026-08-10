# Feature Specification: Highly Available Clustered Storage

**Feature Branch**: `TLSENG-1132`
**Created**: 2026-07-17
**Status**: Draft
**Input**: User description: "Replace sqlite with dqlite for HA, managed via microcluster. Notary is not yet deployed at any production site so breaking changes are safe. Support single-node deployment (likely as a single-node cluster). Design so a future mode can fully outsource storage to an external database (e.g. a PostgreSQL connection URL). Take into account OIDC authentication and HSM-backed encryption at rest."

## Overview

Notary is a certificate authority: its database is a security ledger. An issued certificate that is not recorded, or a revocation that is lost, is a security incident. Today all state lives in a single local SQLite file, so the loss of the machine hosting Notary loses the ledger and makes Notary a single point of failure in otherwise highly available deployments.

This feature replaces the single-file storage with quorum-replicated storage embedded in the Notary binary, managed as a self-contained cluster: every deployment is a cluster, and a single node is simply a cluster of one. Operators form, grow, shrink, and inspect the cluster through Notary's own configuration, CLI, and API — no external database or coordination service is required. Committed writes survive the loss of a minority of nodes with automatic failover. Notary's existing security integrations carry over unchanged regardless of which member handles a request: OIDC-based (and local) login, and HSM-backed (or equivalent) encryption at rest for sensitive fields.

The service is treated as unreleased (no production deployments), so this is an accepted breaking change with no migration path from existing single-file databases. The storage configuration is shaped so that a later, separate mode — fully outsourcing storage to an external database such as PostgreSQL — can be added afterwards without reworking this feature's foundations.

## Clarifications

### Session 2026-07-17

- Q: What must happen if two members of a freshly forming deployment concurrently attempt to create singleton security-critical state (storage-encryption key, session-signing secret, embedded authorization store/model)? → A: Require exactly-once creation as an explicit correctness guarantee — whichever attempt commits first wins, and every other member MUST detect and adopt that committed state rather than creating a conflicting copy.

## User Scenarios & Testing _(mandatory)_

### User Story 1 - Single-node deployment stays simple (Priority: P1)

An operator (or evaluation user) deploys Notary on one machine. They configure a node identity, a storage location, and start the service with an explicit "initialize new deployment" instruction. Notary comes up as a cluster of one and behaves exactly as the product does today: login (local and OIDC), certificate issuance, revocation, ACME, and encryption at rest all work unchanged.

**Why this priority**: Single node is the most common deployment shape and the entry point for every other scenario; if it regresses in ceremony or capability, the feature has failed its baseline.

**Independent Test**: Deploy one node from scratch, exercise the full existing functional test surface (auth, issuance, revocation, ACME, encrypted-at-rest fields), restart the node, and confirm state and identity survive the restart.

**Acceptance Scenarios**:

1. **Given** a fresh machine with no prior Notary state, **When** the operator starts Notary with an empty storage location, node identity, and the explicit new-deployment instruction, **Then** Notary initializes a single-node deployment and serves its full existing API.
2. **Given** a running single-node deployment, **When** the node restarts, **Then** it resumes the same identity and data without any operator action and without re-supplying initialization instructions.
3. **Given** a fresh machine, **When** Notary is started with an empty storage location and _neither_ an initialization nor a join instruction, **Then** Notary refuses to start with an error naming both valid alternatives (initialize a new deployment, or join one with a credential) rather than silently creating a new deployment or failing generically.
4. **Given** a single-node deployment, **When** no clustering-specific operations are ever invoked, **Then** the operator experience (config surface actually needed, commands, status) carries no multi-node ceremony.

---

### User Story 2 - Grow to a highly available cluster with zero data loss (Priority: P1)

An operator running a single node needs high availability. On the existing node they request a join credential for each new member; on each new machine they configure that node's identity and address and start Notary with the join credential. The cluster grows to three (or more) nodes with no downtime and no data migration. When a minority of nodes is lost, the service keeps operating with no committed write lost.

**Why this priority**: This is the reason the feature exists — the CA must not be the single point of failure, and lost writes (unrecorded certificates, lost revocations) are security incidents.

**Independent Test**: Form a 3-node cluster from a populated single node, write through any node, kill one node, and verify continued service and full data integrity; restore the killed node and verify it rejoins and catches up.

**Acceptance Scenarios**:

1. **Given** a populated single-node deployment, **When** two more nodes join using valid join credentials, **Then** the cluster reaches three members with all pre-existing data intact and no service interruption.
2. **Given** a join credential, **When** it is used once, expires, or is presented by a node whose configured identity does not match the credential, **Then** subsequent or mismatched use is rejected with an error identifying the specific cause (already used, expired, or identity mismatch) rather than a generic rejection.
3. **Given** a healthy 3-node cluster, **When** any single node fails abruptly, **Then** writes continue to succeed (after automatic failover within a bounded time) and every write acknowledged before the failure is still present.
4. **Given** a 3-node cluster that has lost quorum (two nodes down), **When** a client attempts a write or issuance, **Then** the request fails promptly with an error identifying the cause as loss of cluster quorum — never a silent acceptance that could be lost, and never an error indistinguishable from an unrelated failure.
5. **Given** a cluster without quorum, **When** a client downloads a CRL or an issued certificate, **Then** the surviving node keeps serving these (possibly slightly stale) signed artifacts, with staleness discoverable only through the client's existing trust mechanisms (e.g. CRL validity window, certificate/signature validation) — no new client-facing staleness indicator is introduced.
6. **Given** a rejoining or newly joined node, **When** it has caught up, **Then** requests served by it return the same results as any other member.

---

### User Story 3 - Operate cluster membership over time (Priority: P2)

An operator (or deployment automation such as a charm) maintains the cluster across its life: inspecting membership and health, removing a node gracefully for decommissioning, and force-removing a node that died and will never return (e.g. a lost cloud instance or Kubernetes unit whose volume is gone). A replacement node then joins with a fresh credential.

**Why this priority**: Without safe membership operations, HA decays over time — dead members erode fault tolerance, and automation cannot self-heal deployments.

**Independent Test**: On a 3-node cluster, gracefully remove one live member, force-remove one abruptly-killed member, verify the remaining cluster stays healthy, then join a replacement and verify a return to full strength.

**Acceptance Scenarios**:

1. **Given** a healthy cluster, **When** an authorized admin queries cluster status, **Then** the response lists every member with its identity, address, role, and health, and identifies the current write leader.
2. **Given** a live member, **When** an admin removes it, **Then** it hands off its responsibilities and leaves without any loss of committed data or interruption to the remaining members.
3. **Given** a member that is permanently dead, **When** an admin removes it by identity, **Then** the cluster expels it and re-balances member roles to protect fault tolerance.
4. **Given** a node that lost its local state (e.g. rescheduled without its volume), **When** it starts with initialization or join instructions but its identity still exists in the cluster, **Then** it cannot silently fork a second deployment; the documented path is removal of the old identity followed by a fresh join.
5. **Given** all membership operations above, **When** driven by non-interactive automation, **Then** each is achievable through the API with machine-readable outcomes (no interactive prompts).
6. **Given** a live member that has become unreachable, **When** an admin attempts a graceful (non-forced) removal, **Then** the attempt fails with an error indicating the member is unreachable and that forced removal is the next step, rather than hanging indefinitely or silently escalating.

---

### User Story 4 - Back up and restore a clustered deployment (Priority: P2)

An admin takes periodic backups of the deployment through any node and, after data corruption or operator error, restores a chosen backup into the running cluster. After a catastrophic loss of every node, a documented recovery procedure rebuilds a working deployment from the most recent backup.

**Why this priority**: A CA ledger needs disaster recovery independent of replication — replication does not protect against corruption, operator error, or full-site loss. Existing backup/restore functionality must not regress.

**Independent Test**: Back up a populated 3-node cluster, mutate data, restore the backup, and verify all nodes converge on the restored state — including encrypted fields remaining decryptable and logins still working; separately, rebuild from backup after destroying all nodes.

**Acceptance Scenarios**:

1. **Given** a healthy cluster, **When** an admin requests a backup on any node, **Then** a portable, complete backup archive of the ledger is produced.
2. **Given** a running cluster and a valid backup archive, **When** an admin restores it, **Then** every member converges on the restored state and continues serving, with security-critical derived state (decryption capability, session validation) correct on every node afterwards.
3. **Given** total loss of all nodes, **When** the operator follows the documented recovery procedure with a backup archive, **Then** a new deployment serves the backed-up data.
4. **Given** a backup taken on any member, **When** it is inspected, **Then** its contents are readable with standard tooling for audit purposes (no proprietary opaque format).

---

### User Story 5 - Upgrades apply schema changes exactly once, cluster-wide (Priority: P3)

An operator performs a rolling upgrade of a multi-node deployment to a new Notary version that includes storage schema changes. The upgrade coordinates itself: schema changes apply exactly once for the whole cluster at the safe moment, nodes on the old schema do not corrupt data, and the operator does not orchestrate anything beyond restarting nodes with the new version.

**Why this priority**: Needed for the long-term operability of clusters, but exercised less frequently than deployment, membership, and recovery flows.

**Independent Test**: Roll a 3-node cluster from version N to N+1 (with a schema change) one node at a time and verify a single coordinated schema application, no data corruption, and full service afterwards.

**Acceptance Scenarios**:

1. **Given** a 3-node cluster on version N, **When** nodes restart one at a time on version N+1 containing schema changes, **Then** the schema change is applied exactly once cluster-wide and all nodes end up serving on the new version.
2. **Given** a partially upgraded cluster, **When** members are on mixed versions, **Then** no member applies changes prematurely or corrupts data; the cluster reaches full service when the upgrade completes.

---

### Edge Cases

- Two operators (or a confused automation) attempt to initialize a new deployment on two machines and then join them: the join must fail cleanly rather than merge or fork the ledger (split-brain prevention).
- A node's local recorded state disagrees with its configuration file (e.g. a changed address or identity after the deployment was formed): recorded state wins; the deviation is surfaced as a warning, not silently applied.
- A join credential leaks: credentials are single-use and short-lived, and their minting is restricted to authorized admins, bounding the exposure window.
- An OIDC login begins on one node and the provider redirects the user back to a different node (as happens behind a load balancer): the login MUST complete transparently to the end user — no visible error, redirect loop, or extra action on their part — regardless of which member receives the callback.
- The HSM (or external key-wrapping service) is reachable from some nodes but not others: any node that cannot unwrap the storage encryption key must fail its readiness clearly, since it cannot serve encrypted data; documentation must state that all members need access to the same key-wrapping backend.
- Concurrent certificate revocations land on different nodes at nearly the same time: the resulting revocation list must contain both revocations (no lost update).
- The clock or network partitions a member away and it later returns: it must catch up and rejoin service automatically without operator action.
- A backup is restored whose encryption key differs from the running cluster's unwrapped key: nodes must detect and re-establish correct decryption capability or fail readiness clearly, never serve garbage.
- An admin removes the final remaining node / attempts to shrink below one: the operation MUST be refused with an error stating that removing the last member is not permitted, rather than executing a partial or ambiguous state change.
- Automation restarts a node that is already part of a deployment while still passing initialization or join flags: the flags are ignored, and a logged warning identifies which flag was ignored and why, so automation logs can distinguish an idempotent restart from a real misconfiguration.
- Two members of a freshly forming deployment race to create singleton security-critical state (the storage-encryption key, the session-signing secret, or the embedded authorization store/model) at nearly the same moment: exactly one creation MUST commit; every other member MUST adopt the committed value rather than creating a divergent copy or failing outright.

## Requirements _(mandatory)_

### Functional Requirements

**Deployment & initialization**

- **FR-001**: Every deployment MUST be a cluster; a single node MUST operate as a fully functional cluster of one, with the same feature surface Notary has today (OIDC and local login, issuance, revocation, ACME, encryption at rest).
- **FR-002**: Creating a new deployment MUST require an explicit operator instruction (distinct from normal start), and joining an existing deployment MUST require a valid join credential; a node with no prior state and no such instruction MUST refuse to start with an error that names both valid alternatives (initialize a new deployment, or join one with a credential) rather than a generic startup failure.
- **FR-003**: A node restarted with existing local state MUST resume its identity and data with no operator input; initialization/join instructions present on restart MUST be ignored with a logged warning.
- **FR-004**: Each node MUST be configured with a stable operator-chosen identity, a storage location, and (for multi-node use) a peer-reachable cluster address; a single node MUST NOT be required to provide a peer-reachable address.
- **FR-005**: Node configuration MUST be strictly node-local: no peer lists, quorum counts, or shared sections, so that adding a member never edits an existing member's configuration.

**Bootstrap & singleton state**

- **FR-006**: Security-critical state that must exist exactly once across the deployment (the storage-encryption key, the login-session signing secret, and the embedded authorization store/model) MUST be created exactly once cluster-wide. If multiple members concurrently attempt to create this state during initial deployment formation, exactly one attempt MUST succeed and every other member MUST detect and adopt the committed state rather than creating a conflicting copy or failing.

**Membership operations**

- **FR-007**: An authorized admin MUST be able to mint a join credential bound to a specific new-node identity; credentials MUST be single-use and expire after a short bounded time.
- **FR-008**: An authorized admin MUST be able to remove a member by identity whether it is live (graceful handover) or permanently unreachable (forced removal), through one interface.
- **FR-009**: The cluster MUST automatically manage member roles (which members vote, which stand by) to maximize fault tolerance for the current member count, without operator tuning.
- **FR-010**: All membership operations (mint credential, join, remove, status) MUST be drivable non-interactively by automation with machine-readable results, and MUST be restricted to authorized admins.
- **FR-011**: The system MUST prevent split-brain: a node that lost its state cannot silently create or merge a divergent deployment, and two independently initialized deployments MUST NOT be joinable into one.

**Durability & availability semantics**

- **FR-012**: A write acknowledged to a client MUST survive the permanent loss of any minority of members (zero committed-write loss).
- **FR-013**: With a majority of members healthy, the service MUST remain fully available, recovering automatically from single-member failure within a bounded time and with no operator action.
- **FR-014**: Without a majority, operations that record or change state (issuance, revocation, account changes, login-affecting reads) MUST fail promptly with an error that identifies the cause as insufficient cluster quorum — distinguishable from other error classes — never block indefinitely or acknowledge unreplicated writes.
- **FR-015**: Without a majority, distribution of already-signed artifacts (revocation lists, issued certificates) MUST continue from surviving members, accepting bounded staleness; staleness MUST remain discoverable only through mechanisms clients already rely on today (e.g. CRL validity fields, signature verification) — this feature MUST NOT introduce a new client-facing staleness indicator.
- **FR-016**: Concurrent writes through different members MUST NOT lose updates; in particular, concurrent revocations MUST all appear in the resulting revocation list.

**Observability**

- **FR-017**: The status surface MUST report, per member: identity, address, role, health, and which member currently leads writes; overall it MUST report whether the cluster has write quorum.
- **FR-018**: Status MUST be available via both the API and a CLI convenience, and MUST be suitable for load-balancer/orchestrator health and readiness checks; a node that cannot serve correctly reports not-ready with a cause that distinguishes, at minimum, an unreachable key-wrapping backend from a node that has not yet finished syncing, so operators and automation can act on the right remediation.

**Backup, restore & recovery**

- **FR-019**: An admin MUST be able to produce a complete backup archive of the ledger through any member; the archive contents MUST be inspectable with standard tooling.
- **FR-020**: An admin MUST be able to restore a backup archive into a running cluster; afterwards all members MUST converge on the restored state, including refreshing security-critical derived state (storage-encryption capability, session validation) before serving.
- **FR-021**: A documented recovery procedure MUST exist for total cluster loss, rebuilding a serving deployment from a backup archive.

**Upgrades**

- **FR-022**: Storage schema changes shipped in a new version MUST be applied exactly once per cluster during upgrade, coordinated automatically; mixed-version interim states MUST NOT corrupt data.

**Security integrations**

- **FR-023**: Encryption at rest MUST be preserved: sensitive fields remain encrypted in replicated storage exactly as they are today, and the key-wrapping backends (HSM/PKCS#11, Vault, none) MUST continue to work unchanged; every member MUST have access to the same key-wrapping backend to serve.
- **FR-024**: OIDC and local login MUST work when requests (including OIDC provider callbacks) land on any member; authorization decisions (embedded relationship-based access control) MUST be consistent cluster-wide.
- **FR-025**: Traffic between members MUST be mutually authenticated and encrypted, with member credentials managed automatically by the system — separate from the operator-managed API TLS identity, which is unchanged.

**Forward compatibility & packaging**

- **FR-026**: The storage configuration surface MUST be structured so that a future, mutually exclusive "external database" mode (e.g. a PostgreSQL connection URL) can be added as a sibling option without reshaping this feature's configuration; storage-engine specifics MUST stay contained behind the existing storage seam, and schema migrations MUST remain portable SQL.
- **FR-027**: All supported packaging (snap, OCI/rock) MUST ship the feature fully — including the cluster port and storage location provisioning — for machine, container, and Kubernetes deployments; Kubernetes deployments MUST be able to preserve node identity across pod rescheduling.
- **FR-028**: There is NO import path from pre-existing single-file databases (accepted breaking change); the old file-path storage configuration is removed and its use MUST produce a startup error that names the deprecated configuration key and points at its replacement, rather than a generic parse or validation failure.

### Key Entities

- **Cluster**: the deployment as a whole — the authoritative ledger plus its member set; membership is cluster _state_, not configuration.
- **Member (node)**: one Notary process with a stable operator-chosen identity, a local storage location, a cluster address, and an automatically assigned role (leading writes / voting / standing by).
- **Join credential**: a single-use, short-lived, identity-bound token minted by an admin that authorizes exactly one new member to join.
- **Cluster status**: point-in-time view of members, roles, health, leadership, and quorum, exposed for operators and automation.
- **Backup archive**: portable, inspectable snapshot of the complete ledger, produced through any member and usable for online restore or total-loss recovery.

## Success Criteria _(mandatory)_

### Measurable Outcomes

- **SC-001**: A 3-node deployment survives abrupt loss of any one node with zero committed-write loss and resumes full write service within 30 seconds, with no operator action.
- **SC-002**: An operator can go from nothing to a serving single node in one start command plus one config file, and from one node to a 3-node HA cluster in under 15 minutes with zero downtime and zero data migration steps.
- **SC-003**: 100% of the existing functional test surface (login incl. OIDC, issuance, revocation, ACME, encrypted-at-rest fields) passes unchanged against both a single node and a 3-node cluster, with requests distributed across members.
- **SC-004**: During quorum loss, 100% of state-changing requests fail within 10 seconds with a clear unavailable error, while CRL and certificate downloads continue to succeed on surviving nodes.
- **SC-005**: Backup, online restore, and the total-loss recovery procedure each complete successfully on a populated 3-node cluster, with post-restore data (including encrypted fields) fully intact and verifiable on every node.
- **SC-006**: A rolling upgrade of a 3-node cluster across a schema change completes with exactly one schema application and no failed requests attributable to schema state after the upgrade completes.
- **SC-007**: All membership operations (credential mint, join, remove live, remove dead, status) succeed when driven purely via the API by automation, with no interactive input.

## Assumptions

- **Technology direction is fixed by the requester**: raft-replicated SQLite (dqlite) embedded in the binary, with cluster management via microcluster — the established Canonical self-contained-HA pattern. Requirements above are written outcome-first, but solution selection is not open.
- **Single-node = one-voter cluster** (the user's own leaning, adopted as the default): there is no separate plain-SQLite production mode, so the standalone→HA growth path needs no migration.
- **Breaking changes are acceptable**: no production deployments exist; the file-path storage config is removed and no importer for old database files is built.
- **Remaining implementation-level correctness work**: two multi-writer correctness details are pure implementation concerns with no material effect on outcomes, so they are not elevated to requirements here — separate schema-migration bookkeeping between Notary and the embedded authorization system, and per-connection database session settings. Everything else that concurrent, replicated writers put at risk — singleton-state bootstrap races (FR-006), concurrent CRL updates (FR-016), and OIDC login state surviving a callback landing on any member (FR-024) — is specified directly in this document.
- **The external-database mode is out of scope** for this feature but must not be foreclosed (FR-026): a future mode where Notary fully outsources storage to an external database (e.g. a PostgreSQL connection URL) is expected to arrive as a sibling configuration option later.
- **Charm/orchestrator implementation is out of scope** (separate repository); this spec only guarantees the automation-facing surface it needs (FR-010, FR-027).
- **Read scaling and multi-region replication are non-goals**: HA is the goal; CA write rates are low, and quorum-replication write latency is acceptable.
- **All members can reach the same key-wrapping backend** (HSM/Vault) in HA deployments; deployments that cannot satisfy this must not expect encrypted-data service from cut-off members.
