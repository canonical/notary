# Snap release checklist

The production track is `1`. Main publishes only to `1/edge`; stable is a
manual promotion of an accepted candidate revision, never a rebuild.

## Prerequisites

- Confirm Store ownership and release permissions for the existing `1` track.
- Check the main workflow for the exact commit: Go tests/lint/vet, frontend
  tests, Gosec, snap lifecycle tests, and snap dependency scans must all pass.
- Record commit, snap revision, architecture, artifact SHA-256, dependency scan
  results, and known limitations. Current snap CI covers amd64 only.
- The snap pins Bun 1.3.14 and libdqlite 1.18.7~noble1. The latter is supplied by
  `ppa:dqlite/dev`; this remains a release dependency requiring maintainer
  approval and a security-update plan. Update the pin deliberately and rerun
  acceptance. If that package disappears, fail the build rather than silently
  taking an unqualified version.
- High/critical dependency findings block publication. Triage findings rather
  than disabling the gate. A scan is not a substitute for security review.

## Candidate acceptance

With Store-authorized credentials, substitute the tested revision:

```shell
snapcraft release notary <revision> 1/candidate
```

The automated lifecycle test installs in strict confinement, initializes an
administrator, uploads a CSR and certificate, checks restart and configuration
changes, rejects live backup, restores a cold backup, replaces the local snap,
and reverts it. Replacement uses the same build, so it tests lifecycle mechanics,
not cross-version schema compatibility.

Before stable, also record results from disposable hosts for:

- Installation from `1/candidate`, service enablement across a real reboot,
  HTTPS/UI/login, certificate signing/revocation, and persisted data.
- Three confined snap members: sequential join, writes through every member,
  leader loss, rejoin, member removal, and quorum-loss recovery from backup.
- Coordinated refresh one member at a time under writes, interruption during
  refresh, and healthy service on the new revision. For subsequent releases,
  use the previous stable revision as the starting point, test mixed versions,
  and establish whether revert can read the resulting schema.
- Vault-backed initialization and decrypt after restart/restore. Qualify any
  claimed HSM support on the exact device, SDK, connector, and architecture.
- A candidate soak period appropriate to the intended workload; retain logs
  and test evidence and obtain release-owner approval.

The first production release makes no compatibility promise for pre-release
tracks. Do not skip backup/restore or persistence tests on that basis.

## Stable promotion

Promote the exact candidate revision that passed acceptance:

```shell
snapcraft release notary <revision> 1/stable
snapcraft status notary
```

Publish release notes, operational limitations, and the qualified upgrade/revert
path. Snap revert does not restore data or configuration in `SNAP_COMMON`.
Follow the deployment guide's coordinated refresh procedure for clusters.