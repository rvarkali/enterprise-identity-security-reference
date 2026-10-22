# Historical credential exposure and owner disposition

Updated **2026-10-22 UTC** (2026-10-21 America/Los_Angeles) for final publication
preparation. **All four findings remain OPEN_RISK_ACCEPTED.** This records an
owner risk decision and verified stop-only containment, not credential rotation,
cryptographic invalidation, account disabling or verified session/token revocation.
The candidate remains unpublished; exact-artifact and Git-initialization approval
are separate next steps.

## Evidence and scope

| Reference | Evidence | Classification and limitation |
|---|---|---|
| R1 | Earlier P2.3C/P2.3D assessments recorded publicly accessible credential-bearing development history | Historical exposure acknowledged; third-party copies cannot be recalled or ruled out |
| R2 | Owner statement in the Final Publication Preparation request: development and execution only on the local Mac; never externally deployed; no future deployment planned; PostgreSQL, Keycloak administrator, Alice and Bob credentials not reused outside this project | OPERATOR_REPORTED; not password comparison or independent account inspection |
| R3 | Preceding authorized stop-only execution: eight approved running containers stopped individually; closing Docker metadata showed zero running IAM containers and zero active IAM published port bindings; 56 IAM containers, 27 volumes and 10 networks preserved; 12 unrelated containers unchanged | Verified local Docker metadata at that operation; no database contents or administrative APIs accessed; not a continuing uptime monitor |
| R4 | Owner accepts residual risk from historical credential exposure and confirms the original repository is now private and will remain private | OPERATOR_REPORTED; visibility reduction cannot undo prior disclosure; the original repository was not modified during preparation |
| R5 | Current candidate scans and offline regression | Bounded validation recorded in the [validation summary](portfolio-validation-summary.md) and [manifest](publication-manifest.json); not credential invalidation evidence |

This is one implementation: the private development repository and its derived,
sanitized offline publication candidate. Operational secrets, private PKI, raw
evidence, runtime configuration, database data and Git history are excluded.
Private support records are referenced only by sanitized evidence category.

## Per-finding disposition

The accountable decision maker is the project owner. R2 and R4 apply separately
to every row; they supersede the earlier report that no owner disposition had been
supplied. They do not establish technical closure.

| Finding | Category and known local consumers | Potential retained state | Non-reuse / validity / invalidation | Disposition |
|---|---|---|---|---|
| CRED-001 | PostgreSQL; API eligibility and OpenFGA migration/runtime datastore connections | Retained PostgreSQL volume, possible test copies and backups; externally supplied consumer configuration | Non-reuse outside this project owner-confirmed; credential validity UNKNOWN; invalidation NOT_ESTABLISHED | OPEN_RISK_ACCEPTED — local endpoints stopped; persistent state retained |
| CRED-002 | Keycloak administrator; local administration and provisioning tools | Existing account/session database may remain in the preserved Keycloak writable layer or recoverable copies | Non-reuse outside this project owner-confirmed; credential validity UNKNOWN; invalidation NOT_ESTABLISHED | OPEN_RISK_ACCEPTED — local identity endpoint stopped; no administrator reset/disable claimed |
| CRED-003 | Alice demo account; human login and authentication acceptance | Retained Keycloak account, session/refresh/offline-grant state and potentially issued tokens | Non-reuse outside this project owner-confirmed; credential validity UNKNOWN; invalidation NOT_ESTABLISHED | OPEN_RISK_ACCEPTED — identity and included API acceptors stopped; no individual account/token revocation claimed |
| CRED-004 | Bob demo account; human login and authentication acceptance | Same state categories, assessed as a separate finding | Non-reuse outside this project owner-confirmed; credential validity UNKNOWN; invalidation NOT_ESTABLISHED | OPEN_RISK_ACCEPTED — independent owner disposition; Alice's result is not substituted for Bob's |

No password values were retrieved, compared or tested. No credential rotation,
account modification, database inspection or session/grant revocation was performed.
No finding is CLOSED_WITH_EVIDENCE, technically remediated or proven compromised.
The operator's accepted-risk publication path replaces the earlier requirement
that all four findings first be technically closed; it does not change their open
technical status or grant permission to publish this artifact.

## Containment and persistent-state limitations

- The stop-only operation removed active local IAM endpoints at the recorded check.
  Every identified IAM container had restart policy `no`; manual starts, restored
  containers or host automation can still reactivate the runtime.
- Containers, named volumes, bind-mounted PKI, backups and evidence were preserved.
  In particular, stopping PostgreSQL does not remove stored role verifiers, and
  stopping Keycloak does not reset administrator or demo-user accounts.
- The Keycloak metadata review found an import-directory bind but no mounted
  database volume. Its retained writable layer is potentially sensitive; the
  backend and actual account state were not inspected.
- Ten PostgreSQL helper volumes, rehearsal PKI, isolated gateway state and other
  retained artifacts require separate preservation/disposal decisions. Unattributed
  orphan volumes were not presumed safe or deleted.
- Stopping API acceptors does not revoke signed JWTs. Retained refresh/offline
  sessions or restored acceptors could make old authentication state relevant.
  The human required-exp correction was not deployed before retirement; ordinary
  token-lifetime assumptions are not proof of complete token disposition.
- Historical public copies may persist regardless of the original repository's
  current private visibility. A fresh-history repository does not erase exposure.

## Configuration and future reactivation boundary

The included [API configuration](../../apps/api/src/main/resources/application.yaml),
[realm definition](../../identity/keycloak/realm-import/iam-realm.json) and
[machine provisioning source](../../infrastructure/docker/configure-machine-keycloak.py)
are implementation references, not instructions to deploy this candidate.
PostgreSQL/API/OpenFGA consumers use external credential inputs; Keycloak
bootstrap or realm-import changes do not reset an already initialized account.
The candidate excludes Compose and live acceptance tooling.

No deployment is planned. If that decision changes, reassess all four findings
before any restart or restoration. Separately authorize credential/account
invalidation or rotation, dependent configuration updates, session/token handling,
persistent-copy disposition and narrow validation. Do not use existing Compose
reconciliation as a shortcut: the development source includes undeployed changes.
Any newly discovered reuse or exposure beyond the accepted scope reopens the
owner's risk decision and requires a new response assessment.

## Publication decision and remaining approvals

The owner has selected private retention of the original repository and a reviewed
fresh-history offline portfolio for a new repository. No original history, live
configuration or protected evidence is part of that publication path.

Current disposition: **residual risk accepted by the owner; technical findings
remain open; candidate prepared for separate approval**. Current validation must
pass, the exact manifest/payload must be reviewed, and local Git initialization
must be explicitly approved before it occurs. A commit or push requires separate
authorization. Neither this document nor risk acceptance is permission to publish.

Optional future technical closure requires recorded, finding-specific evidence of
credential/account invalidation or an approved permanent-retirement and retained-
state disposition. Risk acceptance alone must never be relabeled as verified
revocation. The [offline suite guide](../../infrastructure/testing/README.md)
explains the separate test boundary.
