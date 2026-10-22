# Portfolio security validation summary

This record separates historical evidence, current offline validation, verified
stop-only runtime containment and owner-reported risk decisions. Final preparation
was reviewed on **2026-10-22 UTC** (2026-10-21 America/Los_Angeles). This is not a
security certification, credential revocation record or deployment acceptance.
The candidate is one sanitized derivative of the development implementation.
Post-publication status reviewed **2026-10-22 America/Los_Angeles**: the sanitized
offline reference is [published on GitHub](https://github.com/rvarkali/enterprise-identity-security-reference)
with fresh publication history. This documentation review does not rerun tests,
perform live acceptance, commit changes or push updates.

## Retained final-preparation execution — VERIFIED_OFFLINE

The supported runner was inspected before execution. Its explicit selection uses
mocked dependencies, test-owned temporary JWKS/TLS servers and generated synthetic
fixtures. It builds in a temporary directory, uses Maven offline resolution and
restricts child environments/output. The Python harness rejects socket and
subprocess effects. No existing IAM service, Docker environment, actual credential
or operational PKI was accessed. This is bounded execution evidence, not an OS-level
network-isolation certification.

| Execution item | Observed result |
|---|---|
| Command, from candidate root | `python3 infrastructure/testing/security_regression.py` |
| Started / completed UTC | 2026-10-22T05:29:23Z / 2026-10-22T05:29:45Z (observed execution window) |
| Exit status | 0 |
| Java | 187 passed; 0 failures, errors or skips |
| Python | 72 passed; 0 failures, errors or skips |
| Python module counts | test_machine_keycloak: 56; test_generate: 3; test_deploy: 4; test_fixtures: 9 |
| Required selected total | 259 passed; no failed or skipped selected tests |
| Native OPA / OpenFGA | Two optional checks SKIPPED: executables unavailable; outside required P0 scope |
| Tool versions | Python 3.14.6; JDK 21.0.10; Maven 3.9.16 |
| Cache / execution prerequisites | Required parent POMs and build-plugin families present; successful Maven offline execution confirmed remaining cache sufficiency |
| Local permissions | Previously established sandbox socket restriction; approved escalation used for test-owned local sockets |
| Candidate/test identity | 47-file regression input inventory; SHA-256 below and in the manifest |

Regression input SHA-256:
`43e773331ea77961e70c171e4c4a07379998901a6ed48db95a9bbc7cdf5d7433`.
The [manifest](publication-manifest.json) records the input paths and deterministic
hashing convention. It includes optional policy/model fixture inputs without
claiming those native checks ran. Documentation/license edits do not alter this
test-input identity. The complete candidate payload has a separate manifest hash;
the manifest does not hash itself.

The initial invocation safely rejected Java 25 before running tests. Selecting the
installed JDK 21 with `JAVA21_HOME` allowed the same command to pass. No test or
production code was changed, and no dependencies were installed. The earlier P0
run also passed 187 Java and 72 Python tests; it remains historical evidence.

The fresh run did not rerun browser acceptance, native policy/model evaluation,
Compose/Nginx/Keycloak import checks, live SQL or deployment rollback. Historical
P2.2E6, P2.3G and P2.3H results remain historical, even where their counts match.

## Runtime retirement and owner disposition

The preceding **Authorized Stop-Only Runtime Retirement** execution verified that
all eight approved running IAM containers were stopped, with zero IAM containers
running and zero active IAM published Docker port bindings afterward. All 56 IAM
containers, 27 volumes and 10 networks were preserved; the 12 unrelated containers
were unchanged. Restart policies remained `no`. This is the recorded Docker
metadata result, not account inspection or an ongoing runtime monitor. Final
publication preparation did not operate Docker or contact live IAM services.

The owner confirms local-Mac-only use, no external deployment, no future deployment
plans, and no reuse outside this project of PostgreSQL, Keycloak administrator,
Alice or Bob credentials. The owner accepts residual risk from historical exposure
and confirms private retention of the original repository. These are
**OPERATOR_REPORTED** statements, not independent password/reuse or visibility
verification. Historical public exposure remains acknowledged.

All four findings are **OPEN_RISK_ACCEPTED**. No credential rotation, invalidation,
account disabling or verified session/token revocation is claimed. Persistent
storage and container writable layers remain; restoration could reactivate old
state. The current owner decision supersedes the previous insufficient-evidence
publication hold with an explicit accepted-risk preparation path, without claiming
technical remediation. See the [per-finding disposition](public-credential-exposure-response.md).

## Publication status and evidence boundaries

| Label | Current evidence boundary |
|---|---|
| IMPLEMENTED | Included human/machine authentication and ordered authorization source |
| HISTORICALLY_TESTED | Prior isolated/live observations and earlier offline runs below |
| VERIFIED_OFFLINE | Retained 259-test final-preparation run; execution window and test-input identity recorded above; no test rerun in this documentation review |
| CURRENTLY_VERIFIED | Post-publication repository metadata, local documentation links and manifest integrity; earlier scan and stop-only evidence retain their original scope |
| OPERATOR_REPORTED | Local-only scope, credential non-reuse, no future deployment, original repository Private visibility and residual-risk acceptance |
| EXCLUDED | Compose, gateway, administration/lifecycle implementation, live acceptance, runtime configuration and protected PKI/evidence |
| NOT_VERIFIED | Credential validity, invalidation/revocation, preserved account/session contents and deployment equivalence |

Read-only GitHub metadata now confirms `rvarkali/enterprise-identity-security-reference`
is **PUBLIC and nonempty, with default branch main**. Its main-branch commit matched
the clean local checkout at the start of this review. The earlier empty-repository
observation was a pre-publication check and is no longer the current status.
No repository content was uploaded or overwritten by this review. The original
repository was not modified; its Private visibility remains owner-reported.

The [manifest](publication-manifest.json) hashes all 88 payload files and excludes
itself and Git metadata, for 89 publication files total. It records the published
baseline separately from this local documentation revision. Documentation hashes
change with these edits; the 47-file regression input identity is unchanged.
The existing MIT license remains owner-approved. These local edits are not yet
committed or pushed. Runtime restart remains outside the offline publication scope.

## Candidate scope

Supported reproduction is the included offline security regression runner.
Compose, the TLS deployment override, gateway, administrative/lifecycle components
and live acceptance tooling are excluded. Remaining Dockerfiles, SQL, configuration
examples and provisioning helpers are implementation/test references, not a complete
deployment package. Historical E1–E9 evidence describes the development repository;
some referenced implementation and reports are intentionally omitted here.
The [portfolio README](../../README.md) supplies the essential architecture overview.

## Evidence classifications

| Classification | Meaning |
|---|---|
| VERIFIED_OFFLINE | Selected tests passed using mocks or test-owned local fixtures, without existing IAM services |
| VERIFIED_ISOLATED | A bounded check passed in a disposable environment; equivalence to the live deployment is not implied |
| HISTORICALLY_VERIFIED_LIVE | A specific prior live observation was recorded; not a current deployment check |
| OPERATOR_REPORTED | A result attributed to an operator, not independently observed by the reviewer |
| PARTIAL | Implementation or evidence exists, but the full capability is not closed |
| NOT_IMPLEMENTED | The stated capability is absent, even if planned |
| NOT_TESTED | The specified validation was not performed in the cited scope |

These labels apply to individual claims, not an entire component indiscriminately.
Source presence alone is not execution evidence.

## Evidence references

The matrix uses the following sanitized references. Protected reports are cited by
milestone category only; their contents, paths and operational identifiers are not
publication assets. Codex reports mean the explicitly attributed execution reports
from the development session, not independently downloadable test artifacts.

| Reference | Evidence basis |
|---|---|
| E1 | P2.1F retained human-authentication summary and explicitly operator-reported acceptance record; implementation context in the human flow (development-repository reference; omitted from this candidate) |
| E2 | P2.1I/J retained missing-exp reproduction/remediation summaries and P2.1L packaging summary; [human regression source](../../apps/api/src/test/java/dev/portfolio/iam/HumanJwtSecurityChainTest.java) |
| E3 | Historical B5 observations summarized in the security validation report (development-repository reference; omitted from this candidate) |
| E4 | P2.1M retained isolated rollback summary and P2.1N procedure review; operations context (development-repository reference; omitted from this candidate) is guidance, not proof of execution |
| E5 | Codex P2.2E1 execution report: 40 positive ignore checks, 19 negative controls; [.gitignore](../../.gitignore) |
| E6 | Codex P2.2E2 execution report: isolated Nginx syntax, callback logging and routing checks; [nginx configuration](../../apps/web/nginx.conf) |
| E7 | Codex P2.2E3 execution report: static client assertions and successful fresh isolated Keycloak import; [realm definition](../../identity/keycloak/realm-import/iam-realm.json) |
| E8 | Codex P2.2E4 execution report: two reserved-character credential cases, isolated migration/server/database checks and Compose environment validation; Compose source (development-repository reference; omitted from this candidate) |
| E9 | Codex P2.2E5 execution report: 14 missing/empty/legacy-only credential cases and mocked successful acceptance sequence; acceptance runner (development-repository reference; omitted from this candidate) |
| E10 | Codex P2.2E6 successful consolidated execution, exit code 0; [regression runner](../../infrastructure/testing/security_regression.py) and [suite guide](../../infrastructure/testing/README.md). Temporary raw reports were removed; counts are attributed to that execution |

Earlier reports retain their original scope and counts. E10 and the matrix below
are HISTORICALLY_TESTED evidence; the separate current final-preparation record above does not
upgrade any historical live or isolated claim. The
[portfolio README](../../README.md) uses the same evidence boundaries.

## Historical security validation matrix — HISTORICALLY_TESTED

| Security control | Implementation component | Validation method | Observed result | Evidence | Classification | Limitations |
|---|---|---|---|---|---|---|
| Human OIDC/PKCE | React OIDC client and Keycloak public client | Source/dependency review; operator browser reports; isolated hardened realm import | Login/logout and authorization successes reported by operator; client configuration assertions and import passed | E1, E7 | OPERATOR_REPORTED; VERIFIED_ISOLATED for import; PARTIAL overall | Browser S256 request/state-tampering checks and complete independent browser regression remain NOT_TESTED in cited acceptance scope; import is not login proof |
| Human JWT required-exp | Spring Boot human decoder/security chain | Real decoder and filters with synthetic signed tokens and local JWKS | Valid token accepted; missing-exp, expired, wrong-audience/issuer and invalid-signature cases rejected | E2, E10 | VERIFIED_OFFLINE | Corrected image packaged but not deployed; no new production-signed negative tests |
| Machine OAuth2/JWT | Machine provisioning and dedicated JWT chain | Mock provisioning and synthetic JWT tests; prior actual client-credentials requests | Selected tests passed; historical valid machine request accepted and invalid JWT rejected | E3, E10 | VERIFIED_OFFLINE; HISTORICALLY_VERIFIED_LIVE | Bounded configured-client evidence; no current machine acceptance or generalized onboarding claim |
| Machine certificate binding | Certificate identity authorization | Synthetic certificate tests and historical trusted-wrong-identity case | Wrong URI identity denied after TLS acceptance; valid identity accepted historically | E3, E10 | VERIFIED_OFFLINE; HISTORICALLY_VERIFIED_LIVE | Application identity association, not OAuth certificate-thumbprint-bound tokens |
| Machine listener isolation | Connector-aware guard, separate HTTP/TLS listeners | Test-owned embedded TLS servers; historical cross-listener requests | Machine routes denied on human listener and human routes denied on machine listener | E3, E10 | VERIFIED_OFFLINE; HISTORICALLY_VERIFIED_LIVE | Shared API process; historical proxy denial does not establish current nginx image provenance |
| PostgreSQL eligibility | Principal resolution, resource repository, authorization service | Mocked JDBC eligibility/ownership tests | Selected eligibility, query-binding and fail-closed assertions passed | E10 | VERIFIED_OFFLINE | Not live SQL or full dependency-backed authorization acceptance |
| OpenFGA relationship authorization | OpenFGA client, model and resource gate | Mock HTTP failure handling; offline fixture tests | Denial, malformed/unavailable responses and fixture conflicts handled as asserted | E10 | VERIFIED_OFFLINE | Native model checks skipped; isolated datastore connectivity in E8 is not relationship-decision acceptance |
| OPA policy authorization | OPA client, Rego policy and ordered resource gate | Mock HTTP/client and endpoint tests | Denied/malformed/unavailable decisions do not grant access; earlier gates cannot be bypassed | E10 | VERIFIED_OFFLINE | Native Rego checks skipped in consolidated run; no new live policy traversal |
| Multi-tenant isolation | PostgreSQL ownership and resource endpoints | Synthetic endpoint/fixture tests; operator authorization reports | Cross-tenant denials and ownership assertions passed offline; operator reported successful tenant scenarios | E1, E10 | VERIFIED_OFFLINE; OPERATOR_REPORTED | Operator reports do not independently prove each live dependency decision |
| Credential configuration hardening | Ignore rules, external credential inputs, Compose and realm definition | Path controls, missing-input tests, static assertions and disposable integration | Scoped exclusions and external-input checks passed; reserved-character credentials worked for migration/server; no realm-password fallback | E5, E7, E8, E9 | VERIFIED_OFFLINE; VERIFIED_ISOLATED | Historical public exposure established; invalidation remains unverified; current owner non-reuse/risk decision is recorded separately; ignore rules do not sanitize Git history |
| OIDC callback access logging | Nginx exact callback location | Synthetic callbacks plus SPA/API/denial requests in isolated Nginx | Callback access-log entries suppressed; normal logging and routing retained | E6 | VERIFIED_ISOLATED | Fix not deployed; no assertion about all error logs or other logging layers |
| Certificate lifecycle | Development generator, validation tests and rotation runbook | Offline validity preflight tests; synthetic TLS fixtures; procedure review | Selected validity/TLS tests passed; manual lifecycle guidance exists | E10; PKI guide (development-repository reference; omitted from this candidate) | VERIFIED_OFFLINE for selected tests; PARTIAL overall | No complete dedicated rotation acceptance summary; automated rotation/revocation not established |
| Isolated rollback | Configuration cloning, handoff and recovery rehearsal | Disposable startup/handoff with injected acceptance and startup failures | Prior container restored in the recorded isolated scenarios | E4 | VERIFIED_ISOLATED | Synthetic dependencies/material; revised procedure review is not a second complete rehearsal or live authorization acceptance |
| Security regression reproducibility | Explicit Java/Python suite runner | Offline Maven, mock-based Python tests and output checks | 259 selected tests passed; runner exited 0 | E10 | VERIFIED_OFFLINE | Optional native tools unavailable; environment-gated/live suites excluded; output scan is bounded |

## Reproduce the offline suite

From the repository root:

```sh
python3 infrastructure/testing/security_regression.py
```

Requires JDK 21, Python 3.9+, Maven with cached dependencies/plugins and permission
for temporary test sockets. Set `JAVA21_HOME` as described in the suite guide.
No existing IAM credentials, operational PKI or Docker Compose deployment is needed.

| Historical P2.2E6 result (not the current execution) | Count/status |
|---|---|
| Java security tests | **187 passed**, zero failures/errors/skips |
| Python security tests | **72 passed**, zero failures/errors/skips |
| Total selected tests | **259 passed** |
| OPA native executable | Unavailable / **skipped — NOT_TESTED in this run** |
| OpenFGA native executable | Unavailable / **skipped — NOT_TESTED in this run** |

The native checks are not counted as passes. Test-owned sockets and generated
synthetic TLS fixtures are distinct from live IAM access. Mocked eligibility and
client tests do not establish live end-to-end PostgreSQL–OpenFGA–OPA acceptance.

## Deployment, capability and publication limits

- **Last retained deployment status:** corrected human JWT image, Nginx callback
  logging fix and Compose credential/healthcheck corrections were not deployed;
  Keycloak client hardening was not imported into the then-running realm. Current
  deployment equivalence is NOT_VERIFIED. Editing files does not change live state.
- **Machine identity:** selected offline coverage and bounded historical live
  positive/negative observations exist; current deployment acceptance was not
  performed. The machine endpoint demonstrates authenticated liveness, not policy
  evaluation. Current certificate validity and deployed-image equivalence are not
  established by these historical observations.
- **Runtime retired by stopping, not deletion:** the owner plans no deployment.
  Earlier API replacement gates were not exercised or cleared by retirement.
  Offline success does not authorize restart, deployment or restoration.
- **NOT_IMPLEMENTED:** full SCIM provisioning and Microsoft Entra ID integration.
  Entra remains deferred; the README's PLANNED label describes intent, not delivery.
- **PARTIAL:** full joiner/mover/leaver lifecycle and trusted live MFA assurance.
  The default policy path lacks trusted assurance; synthetic policy demonstrations
  are not proof of a live second-factor-backed authorization decision.
- **NOT_TESTED in E10:** native OPA/FGA checks and environment-gated/live integration
  suites. Full browser/security acceptance and current human-to-machine token
  isolation also remain open acceptance work.
- **Publication is separate:** historical exposure persists as an accepted residual
  risk. Non-reuse and original Private visibility are owner-reported; credential
  invalidation is not established. All four findings remain technically open.
  The sanitized offline reference has been published with fresh history. This
  documentation revision does not change technical credential status or establish
  production readiness, live integration acceptance or deployment authorization.

See the threat model (development-repository reference; omitted from this candidate) and
Zero Trust architecture (development-repository reference; omitted from this candidate) for additional trust assumptions.
