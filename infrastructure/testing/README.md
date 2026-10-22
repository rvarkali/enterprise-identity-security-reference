# Offline security regression

From the repository root:

```sh
python3 infrastructure/testing/security_regression.py
```

Requires Python 3.9+, Maven, a full **JDK 21** (including keytool), cached Maven
dependencies/plugins, and permission to bind temporary local sockets. Set
`JAVA21_HOME` to select JDK 21; otherwise `JAVA_HOME`, macOS JDK discovery, or
the resolved `java` executable is used and checked. A different Java major fails.
Dependency installation is a separate explicit preparation step: this runner
always uses Maven offline mode and never downloads tools or starts Docker.

Included existing tests:

| Area | Tests |
|---|---|
| Human signature/issuer/audience/required-exp | HumanJwtSecurityChainTest |
| Machine JWT, certificate binding, listener and TLS boundaries | MachineSecurityTest, MachineSecurityChainTest, MachineCertificateBindingTest, MachineTlsTest |
| Eligibility, tenant/resource decisions | AuthorizationServiceTest, ResourceRepositoryTest, ResourceEndpointsTest |
| Dependency failure handling | OpenFgaClientTest, OpaClientTest |
| Provisioning/configuration safety | test_machine_keycloak, test_generate, test_deploy, test_fixtures |
| Optional native policy/model checks | `opa check/test`; `fga model validate/test` (embedded ephemeral model testing) |

The Java HTTP clients/DB interfaces are mocked except temporary JWKS and embedded
TLS servers owned by the tests. Hardcoded service-shaped URLs in mock tests are
request assertions, not live calls. TLS tests generate disposable synthetic keys;
they never read existing private PKI. Python tests mock service/subprocess effects;
an audit hook additionally rejects socket connections/binds and subprocess launches.

Excluded: environment-gated LeaverEligibilityTest, JoinerServiceTest,
ActivationJournalServiceTest and OpenFgaJoinerLiveTest; Docker-backed shell runners,
gateway topology/integration tests, live acceptance/provisioning scripts and all
other unselected Java tests. These can mutate databases, containers or service
state and need separately authorized isolated fixtures. No environment variable
can opt them into this runner. PostgreSQL coverage here is mocked logic, not SQL
integration. This suite does not rerun Nginx/Compose/realm-import acceptance.

Child processes receive an allowlisted environment, without IAM credentials,
integration triggers or inherited JVM options. Maven uses empty temporary settings
but the existing local dependency cache. Optional CLIs use a fresh HOME. Native OPA
and FGA are optional (repository references: OPA 1.3.0, FGA CLI 0.8.2); absent tools
produce SKIP, installed tools that fail produce FAIL, never a silent skip.

Maven builds a temporary copy of API source. Existing target reports are untouched.
Temporary Logback/JUL configuration suppresses framework logging while retaining
sanitized client warnings and in-memory audit events required by existing tests. Subprocess output
is captured rather than echoed, and JWT/private-key markers plus known synthetic
password markers are checked before success. Temporary reports and generated test
material are removed on normal success/failure. A forced process/host termination
can leave temporary files; this is not a universal secret scanner or OS network
sandbox. Audit newly added tests before expanding the explicit allowlist.

Expected output: PASS prerequisites, Java count, four Python counts, optional
PASS/SKIP lines, then PASS overall. Missing required tools/cache, test failures,
unexpected selected-test skips and detected sensitive output return exit code 1.
Raw failure output is deliberately suppressed; investigate with synthetic fixtures
and reviewed logging rather than enabling token/request debug logs.

**Offline regression is not live acceptance or deployment authorization.**

## Publication-candidate scope

The selected suite and its source dependencies are included. The other Java suites
and live deployment scripts listed as excluded above are absent or outside the
supported execution scope. Do not run retained provisioning/fixture/PKI helpers
directly: they are supplied for implementation review and mocked-test imports.
Compose and the gateway deployment are not included. No live lab is reproducible
from this candidate.
