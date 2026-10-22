# ADR-003 — Identity and Authorization Data Ownership

**Status:** Proposed for review — Phase 0D.

**Decision:** Keycloak/federated IdP owns credentials and authentication sessions; PostgreSQL owns canonical principals, tenant memberships, resource ownership, delegation/lifecycle workflows and audit records; OpenFGA owns relationship grants; OPA owns contextual policies as code.

**Rationale:** Avoid duplicated grants and stale JWT role claims; preserve strong tenant invariants; make permission revocation effective independently of token expiry.

**Tradeoffs:** DB/OpenFGA updates are not atomic; explicit workflow states, idempotent retries and reconciliation are needed. Per-request current-state checks add latency. Polymorphic resource references require service-level validation.

**Alternatives rejected:** Storing all grants in PostgreSQL alongside OpenFGA; using email as identity key; trusting tenant ID from browser context; embedding long-lived effective grants in JWTs.
