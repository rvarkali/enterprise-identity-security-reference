# Non-Functional and Security Requirements (Draft)

| ID | Requirement / quality gate |
|---|---|
| NFR-01 | All protected operations default to deny if required authz decisions fail or time out. |
| NFR-02 | Resolve resource tenant server-side; never trust client-supplied tenant ID alone. |
| NFR-03 | Do not log passwords, bearer tokens, refresh tokens, or raw sensitive claims. |
| NFR-04 | Automated tests cover cross-tenant IDOR, privilege escalation, invalid JWTs and dependency outages. |
| NFR-05 | Policies and OpenFGA models are versioned, tested, and reviewed with code. |
| NFR-06 | Local developer setup is reproducible with Docker Compose after Phase 1. |
| NFR-07 | Decision logs include correlation ID, subject reference, resource, action, outcome, and policy/model version. |
| NFR-08 | Document revocation behavior and measure observed stale-allow window with and without caching. |
| NFR-09 | Protect SCIM endpoints with scoped service authentication; no anonymous provisioning. |
| NFR-10 | Keep real Entra credentials outside the repository. |

Performance targets are **to be baselined**, not asserted before measurement. This project does not promise production availability or compliance certification.
