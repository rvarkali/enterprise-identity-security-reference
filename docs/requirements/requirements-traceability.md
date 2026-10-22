# Requirements traceability — initial mapping

| IDs | Architecture component | Milestone | Verification evidence |
|---|---|---|---|
| ID-01–06 | Identity registry, Keycloak, federation | M1/M4 | Identity lifecycle and federation tests |
| AUTH-01–06 | Keycloak, Spring Security | M1/M4 | OIDC/OAuth/SAML flows and negative JWT tests |
| AZ-01–08 | API PEP, OpenFGA, OPA | M2 | Allow/deny policy matrix |
| MID-01–06 | Service client, mTLS server | M3 | Certificate and OAuth S2S tests |
| AID-01–06 | Agent registry, delegation, MCP adapter | M3 | Delegation boundary tests |
| GOV-01–06 | SCIM adapter, lifecycle and JIT workflows | M4 | JML/JIT/access review scenarios |
| ZT-01–06 | Shared enforcement and context resolver | M2–M5 | Cross-identity zero-trust tests |
| SEC-01–06 | Audit store, rule evaluator | M5 | Detection and response fixtures |
| TEST-01–05 | Security test suites | M5 | CI test report |
| ARCH-01–05 | Docker, docs, CI | M0–M5 | Reproducible setup and demo |

This is a group-level initial mapping; expand to individual test IDs during LLD.
