# Phased Roadmap

| Phase | Name | Exit gate |
|---|---|---|
| 0 | Requirements and architecture | Requirements, diagrams, data model, ADRs reviewed |
| 1 | Local foundation | Compose services and API/UI skeleton start successfully |
| 2 | Authentication/OIDC/MFA | Successful login and negative JWT tests |
| 3 | Tenancy/RBAC | Tenant escape tests fail securely; scoped roles work |
| 4 | OpenFGA/ReBAC | Direct, team and inherited permissions tested |
| 5 | OPA/ABAC | Context policies and combined decision tests pass |
| 6 | Audit/revocation/failure modes | Decision records, removal tests, dependency outage tests |
| 7 | Entra/SAML/SCIM demos | Federation and lifecycle demonstrations verified |
| 8 | Integration and portfolio | Reproducible demo, test report, architecture walkthrough |

**Estimated duration:** 8–10 weeks part-time; adjust after Phase 1. Work sequentially and avoid expanding scope before exit gates pass.
