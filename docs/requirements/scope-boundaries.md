# Scope boundaries — v2.0

**In scope:** two seeded tenants; one end-to-end scenario per capability; Keycloak, PostgreSQL, Spring Boot, React, OpenFGA, OPA; one S2S mTLS link; one agent and one protected MCP tool; Entra OIDC federation and a minimal SAML/SCIM demo; lightweight JML, JIT, access review and rule-based detections.

**Out of scope:** production deployment, Kubernetes, service mesh, SPIRE, enterprise network segmentation, real device posture, complete IGA/PAM/SIEM platforms, multi-agent orchestration, full SCIM compliance, HA and production SLAs.

**Dependency rule:** agent-trust and agenttrust-platform are optional future reuse candidates, not required dependencies. GraphQL and AI log analysis repositories are empty and are not dependencies.

**Quality gate:** each major capability has one successful demo, one negative security test and documented tradeoffs.
