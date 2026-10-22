# IAM-REQ-v2.0 — Locked requirements baseline

Status: **LOCKED** | Approved: 2026-10-15 | Total: **60**

Scope: identity-centric Zero Trust reference implementation for human, machine, and AI agent identities. Requirement wording and IDs are frozen; changes require a documented change request.

Each requirement must map to a design component and verification evidence.

## ID (6)

| ID | Requirement |
|---|---|
| ID-01 | Support distinct human, machine, and agent identities. |
| ID-02 | Support two isolated enterprise tenants. |
| ID-03 | Maintain identity ownership and tenant associations. |
| ID-04 | Support identity activation and deactivation. |
| ID-05 | Integrate Keycloak as primary identity provider. |
| ID-06 | Support Microsoft Entra ID OIDC federation. |

## AUTH (6)

| ID | Requirement |
|---|---|
| AUTH-01 | Implement OAuth authorization code with PKCE. |
| AUTH-02 | Support OIDC authentication and MFA. |
| AUTH-03 | Validate JWT signature, issuer, audience, and expiration. |
| AUTH-04 | Support session expiration, renewal, and logout. |
| AUTH-05 | Implement OAuth client credentials for machines. |
| AUTH-06 | Demonstrate one SAML federation flow. |

## AZ (8)

| ID | Requirement |
|---|---|
| AZ-01 | Implement tenant-scoped RBAC. |
| AZ-02 | Implement ReBAC with OpenFGA. |
| AZ-03 | Support team/project/document permission inheritance. |
| AZ-04 | Implement ABAC with OPA. |
| AZ-05 | Enforce tenant isolation at resource boundary. |
| AZ-06 | Combine relationship and contextual decisions. |
| AZ-07 | Implement default deny and fail closed. |
| AZ-08 | Test authorization after permission changes. |

## MID (6)

| ID | Requirement |
|---|---|
| MID-01 | Register a machine/service identity. |
| MID-02 | Authenticate S2S with OAuth client credentials. |
| MID-03 | Enforce service-specific scopes and permissions. |
| MID-04 | Implement one mTLS-protected service connection. |
| MID-05 | Validate trusted client certificates. |
| MID-06 | Demonstrate machine credential rotation or revocation. |

## AID (6)

| ID | Requirement |
|---|---|
| AID-01 | Register one distinct AI agent identity. |
| AID-02 | Authenticate agent API requests. |
| AID-03 | Support scoped human-to-agent delegation. |
| AID-04 | Authorize agent access to one MCP tool. |
| AID-05 | Prevent exceeding delegated permissions. |
| AID-06 | Audit agent and delegating user identities. |

## GOV (6)

| ID | Requirement |
|---|---|
| GOV-01 | Demonstrate SCIM user provisioning. |
| GOV-02 | Demonstrate SCIM user deactivation. |
| GOV-03 | Demonstrate group membership updates. |
| GOV-04 | Implement joiner-mover-leaver lifecycle. |
| GOV-05 | Implement one access-review workflow. |
| GOV-06 | Demonstrate time-bound JIT privileged access. |

## ZT (6)

| ID | Requirement |
|---|---|
| ZT-01 | Authenticate every protected request. |
| ZT-02 | Authorize every protected operation. |
| ZT-03 | Enforce least privilege for all identity types. |
| ZT-04 | Demonstrate contextual restrictions. |
| ZT-05 | Re-evaluate permissions after revocation. |
| ZT-06 | Document trust boundaries and enforcement points. |

## SEC (6)

| ID | Requirement |
|---|---|
| SEC-01 | Generate structured authentication and authorization events. |
| SEC-02 | Record identity/resource/action/decision/correlation context. |
| SEC-03 | Detect repeated authorization failures. |
| SEC-04 | Detect suspicious privilege changes. |
| SEC-05 | Detect agent or machine permission violations. |
| SEC-06 | Demonstrate one response action. |

## TEST (5)

| ID | Requirement |
|---|---|
| TEST-01 | Test invalid and expired tokens. |
| TEST-02 | Test cross-tenant authorization bypass. |
| TEST-03 | Test privilege escalation and unauthorized access. |
| TEST-04 | Test mTLS certificate rejection and delegation restrictions. |
| TEST-05 | Test revocation and authorization dependency failures. |

## ARCH (5)

| ID | Requirement |
|---|---|
| ARCH-01 | Provide reproducible Docker Compose environment. |
| ARCH-02 | Document HLD, LLD and security architecture. |
| ARCH-03 | Maintain editable architecture and sequence diagrams. |
| ARCH-04 | Document decisions and tradeoffs. |
| ARCH-05 | Provide automated test evidence and demo guide. |
