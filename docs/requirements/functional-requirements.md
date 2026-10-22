# Functional Requirements (Draft v0.1)

| ID | Requirement | Priority | Phase |
|---|---|---|---|
| FR-01 | Authenticate users through Keycloak-hosted login | Must | 2 |
| FR-02 | Support OIDC authorization code + PKCE | Must | 2 |
| FR-03 | Validate JWT signature, issuer, audience, expiry | Must | 2 |
| FR-04 | Support secure session refresh and logout | Must | 2 |
| FR-05 | Require MFA for a configured test user | Must | 2 |
| FR-06 | Create tenants, teams, projects and documents | Must | 3 |
| FR-07 | Enforce tenant-scoped RBAC | Must | 3 |
| FR-08 | Enforce direct, team, and inherited permissions via OpenFGA | Must | 4 |
| FR-09 | Evaluate contextual ABAC constraints via OPA | Must | 5 |
| FR-10 | Log authorization decisions without tokens/secrets | Must | 6 |
| FR-11 | Revoke permissions and measure observed propagation | Must | 6 |
| FR-12 | Demonstrate Entra ID OIDC federation through Keycloak | Should | 7 |
| FR-13 | Demonstrate SAML federation with a test IdP | Should | 7 |
| FR-14 | Demonstrate SCIM user/group create/update/deactivate | Should | 7 |
| FR-15 | Provide repeatable automated authorization and security tests | Must | 8 |

## Personas
- ACME admin Alice; ACME editor Bob; ACME viewer Carol
- GLOBEX admin David; GLOBEX editor Emma
- Contractor with time-limited access; provisioning administrator

## Core use cases
1. Alice signs in using OIDC and MFA and creates a project in ACME.
2. Alice grants the Platform team editor access to a project; Bob inherits document edit rights.
3. Carol cannot delete a project; David cannot read ACME documents.
4. Contractor access is denied after expiry despite a valid relationship.
5. Removing Bob from the team removes inherited rights.
6. Deactivating a user via SCIM prevents further authorized access.
