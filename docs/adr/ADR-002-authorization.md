# ADR-002: Compose OpenFGA and OPA decisions

**Status:** Proposed

## Decision
Use OpenFGA for relationship entitlements, OPA for contextual constraints, and application-enforced tenant ownership. Protected operations require all applicable checks to allow.

## Alternatives
Only application RBAC; only OpenFGA; only OPA.

## Open questions
How to version policies/models, minimize latency, handle outages, and preserve revocation semantics.
