# ADR-001: Local-first production-informed reference

**Status:** Accepted for initial scaffold

## Decision
Implement a multi-tenant document/project reference app locally using Docker Compose. Defer Kubernetes, HA, multi-region and service mesh.

## Rationale
Prioritize IAM protocols, authorization correctness, threat modeling and demonstrable security tests over infrastructure complexity.

## Consequences
The result is a portfolio reference, not a production-ready identity service. Cloud deployment remains optional.
