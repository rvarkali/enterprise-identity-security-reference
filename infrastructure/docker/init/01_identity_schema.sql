-- Phase 0D: Proposed PostgreSQL DDL. Review and migration-test before applying.
-- Requires pgcrypto for gen_random_uuid() on older PostgreSQL versions.
CREATE TABLE tenants (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), slug text NOT NULL UNIQUE,
 display_name text NOT NULL, status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','SUSPENDED'))
);
CREATE TABLE principals (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), kind text NOT NULL CHECK (kind IN ('HUMAN','MACHINE','AGENT')),
 display_name text NOT NULL, status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE principal_identities (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), principal_id uuid NOT NULL REFERENCES principals(id),
 issuer text NOT NULL, subject text NOT NULL, UNIQUE (issuer, subject)
);
CREATE TABLE tenant_principals (
 tenant_id uuid NOT NULL REFERENCES tenants(id), principal_id uuid NOT NULL REFERENCES principals(id),
 status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','DISABLED')),
 PRIMARY KEY (tenant_id, principal_id)
);
CREATE TABLE teams (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 name text NOT NULL, UNIQUE (id, tenant_id), UNIQUE (tenant_id, name)
);
CREATE TABLE projects (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 name text NOT NULL, UNIQUE (id, tenant_id)
);
CREATE TABLE documents (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 project_id uuid NOT NULL, name text NOT NULL,
 classification text NOT NULL DEFAULT 'INTERNAL' CHECK (classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL')),
 UNIQUE (id, tenant_id), FOREIGN KEY (project_id, tenant_id) REFERENCES projects(id, tenant_id)
);
CREATE TABLE agent_delegations (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 delegator_id uuid NOT NULL, agent_id uuid NOT NULL,
 resource_type text NOT NULL CHECK (resource_type IN ('PROJECT','DOCUMENT','MCP_TOOL')),
 resource_id uuid NOT NULL, action text NOT NULL,
 status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','REVOKED')),
 issued_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz NOT NULL,
 revoked_at timestamptz, CHECK (expires_at > issued_at),
 CHECK (delegator_id <> agent_id),
 FOREIGN KEY (tenant_id, delegator_id) REFERENCES tenant_principals(tenant_id, principal_id),
 FOREIGN KEY (tenant_id, agent_id) REFERENCES tenant_principals(tenant_id, principal_id)
);
CREATE INDEX idx_delegation_active ON agent_delegations (tenant_id, agent_id, expires_at) WHERE status='ACTIVE';
CREATE TABLE jit_requests (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL,
 requester_id uuid NOT NULL, approver_id uuid, requested_permission text NOT NULL,
 resource_type text NOT NULL, resource_id uuid NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','DENIED','EXPIRED','REVOKED')),
 created_at timestamptz NOT NULL DEFAULT now(), expires_at timestamptz,
 FOREIGN KEY (tenant_id, requester_id) REFERENCES tenant_principals(tenant_id, principal_id),
 FOREIGN KEY (tenant_id, approver_id) REFERENCES tenant_principals(tenant_id, principal_id)
);
CREATE TABLE access_reviews (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 reviewer_id uuid NOT NULL, subject_id uuid NOT NULL,
 resource_type text NOT NULL, resource_id uuid NOT NULL, permission text NOT NULL,
 status text NOT NULL DEFAULT 'PENDING' CHECK (status IN ('PENDING','APPROVED','REVOKED')),
 reviewed_at timestamptz,
 FOREIGN KEY (tenant_id, reviewer_id) REFERENCES tenant_principals(tenant_id, principal_id),
 FOREIGN KEY (tenant_id, subject_id) REFERENCES tenant_principals(tenant_id, principal_id)
);
CREATE TABLE audit_events (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), occurred_at timestamptz NOT NULL DEFAULT now(),
 tenant_id uuid REFERENCES tenants(id), actor_id uuid REFERENCES principals(id),
 correlation_id text NOT NULL, event_type text NOT NULL,
 resource_type text, resource_id text, action text,
 outcome text NOT NULL CHECK (outcome IN ('ALLOW','DENY','ERROR','INFO')),
 reason_codes jsonb NOT NULL DEFAULT '[]'::jsonb, policy_version text
);
CREATE INDEX idx_audit_tenant_time ON audit_events(tenant_id, occurred_at DESC);
CREATE TABLE security_findings (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id uuid NOT NULL REFERENCES tenants(id),
 rule_id text NOT NULL, severity text NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH')),
 status text NOT NULL DEFAULT 'OPEN' CHECK (status IN ('OPEN','ACKNOWLEDGED','RESOLVED')),
 created_at timestamptz NOT NULL DEFAULT now(), correlation_id text
);
-- Follow-up migration hardening:
-- 1. Enforce HUMAN delegator / AGENT delegatee with a transaction-safe trigger or service validation.
-- 2. Verify polymorphic resource_type/resource_id resolves to an actual same-tenant resource.
-- 3. Restrict audit INSERT/UPDATE/DELETE privileges by DB role; consider immutable append-only storage.
-- 4. Reconcile OpenFGA tuples after workflow state changes; never trust DB roles as effective grants.
