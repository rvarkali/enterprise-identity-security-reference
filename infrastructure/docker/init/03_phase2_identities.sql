-- Phase 2 deterministic demo identities. Use only in local reference environment.
INSERT INTO principals(id,kind,display_name) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','HUMAN','Alice (ACME)'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','HUMAN','Bob (GLOBEX)')
ON CONFLICT (id) DO NOTHING;
INSERT INTO principal_identities(principal_id,issuer,subject) VALUES
 ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa','http://localhost:8081/realms/iam-reference','11111111-1111-4111-8111-111111111111'),
 ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb','http://localhost:8081/realms/iam-reference','22222222-2222-4222-8222-222222222222')
ON CONFLICT (issuer,subject) DO NOTHING;
INSERT INTO tenant_principals(tenant_id,principal_id)
SELECT t.id, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'::uuid FROM tenants t WHERE t.slug='acme'
ON CONFLICT DO NOTHING;
INSERT INTO tenant_principals(tenant_id,principal_id)
SELECT t.id, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'::uuid FROM tenants t WHERE t.slug='globex'
ON CONFLICT DO NOTHING;
