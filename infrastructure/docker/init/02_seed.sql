INSERT INTO tenants(slug, display_name) VALUES ('acme','ACME Corporation'),('globex','Globex Corporation') ON CONFLICT (slug) DO NOTHING;
