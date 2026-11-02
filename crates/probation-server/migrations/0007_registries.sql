-- Public client identity and selected registry state. Private client keys are never stored here.
ALTER TABLE memberships
    ADD COLUMN certificate_uuid uuid NOT NULL DEFAULT gen_random_uuid() UNIQUE,
    ADD COLUMN package_access_disabled_at timestamptz;

CREATE TABLE registry_certificate_providers (
    org_id integer PRIMARY KEY REFERENCES orgs (id) ON DELETE CASCADE,
    kind text NOT NULL DEFAULT 'probation' CHECK (kind IN ('probation', 'organisation')),
    self_service boolean NOT NULL DEFAULT true,
    issuer_key_enc bytea,
    issuer_cert_pem text,
    issuer_fingerprint bytea CHECK (issuer_fingerprint IS NULL OR length(issuer_fingerprint) = 32),
    expected_ocsp_url text,
    identity_field text NOT NULL DEFAULT 'uri_san_membership_uuid'
        CHECK (identity_field = 'uri_san_membership_uuid'),
    CHECK (kind = 'probation' OR (issuer_key_enc IS NULL AND NOT self_service))
);

CREATE TABLE registry_certificate_roots (
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    fingerprint bytea NOT NULL CHECK (length(fingerprint) = 32),
    certificate_pem text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    PRIMARY KEY (org_id, fingerprint)
);

CREATE TABLE registry_member_certificates (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    membership_id integer NOT NULL REFERENCES memberships (id) ON DELETE CASCADE,
    issuer_fingerprint bytea NOT NULL CHECK (length(issuer_fingerprint) = 32),
    leaf_fingerprint bytea NOT NULL UNIQUE CHECK (length(leaf_fingerprint) = 32),
    serial bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    issued_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (issuer_fingerprint, serial)
);
CREATE INDEX registry_member_certificates_member ON registry_member_certificates (membership_id, revoked_at);

CREATE TABLE registries (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    ecosystem text NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name text NOT NULL,
    target_url text,
    trusted boolean NOT NULL DEFAULT false,
    removed_at timestamptz,
    UNIQUE (id, org_id)
);
CREATE INDEX registries_live_org ON registries (org_id, ecosystem) WHERE removed_at IS NULL;

-- Slice 1's single-origin adapter has one stable npm registry ID per organisation.
INSERT INTO registries (org_id, ecosystem, name)
SELECT id, 'npm', 'Default npm' FROM orgs;

CREATE FUNCTION seed_org_registry() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO registries (org_id, ecosystem, name) VALUES (NEW.id, 'npm', 'Default npm');
    RETURN NEW;
END
$$;
CREATE TRIGGER seed_org_registry AFTER INSERT ON orgs
    FOR EACH ROW EXECUTE FUNCTION seed_org_registry();

CREATE FUNCTION refuse_registry_target_change() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF OLD.target_url IS NOT NULL AND NEW.target_url IS DISTINCT FROM OLD.target_url THEN
        RAISE EXCEPTION 'registry target is immutable';
    END IF;
    IF NEW.org_id IS DISTINCT FROM OLD.org_id OR NEW.ecosystem IS DISTINCT FROM OLD.ecosystem THEN
        RAISE EXCEPTION 'registry identity is immutable';
    END IF;
    RETURN NEW;
END
$$;
CREATE TRIGGER refuse_registry_target_change BEFORE UPDATE ON registries
    FOR EACH ROW EXECUTE FUNCTION refuse_registry_target_change();

GRANT SELECT, INSERT, UPDATE, DELETE ON registry_certificate_providers,
    registry_certificate_roots, registry_member_certificates, registries TO probation_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO probation_app;
