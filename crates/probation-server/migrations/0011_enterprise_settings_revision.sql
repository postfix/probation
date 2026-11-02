ALTER TABLE registry_certificate_providers
    ADD COLUMN settings_revision bigint NOT NULL DEFAULT 0;
