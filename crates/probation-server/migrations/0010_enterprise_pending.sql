ALTER TABLE registry_certificate_providers
    DROP CONSTRAINT registry_certificate_providers_kind_check;
ALTER TABLE registry_certificate_providers
    ADD CONSTRAINT registry_certificate_providers_kind_check
    CHECK (kind IN ('probation', 'pending', 'organisation'));
