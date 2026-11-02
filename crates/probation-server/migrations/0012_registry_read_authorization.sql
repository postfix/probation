-- The administrator's shared download credential is encrypted by the portal.
ALTER TABLE registries ADD COLUMN read_authorization_enc bytea;
