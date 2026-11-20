-- Row 24 (code review F5): an OCI registry may declare the origin of the token service its `WWW-Authenticate` challenge names when
-- that is not the registry's own host (GitLab Container Registry, Harbor behind Keycloak). Additive and optional: every row written
-- before reads as before (NULL), and an enforcer that does not know the field ignores it and so keeps refusing such a realm (fail closed).
ALTER TABLE registries ADD COLUMN token_origin text;
ALTER TABLE registries ADD CONSTRAINT registries_token_origin_check
    CHECK (token_origin IS NULL OR (ecosystem = 'oci' AND target_url IS NOT NULL AND length(token_origin) <= 2048));
