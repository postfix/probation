-- Row 18: the origin and path prefix a Cargo registry's archives (the `dl` of its config.json) may
-- be fetched from when they are not under its target (Artifactory keeps `.../index` and
-- `.../crates` apart). Additive and nullable with no default: a row written before this migration
-- reads NULL, the descriptor omits the field, and the enforcer requires the archives to lie under
-- the target, exactly as before. Only a Cargo registry with a target may carry one.
ALTER TABLE registries ADD COLUMN archive_origin text
    CHECK (archive_origin IS NULL OR (ecosystem = 'cargo' AND target_url IS NOT NULL AND length(archive_origin) <= 2048));
