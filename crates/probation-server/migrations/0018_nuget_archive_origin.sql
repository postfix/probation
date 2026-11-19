-- Row 20: a NuGet registry may declare the origin and path prefix its packages are redirected to (GitHub
-- Packages, Azure Artifacts and Artifactory with cloud storage answer a .nupkg with a redirect to their
-- storage). The column and the descriptor field exist since 0016; this only widens who may hold one from
-- Cargo and Go registries to Cargo, Go and NuGet registries (a target is still required). Additive: every row
-- written before reads as before, and an enforcer that does not know the field ignores it, so it keeps
-- refusing the redirect (fail closed).
--
-- The constraint is found by what it constrains, never by a guessed name (0017 did the same).
DO $$
DECLARE
    found text;
BEGIN
    FOR found IN
        SELECT conname FROM pg_constraint
        WHERE conrelid = 'registries'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%archive_origin%'
    LOOP
        EXECUTE format('ALTER TABLE registries DROP CONSTRAINT %I', found);
    END LOOP;
END
$$;
ALTER TABLE registries ADD CONSTRAINT registries_archive_origin_check
    CHECK (archive_origin IS NULL OR (ecosystem IN ('cargo', 'go', 'nuget') AND target_url IS NOT NULL AND length(archive_origin) <= 2048));
