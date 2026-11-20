-- Row 24: an OCI registry may declare the origin and path prefix its blobs are redirected to (Docker Hub, GHCR, Quay, ECR, Harbor with
-- object storage and Artifactory answer a blob download with a redirect to a signed storage URL). The column and the descriptor field
-- exist since 0016; this only widens who may hold one from Cargo, Go, NuGet, Maven and Conan registries to those and OCI registries (a
-- target is still required). Additive: every row written before reads as before, and an enforcer that does not know the field ignores it,
-- so it keeps refusing the redirect (fail closed). The ecosystem tag `oci` is carried since 0014.
--
-- The constraint is found by what it constrains, never by a guessed name (0017, 0018, 0020 and 0021 did the same).
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
    CHECK (archive_origin IS NULL OR (ecosystem IN ('cargo', 'go', 'nuget', 'maven', 'conan', 'oci') AND target_url IS NOT NULL AND length(archive_origin) <= 2048));
