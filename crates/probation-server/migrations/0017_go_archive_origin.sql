-- Row 19: a Go registry may declare the origin and path prefix its zips are redirected to (a private
-- proxy in redirect mode, Athens or Artifactory with cloud storage, answers a zip with a 302 to its
-- bucket). The column and the descriptor field exist since 0016; this only widens who may hold one
-- from Cargo registries to Cargo and Go registries (a target is still required). Additive: every
-- row written before reads as before, and an enforcer that does not know the field ignores it, so it
-- keeps refusing the redirect (fail closed).
--
-- 0016 declared its CHECK on the column but it names two other columns, so Postgres gave it a table
-- level name of its own; the constraint is found by what it constrains, never by a guessed name.
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
    CHECK (archive_origin IS NULL OR (ecosystem IN ('cargo', 'go') AND target_url IS NOT NULL AND length(archive_origin) <= 2048));
