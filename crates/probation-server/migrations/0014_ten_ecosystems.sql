-- Row 17: the shared nine-family identities. Each constraint that names the ecosystem is
-- widened in place to the nine selected tags (npm, pypi, maven, go, cargo, nuget,
-- rubygems, conan, oci). Widening only: every old row satisfies the new constraint, so
-- old rows reopen unchanged and no data is rewritten or recreated. A server binary older
-- than this migration refuses to decode a row of a new tag (see `policy::ecosystem_of`),
-- and downgrading the database is not supported; new rows are never deleted to make it so.
ALTER TABLE policy_blocks DROP CONSTRAINT policy_blocks_ecosystem_check;
ALTER TABLE policy_blocks ADD CONSTRAINT policy_blocks_ecosystem_check
    CHECK (ecosystem IN ('npm', 'pypi', 'maven', 'go', 'cargo', 'nuget', 'rubygems', 'conan', 'oci'));
ALTER TABLE policy_exceptions DROP CONSTRAINT policy_exceptions_ecosystem_check;
ALTER TABLE policy_exceptions ADD CONSTRAINT policy_exceptions_ecosystem_check
    CHECK (ecosystem IN ('npm', 'pypi', 'maven', 'go', 'cargo', 'nuget', 'rubygems', 'conan', 'oci'));
ALTER TABLE activity DROP CONSTRAINT activity_ecosystem_check;
ALTER TABLE activity ADD CONSTRAINT activity_ecosystem_check
    CHECK (ecosystem IN ('npm', 'pypi', 'maven', 'go', 'cargo', 'nuget', 'rubygems', 'conan', 'oci'));
ALTER TABLE registries DROP CONSTRAINT registries_ecosystem_check;
ALTER TABLE registries ADD CONSTRAINT registries_ecosystem_check
    CHECK (ecosystem IN ('npm', 'pypi', 'maven', 'go', 'cargo', 'nuget', 'rubygems', 'conan', 'oci'));
