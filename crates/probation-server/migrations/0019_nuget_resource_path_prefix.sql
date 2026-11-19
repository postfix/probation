-- Row 20 (security review F3): a NuGet registry may narrow the resources its service index names to a path prefix
-- of its own host (whole segments). Absent: anywhere on the host, as before. Additive: every row written before
-- reads as before, and an enforcer that does not know the field ignores it (the host-wide rule).
ALTER TABLE registries ADD COLUMN resource_path_prefix text;
ALTER TABLE registries ADD CONSTRAINT registries_resource_path_prefix_check
    CHECK (resource_path_prefix IS NULL OR (ecosystem = 'nuget' AND target_url IS NOT NULL AND length(resource_path_prefix) <= 512));
