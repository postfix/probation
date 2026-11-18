-- LS-F12: whether a registry serves the public package namespace, so its package names may
-- be sent to OSV. Additive and nullable with no default: a row written before this
-- migration reads NULL, the descriptor omits the field, and the enforcer applies its
-- default rule (Public), so no existing behaviour changes.
ALTER TABLE registries ADD COLUMN osv_scope text CHECK (osv_scope IN ('public', 'private'));
