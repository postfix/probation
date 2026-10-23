-- Slice 7: global admins, the fleet, automation tokens and retention (03 § accounts,
-- keys, fleet, audit, portal; 02 § Data).

-- S7-1: purging the login that started a rollout keeps the rollout.
ALTER TABLE settings_rollouts
    ALTER COLUMN created_by DROP NOT NULL,
    DROP CONSTRAINT settings_rollouts_created_by_fkey,
    ADD CONSTRAINT settings_rollouts_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES logins (id) ON DELETE SET NULL,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

-- When a step was released to its firewall, so one that does not report success within
-- 3 of its intervals times out, and the error a failed one reported (C70, C71).
ALTER TABLE settings_rollout_steps
    ADD COLUMN sent_at timestamptz,
    ADD COLUMN done_at timestamptz,
    ADD COLUMN error text;

-- The automation token a push was made with; `actor_login` names its creator (C86).
ALTER TABLE audit_log ADD COLUMN actor_token bigint;

-- When an org admin asked for a range, for the operator's list (C77).
ALTER TABLE org_ip_ranges ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

-- At most 100 years of either log: a longer cutoff overflows the timestamp, so the prune
-- and every activity upload would fail (C68).
ALTER TABLE platform_settings
    ADD CONSTRAINT platform_settings_activity_retention_max CHECK (activity_retention_days <= 36500),
    ADD CONSTRAINT platform_settings_audit_retention_max CHECK (audit_retention_days <= 36500);
ALTER TABLE orgs
    ADD CONSTRAINT orgs_activity_retention_max CHECK (activity_retention_days <= 36500),
    ADD CONSTRAINT orgs_audit_retention_max CHECK (audit_retention_days <= 36500);

-- The purge must be able to erase a global admin who approved a range or sent an
-- invitation (C33, C94). As slice 6's 0004 does, and idempotent with it: a range stays
-- approved, `approved_by` kept as history with no foreign key; an erased login's
-- invitation links go with it, never reopened by a NULL `accepted_by`.
ALTER TABLE org_ip_ranges DROP CONSTRAINT IF EXISTS org_ip_ranges_approved_by_fkey;
ALTER TABLE invitations
    DROP CONSTRAINT IF EXISTS invitations_created_by_fkey,
    ADD CONSTRAINT invitations_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES logins (id) ON DELETE CASCADE,
    DROP CONSTRAINT IF EXISTS invitations_accepted_by_fkey,
    ADD CONSTRAINT invitations_accepted_by_fkey
        FOREIGN KEY (accepted_by) REFERENCES logins (id) ON DELETE CASCADE;
