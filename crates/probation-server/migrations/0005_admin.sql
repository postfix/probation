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
