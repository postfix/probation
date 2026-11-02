-- Slice 6 follow-ups: removed members and erasing logins.

-- A member an org admin removed is not added back by the organisation's SSO, by sign-in
-- or by linking; accepting an invitation created after `removed_at` clears the row (an
-- older one is refused, AC3), and it goes with the login when that is erased. An
-- approved leave writes none (C128, C130).
CREATE TABLE org_removals (
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    removed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, login_id)
);
-- The same by the SSO identity the removed login held, so a new login with that identity
-- (after the method was unlinked, say) is not added back either while the removed login
-- exists; erasing the removed login erases this too (C130).
CREATE TABLE org_sso_removals (
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    removed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (org_id, issuer, subject)
);
-- When a login stopped being an org admin of an organisation (demoted, removed or left).
-- For 30 days after, only a global admin resets its authenticator, so an org admin cannot
-- demote another admin, reset them and promote them back (C39, S6-4).
CREATE TABLE former_org_admins (
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    until timestamptz NOT NULL,
    PRIMARY KEY (org_id, login_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_removals, org_sso_removals, former_org_admins
    TO probation_app;

-- The purge erases a login past its 30 days (C33). An erased login's invitation links go
-- with it, sent or accepted: a spent link is deleted, never reopened by a NULL.
ALTER TABLE invitations
    DROP CONSTRAINT invitations_created_by_fkey,
    ADD CONSTRAINT invitations_created_by_fkey
        FOREIGN KEY (created_by) REFERENCES logins (id) ON DELETE CASCADE,
    DROP CONSTRAINT invitations_accepted_by_fkey,
    ADD CONSTRAINT invitations_accepted_by_fkey
        FOREIGN KEY (accepted_by) REFERENCES logins (id) ON DELETE CASCADE;
ALTER TABLE leave_requests
    DROP CONSTRAINT leave_requests_approved_by_fkey,
    ADD CONSTRAINT leave_requests_approved_by_fkey
        FOREIGN KEY (approved_by) REFERENCES logins (id) ON DELETE SET NULL;
-- A range stays approved when the purge erases the login that approved it: approval is
-- `approved_by IS NOT NULL` (the sync API's network lock and the overlap constraint), so
-- the id is kept as history, like audit_log.actor_login, with no foreign key.
ALTER TABLE org_ip_ranges DROP CONSTRAINT org_ip_ranges_approved_by_fkey;
