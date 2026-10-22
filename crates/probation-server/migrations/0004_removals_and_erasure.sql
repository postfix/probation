-- Slice 6 follow-ups: removed members and erasing logins.

-- A member an org admin removed (or whose leave an org admin approved) is not added back
-- by the organisation's SSO, by sign-in or by linking; only accepting an invitation
-- clears the row (C128).
CREATE TABLE org_removals (
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    PRIMARY KEY (org_id, login_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON org_removals TO probation_app;

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
