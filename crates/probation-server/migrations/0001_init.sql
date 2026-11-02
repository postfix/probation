-- Every table of 02-architecture.md § Data. Run as the migration owner role
-- (`probation-server migrate`, PROBATION_SERVER_MIGRATE_DATABASE_URL), which needs
-- CREATEROLE for the first run. The server connects as a login role that is a member
-- of `probation_app`, so the app role owns nothing (T17).

-- Several test databases on one cluster migrate at once: the second CREATE ROLE loses
-- the race on pg_authid's unique index rather than seeing the role.
DO $$
BEGIN
    CREATE ROLE probation_app NOLOGIN;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END
$$;

CREATE TABLE logins (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,
    restore_until timestamptz
);

CREATE TABLE orgs (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    deleted_at timestamptz,
    restore_until timestamptz,
    activity_retention_days integer CHECK (activity_retention_days >= 7),
    audit_retention_days integer CHECK (audit_retention_days >= 7),
    sso_issuer text,
    sso_client_id text,
    sso_client_secret_enc bytea,
    -- The Google `hd` or Microsoft `tid` the SSO callback requires (T2).
    sso_allowed_tenant text,
    UNIQUE (sso_issuer, sso_client_id)
);
-- Typed on /signin (C37), so one spelling names one organisation.
CREATE UNIQUE INDEX orgs_name ON orgs (lower(name));

-- Sign-in looks up by (kind, issuer, subject[, org_id]) only, never by email (C75).
CREATE TABLE sign_in_methods (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('password', 'google', 'github', 'microsoft', 'oidc')),
    issuer text NOT NULL DEFAULT '',
    subject text NOT NULL,
    org_id integer REFERENCES orgs (id) ON DELETE CASCADE,
    email text,
    password_hash text,
    UNIQUE NULLS NOT DISTINCT (kind, issuer, subject, org_id)
);
CREATE UNIQUE INDEX sign_in_methods_password_email ON sign_in_methods (lower(email))
    WHERE kind = 'password';

CREATE TABLE sessions (
    id_hash bytea PRIMARY KEY,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    csrf_token text NOT NULL,
    expires_at timestamptz NOT NULL,
    totp_ok boolean NOT NULL DEFAULT false,
    scope_org_id integer REFERENCES orgs (id) ON DELETE CASCADE
);

-- No two approved ranges overlap (C87).
CREATE TABLE org_ip_ranges (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    cidr cidr NOT NULL,
    approved_by integer REFERENCES logins (id),
    refused_reason text,
    EXCLUDE USING gist (cidr inet_ops WITH &&) WHERE (approved_by IS NOT NULL)
);

CREATE TABLE personal_accounts (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id integer NOT NULL UNIQUE REFERENCES logins (id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    deleted_at timestamptz,
    restore_until timestamptz
);

CREATE TABLE groups (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    name text NOT NULL,
    UNIQUE (id, org_id)
);

-- One row per login and organisation (C10: at most one group there). A global admin is
-- the row with no organisation. `id` is the user place's id: a login has one user layer
-- in each organisation it belongs to.
CREATE TABLE memberships (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    org_id integer REFERENCES orgs (id) ON DELETE CASCADE,
    group_id integer,
    role text NOT NULL CHECK (role IN ('member', 'group_admin', 'org_admin', 'global_admin')),
    UNIQUE NULLS NOT DISTINCT (login_id, org_id),
    FOREIGN KEY (group_id, org_id) REFERENCES groups (id, org_id) ON DELETE SET NULL (group_id),
    CHECK ((org_id IS NULL) = (role = 'global_admin')),
    CHECK (role <> 'group_admin' OR group_id IS NOT NULL)
);

CREATE TABLE invitations (
    token_hash bytea PRIMARY KEY,
    org_id integer REFERENCES orgs (id) ON DELETE CASCADE,
    group_id integer,
    role text NOT NULL CHECK (role IN ('member', 'group_admin', 'org_admin', 'global_admin')),
    created_by integer NOT NULL REFERENCES logins (id),
    expires_at timestamptz NOT NULL,
    accepted_by integer REFERENCES logins (id),
    FOREIGN KEY (group_id, org_id) REFERENCES groups (id, org_id) ON DELETE CASCADE,
    CHECK ((org_id IS NULL) = (role = 'global_admin'))
);

CREATE TABLE leave_requests (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    org_id integer NOT NULL REFERENCES orgs (id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    approved_by integer REFERENCES logins (id),
    UNIQUE (login_id, org_id)
);

-- One layer per place. Platform is place 1; the other places get theirs from the
-- triggers below, so no place exists without a layer.
CREATE TABLE policy_layers (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    place_kind text NOT NULL CHECK (place_kind IN ('platform', 'org', 'group', 'user', 'personal')),
    place_id integer NOT NULL,
    revision bigint NOT NULL DEFAULT 1,
    freeze_seconds bigint CHECK (freeze_seconds >= 0),
    osv_mode text CHECK (osv_mode IN ('off', 'log_only', 'on')),
    allow_exceptions boolean NOT NULL DEFAULT false,
    allow_osv_off boolean NOT NULL DEFAULT false,
    allow_shorter_freeze boolean NOT NULL DEFAULT false,
    UNIQUE (place_kind, place_id)
);

-- A package or version block always has ecosystem and name (C31); a file block carries
-- only its digest, as today's format does (C119).
CREATE TABLE policy_blocks (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    layer integer NOT NULL REFERENCES policy_layers (id) ON DELETE CASCADE,
    ecosystem text CHECK (ecosystem IN ('npm', 'pypi')),
    name text,
    version text,
    digest_algorithm text CHECK (digest_algorithm IN ('sha256', 'sha512')),
    digest text,
    reason text,
    CHECK (
        (digest IS NULL AND digest_algorithm IS NULL AND ecosystem IS NOT NULL AND name IS NOT NULL)
        OR (digest IS NOT NULL AND digest_algorithm IS NOT NULL
            AND ecosystem IS NULL AND name IS NULL AND version IS NULL)
    )
);
CREATE INDEX policy_blocks_layer ON policy_blocks (layer);

CREATE TABLE policy_exceptions (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    layer integer NOT NULL REFERENCES policy_layers (id) ON DELETE CASCADE,
    ecosystem text NOT NULL CHECK (ecosystem IN ('npm', 'pypi')),
    name text NOT NULL,
    version text,
    lifts_block boolean NOT NULL,
    lifts_freeze boolean NOT NULL,
    lifts_osv boolean NOT NULL
);
CREATE INDEX policy_exceptions_layer ON policy_exceptions (layer);

-- Every credential, by the SHA-256 of its text only (C99). `last4` is for display.
CREATE TABLE keys (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    hash bytea NOT NULL UNIQUE CHECK (length(hash) = 32),
    last4 text NOT NULL,
    kind text NOT NULL CHECK (kind IN ('user', 'service', 'automation', 'firewall')),
    place_kind text NOT NULL CHECK (place_kind IN ('platform', 'org', 'group', 'user', 'personal')),
    place_id integer NOT NULL,
    owner_login integer REFERENCES logins (id) ON DELETE SET NULL,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX keys_place ON keys (place_kind, place_id);

-- A writer takes the next revision from the locked counter row inside its own
-- transaction, so revisions become visible in commit order (T7).
CREATE TABLE change_counter (
    id integer PRIMARY KEY CHECK (id = 1),
    value bigint NOT NULL,
    pruned_through bigint NOT NULL
);
INSERT INTO change_counter (id, value, pruned_through) VALUES (1, 0, 0);

CREATE TABLE change_log (
    revision bigint PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    kind text NOT NULL CHECK (kind IN ('key', 'layer', 'place', 'limits', 'ranges', 'settings', 'firewall')),
    subject jsonb NOT NULL
);
CREATE INDEX change_log_at ON change_log (at);

CREATE TABLE firewalls (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name text NOT NULL,
    token_key_id bigint NOT NULL UNIQUE REFERENCES keys (id),
    allowed_source_cidrs cidr[] NOT NULL,
    settings_toml text NOT NULL DEFAULT '',
    settings_revision bigint NOT NULL DEFAULT 0,
    last_seen_at timestamptz,
    last_report jsonb,
    retired_at timestamptz
);

CREATE TABLE settings_rollouts (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    created_by integer NOT NULL REFERENCES logins (id),
    settings_toml text NOT NULL,
    state text NOT NULL CHECK (state IN ('running', 'halted', 'done'))
);

CREATE TABLE settings_rollout_steps (
    rollout_id integer NOT NULL REFERENCES settings_rollouts (id) ON DELETE CASCADE,
    firewall_id integer NOT NULL REFERENCES firewalls (id),
    position integer NOT NULL,
    state text NOT NULL CHECK (state IN ('pending', 'sent', 'applied', 'failed', 'timed_out', 'skipped')),
    PRIMARY KEY (rollout_id, firewall_id),
    UNIQUE (rollout_id, position)
);

-- Append-only for the app role (T17): no foreign keys, so purging a login or an
-- organisation never touches it.
CREATE TABLE audit_log (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at timestamptz NOT NULL DEFAULT now(),
    actor_login integer,
    actor_is_global_admin boolean NOT NULL,
    org_id integer,
    action text NOT NULL,
    subject text NOT NULL,
    before jsonb,
    after jsonb
);
CREATE INDEX audit_log_org_at ON audit_log (org_id, at);

-- The place comes from `key_id`, never from the firewall's report (T9, T18).
CREATE TABLE activity (
    event_id text NOT NULL,
    at timestamptz NOT NULL,
    firewall_id integer NOT NULL REFERENCES firewalls (id),
    place_kind text NOT NULL CHECK (place_kind IN ('platform', 'org', 'group', 'user', 'personal')),
    place_id integer NOT NULL,
    key_id bigint NOT NULL REFERENCES keys (id),
    layer text NOT NULL CHECK (layer IN ('platform', 'org', 'group', 'user', 'personal', 'network', 'none')),
    ecosystem text CHECK (ecosystem IN ('npm', 'pypi')),
    package text,
    version text,
    result text NOT NULL CHECK (result IN ('blocked', 'held', 'would_block', 'refused_revoked', 'refused_suspended', 'refused_network')),
    rule text NOT NULL,
    client_ip inet CHECK (client_ip IS NULL OR result = 'refused_network'),
    eligible_at timestamptz,
    UNIQUE (firewall_id, event_id)
);
CREATE INDEX activity_place_at ON activity (place_kind, place_id, at);

-- `scope_id` NULL is the default for that kind; a row with an id overrides it (C28, C67).
CREATE TABLE limits (
    scope_kind text NOT NULL CHECK (scope_kind IN ('org', 'personal')),
    scope_id integer,
    rate_per_min integer NOT NULL CHECK (rate_per_min > 0),
    max_keys integer NOT NULL CHECK (max_keys >= 0),
    max_service_keys integer CHECK (max_service_keys >= 0),
    UNIQUE NULLS NOT DISTINCT (scope_kind, scope_id)
);
INSERT INTO limits (scope_kind, scope_id, rate_per_min, max_keys, max_service_keys) VALUES
    ('personal', NULL, 1200, 5, NULL),
    ('org', NULL, 6000, 20, 50);

CREATE TABLE platform_settings (
    id integer PRIMARY KEY CHECK (id = 1),
    activity_retention_days integer NOT NULL DEFAULT 90 CHECK (activity_retention_days >= 7),
    audit_retention_days integer NOT NULL DEFAULT 365 CHECK (audit_retention_days >= 7)
);
INSERT INTO platform_settings (id) VALUES (1);

CREATE TABLE email_outbox (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    to_address text NOT NULL,
    template text NOT NULL,
    payload jsonb NOT NULL,
    attempts integer NOT NULL DEFAULT 0,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz
);

-- The platform layer. Nothing is seeded into it: empty means OSV Off and freeze 0
-- below (C125).
INSERT INTO policy_layers (place_kind, place_id) VALUES ('platform', 1);

CREATE FUNCTION place_layer() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO policy_layers (place_kind, place_id) VALUES (TG_ARGV[0], NEW.id);
    RETURN NEW;
END
$$;
CREATE TRIGGER org_layer AFTER INSERT ON orgs
    FOR EACH ROW EXECUTE FUNCTION place_layer('org');
CREATE TRIGGER group_layer AFTER INSERT ON groups
    FOR EACH ROW EXECUTE FUNCTION place_layer('group');
CREATE TRIGGER user_layer AFTER INSERT ON memberships
    FOR EACH ROW WHEN (NEW.org_id IS NOT NULL) EXECUTE FUNCTION place_layer('user');
CREATE TRIGGER personal_layer AFTER INSERT ON personal_accounts
    FOR EACH ROW EXECUTE FUNCTION place_layer('personal');

-- The organisation a place belongs to, or NULL for the platform and personal accounts:
-- the org log an audit row is listed in.
CREATE FUNCTION place_org(kind text, id integer) RETURNS integer
    LANGUAGE sql STABLE AS $$
    SELECT CASE kind
        WHEN 'org' THEN id
        WHEN 'group' THEN (SELECT g.org_id FROM groups AS g WHERE g.id = place_org.id)
        WHEN 'user' THEN (SELECT m.org_id FROM memberships AS m WHERE m.id = place_org.id)
    END;
$$;

-- Audit retention (T17, C26, C68): each organisation's cutoff from its override or the
-- platform default, never newer than 7 days. No argument, so the caller cannot choose
-- a cutoff; it runs with the owner's rights because the app role cannot DELETE.
CREATE FUNCTION prune_audit() RETURNS bigint
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
    WITH gone AS (
        DELETE FROM public.audit_log AS a
        WHERE a.at < now() - make_interval(days => GREATEST(7, COALESCE(
            (SELECT o.audit_retention_days FROM public.orgs AS o WHERE o.id = a.org_id),
            (SELECT p.audit_retention_days FROM public.platform_settings AS p WHERE p.id = 1))))
        RETURNING 1
    )
    SELECT count(*) FROM gone;
$$;
REVOKE ALL ON FUNCTION prune_audit() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prune_audit() TO probation_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO probation_app;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_log FROM probation_app;
REVOKE ALL ON _sqlx_migrations FROM probation_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO probation_app;
