-- Slice 5: sign-in, verification, TOTP and throttling (03 § accounts; 02 § Data).

-- An email-and-password method is unusable until its address is confirmed (C41); every
-- other kind is confirmed by its provider when it is created.
ALTER TABLE sign_in_methods
    ADD COLUMN verified_at timestamptz,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

-- A session exists before sign-in, so every form, the sign-in form included, carries a
-- CSRF token bound to it (C101), and an OAuth `state` is bound to it (T12). `pending`
-- holds what a session waits for before it is signed in: the TOTP step, an OAuth
-- round trip, or the choice for a deleted login (C94).
ALTER TABLE sessions
    ALTER COLUMN login_id DROP NOT NULL,
    ADD COLUMN pending jsonb,
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX sessions_login ON sessions (login_id);

-- Single-use emailed links: only the SHA-256 of the token is stored (T14).
CREATE TABLE email_tokens (
    token_hash bytea PRIMARY KEY,
    method_id integer NOT NULL REFERENCES sign_in_methods (id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('verify', 'reset')),
    -- What a sign-up asked for, applied when the address is confirmed (C5, C6).
    payload jsonb NOT NULL DEFAULT '{}',
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

-- The TOTP secret is sealed under PROBATION_SERVER_SECRET_KEY with the login id as AAD
-- (T16). `last_step` refuses a replayed code (T15).
CREATE TABLE totp (
    login_id integer PRIMARY KEY REFERENCES logins (id) ON DELETE CASCADE,
    secret_enc bytea NOT NULL,
    enabled_at timestamptz,
    last_step bigint NOT NULL DEFAULT 0
);

-- Keyed hashes of the 10 backup codes (C39, T16).
CREATE TABLE backup_codes (
    id integer GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login_id integer NOT NULL REFERENCES logins (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at timestamptz
);
CREATE INDEX backup_codes_login ON backup_codes (login_id);

-- Failed sign-in steps, counted over the last 15 minutes per email, client IP and
-- login's TOTP (T15, T32).
CREATE TABLE sign_in_failures (
    scope text NOT NULL CHECK (scope IN ('email', 'ip', 'totp')),
    subject text NOT NULL,
    at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sign_in_failures_subject ON sign_in_failures (scope, subject, at);

GRANT SELECT, INSERT, UPDATE, DELETE ON email_tokens, totp, backup_codes, sign_in_failures
    TO probation_app;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO probation_app;
