-- Seed data for the A11Y run (slices 5 to 7): one login per role in Acme and Globex, a
-- personal account, a deleted login (for the C94 page) and an unconfirmed one (C41);
-- for slice 6 a second Acme org admin, a freeze on Acme, a leave request, two network-
-- lock ranges, and keys and activity a firewall reported; for slice 7 a suspended
-- organisation with a member, an approved range, firewall reports and rollouts.
-- Every password is "a11y test passphrase". Run as the migration owner after
-- `probation-server migrate`, on a fresh database; the server then connects as
-- `probation_portal_a11y` (password `probation`), a login role in `probation_app`.

DO $$
BEGIN
    CREATE ROLE probation_portal_a11y LOGIN PASSWORD 'probation' IN ROLE probation_app;
EXCEPTION WHEN duplicate_object OR unique_violation THEN
    NULL;
END
$$;

INSERT INTO orgs (name) VALUES ('Acme'), ('Globex');
INSERT INTO groups (org_id, name) SELECT id, 'Frontend' FROM orgs WHERE name = 'Acme';

CREATE TEMPORARY TABLE seed_logins (email text, login_id integer);
WITH people (email) AS (
    VALUES ('admin@probation.test'), ('ana@acme.test'), ('bob@acme.test'), ('mia@acme.test'),
           ('gus@globex.test'), ('pat@home.test'), ('del@home.test'), ('new@home.test'),
           ('oli@acme.test')
), made AS (
    INSERT INTO logins (created_at) SELECT now() FROM people RETURNING id
)
INSERT INTO seed_logins
SELECT people.email, made.id
FROM (SELECT email, row_number() OVER () AS n FROM people) AS people
JOIN (SELECT id, row_number() OVER (ORDER BY id) AS n FROM made) AS made USING (n);

INSERT INTO sign_in_methods (login_id, kind, subject, email, password_hash, verified_at)
SELECT login_id, 'password', email, email,
       '$argon2id$v=19$m=19456,t=2,p=1$AiZ65zdXOGlBZmKQhUZ0Yg$Ok0aFJmoYtzvwo366bLC6R0GMp6RkFdYhXULrLOtibY',
       CASE WHEN email = 'new@home.test' THEN NULL ELSE now() END
FROM seed_logins;

-- Roles (C4, C27): global admin, org admin, group admin, member, and Globex's admin.
INSERT INTO memberships (login_id, org_id, group_id, role)
SELECT s.login_id, NULL::integer, NULL::integer, 'global_admin' FROM seed_logins AS s WHERE s.email = 'admin@probation.test'
UNION ALL
SELECT s.login_id, o.id, NULL::integer, 'org_admin' FROM seed_logins AS s, orgs AS o
WHERE s.email = 'ana@acme.test' AND o.name = 'Acme'
UNION ALL
SELECT s.login_id, o.id, g.id, 'group_admin' FROM seed_logins AS s, orgs AS o JOIN groups AS g ON g.org_id = o.id
WHERE s.email = 'bob@acme.test' AND o.name = 'Acme'
UNION ALL
SELECT s.login_id, o.id, g.id, 'member' FROM seed_logins AS s, orgs AS o JOIN groups AS g ON g.org_id = o.id
WHERE s.email = 'mia@acme.test' AND o.name = 'Acme'
UNION ALL
SELECT s.login_id, o.id, NULL::integer, 'org_admin' FROM seed_logins AS s, orgs AS o
WHERE s.email = 'gus@globex.test' AND o.name = 'Globex'
UNION ALL
SELECT s.login_id, o.id, NULL::integer, 'org_admin' FROM seed_logins AS s, orgs AS o
WHERE s.email = 'oli@acme.test' AND o.name = 'Acme';

-- Personal accounts: Pat's alone, Ana's beside her organisation, and Del's, deleted two
-- days ago together with Del's login (C85, C94).
INSERT INTO personal_accounts (login_id, deleted_at, restore_until)
SELECT login_id,
       CASE WHEN email = 'del@home.test' THEN now() - interval '2 days' END,
       CASE WHEN email = 'del@home.test' THEN now() + interval '28 days' END
FROM seed_logins WHERE email IN ('pat@home.test', 'ana@acme.test', 'del@home.test');
UPDATE logins SET deleted_at = now() - interval '2 days', restore_until = now() + interval '28 days'
WHERE id = (SELECT login_id FROM seed_logins WHERE email = 'del@home.test');
UPDATE personal_accounts SET deleted_at = l.deleted_at
FROM logins AS l WHERE l.id = personal_accounts.login_id AND l.deleted_at IS NOT NULL;

-- Slice 6. Oli is the org admin the slice 6 run turns an authenticator on for (C24), so
-- the slice 5 run's logins stay as they are; run the slice 6 run once per seeded
-- database.
UPDATE policy_layers SET freeze_seconds = 2 * 86400
WHERE place_kind = 'org' AND place_id = (SELECT id FROM orgs WHERE name = 'Acme');
INSERT INTO leave_requests (login_id, org_id)
SELECT s.login_id, o.id FROM seed_logins AS s, orgs AS o WHERE s.email = 'mia@acme.test' AND o.name = 'Acme';
INSERT INTO org_ip_ranges (org_id, cidr, refused_reason)
SELECT id, '198.51.100.16/28'::cidr, NULL::text FROM orgs WHERE name = 'Acme'
UNION ALL
SELECT id, '0.0.0.0/0'::cidr, 'covers the whole internet' FROM orgs WHERE name = 'Acme';
-- A firewall (its token is never used here) and Mia's key, with what it was refused.
INSERT INTO keys (hash, last4, kind, place_kind, place_id, name)
VALUES (sha256('a11y firewall token'), 'oken', 'firewall', 'platform', 1, 'fw-a11y');
INSERT INTO firewalls (name, token_key_id, allowed_source_cidrs)
SELECT 'fw-a11y', id, '{127.0.0.0/8}' FROM keys WHERE name = 'fw-a11y';
INSERT INTO keys (hash, last4, kind, place_kind, place_id, owner_login, name)
SELECT sha256('a11y mia key'), 'aKey', 'user', 'user', m.id, s.login_id, 'work laptop'
FROM seed_logins AS s JOIN memberships AS m ON m.login_id = s.login_id WHERE s.email = 'mia@acme.test';
INSERT INTO activity (event_id, at, firewall_id, place_kind, place_id, key_id, layer, ecosystem,
                      package, version, result, rule, client_ip, eligible_at)
SELECT e.id, now() - e.ago, f.id, k.place_kind, k.place_id, k.id, e.layer, 'npm', e.package, e.version,
       e.result, e.rule, e.ip::inet, e.eligible
FROM (VALUES
    ('a11y-1', interval '1 hour', 'org', 'left-pad', '1.3.0', 'blocked', 'Block on whole package', NULL, NULL::timestamptz),
    ('a11y-2', interval '2 hours', 'org', 'react-dom', '19.2.1', 'held', 'Freeze: published 6 hours ago, freeze is 2 days', NULL, now() + interval '1 day'),
    ('a11y-3', interval '3 hours', 'network', 'lodash', '4.17.21', 'refused_network', 'Network lock', '203.0.113.42', NULL)
) AS e (id, ago, layer, package, version, result, rule, ip, eligible),
     firewalls AS f, keys AS k
WHERE f.name = 'fw-a11y' AND k.name = 'work laptop';

-- Slice 7. Initech is suspended (C64) and Ivy is its member; Globex holds an approved
-- range; fw-a11y reported OSV unreachable and a refused push, fw-a11y-2 never checked
-- in; one rollout halted on fw-a11y and one went through. The slice 7 run turns on an
-- authenticator for admin@probation.test, so run it once per seeded database.
INSERT INTO orgs (name, status) VALUES ('Initech', 'suspended');
WITH made AS (INSERT INTO logins DEFAULT VALUES RETURNING id)
INSERT INTO seed_logins SELECT 'ivy@initech.test', id FROM made;
INSERT INTO sign_in_methods (login_id, kind, subject, email, password_hash, verified_at)
SELECT login_id, 'password', email, email,
       '$argon2id$v=19$m=19456,t=2,p=1$AiZ65zdXOGlBZmKQhUZ0Yg$Ok0aFJmoYtzvwo366bLC6R0GMp6RkFdYhXULrLOtibY', now()
FROM seed_logins WHERE email = 'ivy@initech.test';
INSERT INTO memberships (login_id, org_id, role)
SELECT s.login_id, o.id, 'member' FROM seed_logins AS s, orgs AS o
WHERE s.email = 'ivy@initech.test' AND o.name = 'Initech';
INSERT INTO org_ip_ranges (org_id, cidr, approved_by)
SELECT o.id, '203.0.113.0/24'::cidr, s.login_id FROM orgs AS o, seed_logins AS s
WHERE o.name = 'Globex' AND s.email = 'admin@probation.test';
INSERT INTO keys (hash, last4, kind, place_kind, place_id, name)
VALUES (sha256('a11y firewall token 2'), 'en 2', 'firewall', 'platform', 1, 'fw-a11y-2');
INSERT INTO firewalls (name, token_key_id, allowed_source_cidrs)
SELECT 'fw-a11y-2', id, '{127.0.0.0/8}' FROM keys WHERE name = 'fw-a11y-2';
INSERT INTO settings_rollouts (created_by, settings_toml, state)
SELECT login_id, 'sync_interval_seconds = 30', 'done' FROM seed_logins WHERE email = 'admin@probation.test'
UNION ALL
SELECT login_id, 'npm_upstream_url = "https://registry.npmjs.org"', 'halted' FROM seed_logins WHERE email = 'admin@probation.test';
INSERT INTO settings_rollout_steps (rollout_id, firewall_id, position, state, sent_at, done_at, error)
SELECT r.id, f.id, 0, CASE r.state WHEN 'done' THEN 'applied' ELSE 'failed' END,
       now() - interval '1 hour', now() - interval '59 minutes',
       CASE r.state WHEN 'halted' THEN 'cannot read /etc/probation/tls/cert.pem' END
FROM settings_rollouts AS r, firewalls AS f WHERE f.name = 'fw-a11y'
UNION ALL
SELECT r.id, f.id, 1, CASE r.state WHEN 'done' THEN 'skipped' ELSE 'pending' END, NULL,
       CASE r.state WHEN 'done' THEN now() - interval '58 minutes' END, NULL
FROM settings_rollouts AS r, firewalls AS f WHERE f.name = 'fw-a11y-2';
UPDATE firewalls SET settings_revision = r.id, settings_toml = r.settings_toml, last_seen_at = now(),
    last_report = jsonb_build_object('report', jsonb_build_object(
        'settings_revision', r.id, 'last_apply_error', 'cannot read /etc/probation/tls/cert.pem',
        'status', jsonb_build_object('upstreams', jsonb_build_object('npm', 'ok', 'pypi', 'ok', 'osv', 'unreachable')),
        'effective_period_seconds', 60, 'version', '0.2.2'), 'activity_dropped', '[]'::jsonb)
FROM settings_rollouts AS r WHERE firewalls.name = 'fw-a11y' AND r.state = 'done';
