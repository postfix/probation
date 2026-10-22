-- Seed data for the A11Y run (slice 5): one login per role in Acme and Globex, a
-- personal account, a deleted login (for the C94 page) and an unconfirmed one (C41).
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
           ('gus@globex.test'), ('pat@home.test'), ('del@home.test'), ('new@home.test')
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
WHERE s.email = 'gus@globex.test' AND o.name = 'Globex';

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
