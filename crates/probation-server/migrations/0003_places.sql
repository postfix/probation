-- Slice 6: the portal's places, members, invitations and ranges (03 § portal; 02 § Data).

-- The place a session works in, chosen with the switcher at the top of every page
-- ("org:3" or "personal:5"); checked by `authorized_place` on every use (C29).
ALTER TABLE sessions ADD COLUMN place text;

-- An invitation is listed and cancelled on the organisation page by its id; the address
-- it was mailed to is shown there and never matched against a login (T3).
ALTER TABLE invitations
    ADD COLUMN id integer GENERATED ALWAYS AS IDENTITY UNIQUE,
    ADD COLUMN email text NOT NULL DEFAULT '',
    ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();

GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO probation_app;
