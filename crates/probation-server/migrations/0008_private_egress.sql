-- Exact organization destination and CIDR proposals. Only a global operator may
-- approve; approval is read in the same live certificate-admission snapshot.
CREATE TABLE registry_private_egress (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    org_id integer NOT NULL REFERENCES orgs(id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('registry', 'ocsp')),
    host text NOT NULL CHECK (length(host) BETWEEN 1 AND 253),
    port integer NOT NULL CHECK (port BETWEEN 1 AND 65535),
    cidr cidr NOT NULL,
    requested_by integer NOT NULL REFERENCES logins(id),
    approved_by integer REFERENCES logins(id),
    approved_at timestamptz,
    CHECK ((approved_by IS NULL) = (approved_at IS NULL)),
    UNIQUE (org_id, purpose, host, port, cidr)
);
CREATE INDEX registry_private_egress_approved
    ON registry_private_egress(org_id, purpose, host, port)
    WHERE approved_at IS NOT NULL;
GRANT SELECT, INSERT, UPDATE, DELETE ON registry_private_egress TO probation_app;
GRANT USAGE, SELECT ON SEQUENCE registry_private_egress_id_seq TO probation_app;
