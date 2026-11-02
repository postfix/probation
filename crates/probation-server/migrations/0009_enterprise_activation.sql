-- A sample leaf must first have a live good OCSP answer, then a new live
-- revoked answer after the issuer commits revocation, before activation.
CREATE TABLE registry_enterprise_activation_samples (
    org_id integer PRIMARY KEY REFERENCES orgs (id) ON DELETE CASCADE,
    leaf_fingerprint bytea NOT NULL CHECK (length(leaf_fingerprint) = 32),
    root_fingerprint bytea NOT NULL CHECK (length(root_fingerprint) = 32),
    member_uuid uuid NOT NULL,
    expected_ocsp_url text NOT NULL,
    good_checked_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON registry_enterprise_activation_samples TO probation_app;
