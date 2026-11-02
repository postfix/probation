CREATE TABLE registry_delete_origins (
    registry_id bigint NOT NULL REFERENCES registries(id) ON DELETE CASCADE,
    origin text NOT NULL,
    path_prefix text NOT NULL,
    forward_bearer boolean NOT NULL DEFAULT false,
    PRIMARY KEY (registry_id, origin, path_prefix)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON registry_delete_origins TO probation_app;
