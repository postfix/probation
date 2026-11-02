-- `admin after-restore` (C129, slice 8) moves the settings rollouts' id sequence past
-- every rollout id a firewall may still report from before a database restore, so a
-- new rollout never takes one. Reading and setting the sequence needs these two.
GRANT SELECT, UPDATE ON SEQUENCE settings_rollouts_id_seq TO probation_app;
