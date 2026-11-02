-- SR-17: Permissions for privacy-preserving voter logs.
--
-- The application may insert privacy-safe voter events.
-- It cannot read, modify or delete these records.

REVOKE ALL ON TABLE voter_privacy_log FROM PUBLIC;

GRANT INSERT ON TABLE voter_privacy_log TO evp_app;

GRANT USAGE ON SEQUENCE voter_privacy_log_id_seq TO evp_app;