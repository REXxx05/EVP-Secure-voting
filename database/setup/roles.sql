
-- roles.sql
-- Apply application permissions after all schema migrations.
-- The application role must already exist.
-- PostgreSQL psql variable required: app_user, db_name.

-- Restrict schema creation.
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Allow the application to connect and access public schema objects.
GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";

-- Reference data and candidate management.
GRANT SELECT ON divisions TO :"app_user";
GRANT SELECT, INSERT, UPDATE ON elections, candidates TO :"app_user";

-- Users and enrolments.
GRANT SELECT, INSERT, UPDATE ON users, enrolments TO :"app_user";

-- Ballots: append-only from the application.
GRANT SELECT, INSERT ON ballots TO :"app_user";

-- Ballot integrity records.
GRANT SELECT, INSERT ON ballot_hashes TO :"app_user";

-- Public bulletin board.
GRANT SELECT, INSERT ON bulletin_board TO :"app_user";
GRANT UPDATE (status) ON bulletin_board TO :"app_user";

-- Audit logging: insert only.
REVOKE ALL ON audit_log FROM :"app_user";
GRANT INSERT ON audit_log TO :"app_user";

-- Voter participation: insert only.
REVOKE ALL ON voter_participation FROM :"app_user";
GRANT INSERT ON voter_participation TO :"app_user";

-- Allow eligibility checks through the approved function.
REVOKE ALL ON FUNCTION has_voted(INT, INT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION has_voted(INT, INT) TO :"app_user";

-- Application sessions.
GRANT SELECT, INSERT, UPDATE ON sessions TO :"app_user";

-- Voter privacy events: insert only.
REVOKE ALL ON voter_privacy_log FROM :"app_user";
GRANT INSERT ON voter_privacy_log TO :"app_user";

-- Required identity sequences.
GRANT USAGE ON SEQUENCE audit_log_id_seq TO :"app_user";
GRANT USAGE ON SEQUENCE voter_privacy_log_id_seq TO :"app_user";

-- Existing application inserts require identity sequence access.
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO :"app_user";

-- Ensure sensitive tables remain restricted after general grants.
REVOKE SELECT, UPDATE, DELETE, TRUNCATE
ON audit_log, voter_privacy_log, voter_participation
FROM :"app_user";

-- Keep integrity alert records restricted to the dedicated checker.
REVOKE ALL ON audit_integrity_alerts FROM :"app_user";

-- Keep audit chain state restricted.
REVOKE ALL ON audit_chain_state FROM :"app_user";
