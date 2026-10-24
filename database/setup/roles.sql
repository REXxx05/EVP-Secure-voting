-- roles.sql
-- Creates the limited database user that the backend logs in as (least privilege).
-- We don't run this automatically. Run it with: bash database/setup/create_roles.sh
-- :"app_user", :'app_pass' and :"db_name" get filled in from .env when it runs,
-- so no password is ever saved in this file.

-- Create the app user with a password
CREATE ROLE :"app_user" WITH LOGIN PASSWORD :'app_pass';

-- Nobody except the admin can create new tables
REVOKE CREATE ON SCHEMA public FROM PUBLIC;

-- Let the app user connect and see the tables
GRANT CONNECT ON DATABASE :"db_name" TO :"app_user";
GRANT USAGE ON SCHEMA public TO :"app_user";

-- Reference data: the app can read it and admins can add or edit it,
-- e.g. candidate entry and exclusion
GRANT SELECT ON divisions TO :"app_user";
GRANT SELECT, INSERT, UPDATE ON elections, candidates TO :"app_user";

-- Users and enrolments: read, add and update (e.g. failed login counts)
GRANT SELECT, INSERT, UPDATE ON users, enrolments TO :"app_user";

-- Votes: the app can only ADD and READ them.
-- No UPDATE or DELETE, so a vote can never be changed or removed once saved.
GRANT SELECT, INSERT ON voter_participation, ballots TO :"app_user";

-- Needed so INSERTs can use the auto-increment ids
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO :"app_user";