-- SR-13: Reconcile accepted ballots, integrity hashes and tally inputs.
-- This migration does not modify existing ballot or participation records.

BEGIN;

-- Aggregate-only access to accepted voting submissions.
-- Individual voter identifiers are never returned.

CREATE OR REPLACE FUNCTION public.count_accepted_submissions(
    p_election_id INTEGER
)
RETURNS BIGINT
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog
AS $$
    SELECT COUNT(*)
    FROM public.voter_participation
    WHERE election_id = p_election_id;
$$;

REVOKE ALL ON FUNCTION public.count_accepted_submissions(INTEGER)
FROM PUBLIC;

GRANT EXECUTE ON FUNCTION public.count_accepted_submissions(INTEGER)
TO evp_app;


-- Auditor-visible reconciliation alerts.
-- No voter identifiers or ballot selections are stored.

CREATE TABLE IF NOT EXISTS public.election_security_alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,

    election_id INTEGER NOT NULL
        REFERENCES public.elections(id),

    alert_type VARCHAR(60) NOT NULL,

    reason VARCHAR(80) NOT NULL,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT election_security_alert_type_check
        CHECK (alert_type = 'reconciliation_failed'),

    CONSTRAINT election_security_alert_reason_check
        CHECK (
            reason IN (
                'accepted_count_mismatch',
                'ballot_count_mismatch',
                'hash_count_mismatch',
                'receipt_count_mismatch',
                'integrity_failure',
                'tally_count_mismatch'
            )
        )
);

REVOKE ALL ON TABLE public.election_security_alerts FROM PUBLIC;

GRANT INSERT ON TABLE public.election_security_alerts TO evp_app;

GRANT USAGE ON SEQUENCE public.election_security_alerts_id_seq
TO evp_app;

COMMIT;