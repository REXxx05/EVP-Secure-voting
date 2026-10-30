// SR-13: Reconcile accepted ballots, integrity hashes and tally inputs.
//
// Each accepted voting submission must produce:
// - One House ballot.
// - One Senate ballot.
// - Two ballot integrity hashes.
// - One receipt.
//
// Reconciliation checks these relationships before tallying.
// Discrepancies are recorded as security alerts.
//
// Voter identities and ballot selections are never included in alerts.

const { pool: defaultPool } = require('../config/db');
const { verifyElection } = require('./ballotIntegrity');

class ReconciliationError extends Error {
  constructor(code, message) {
    super(message);
    this.name = 'ReconciliationError';
    this.code = code;
  }
}

// Convert PostgreSQL COUNT results into safe JavaScript integers.
function readCount(result) {
  const count = Number(result.rows[0].count);

  if (!Number.isSafeInteger(count) || count < 0) {
    throw new ReconciliationError(
      'INVALID_COUNT',
      'Database returned an invalid reconciliation count'
    );
  }

  return count;
}

// Record reconciliation failures without exposing voter information.
async function recordReconciliationAlert(pool, electionId, reason) {
  await pool.query(
    `INSERT INTO public.election_security_alerts
       (election_id, alert_type, reason)
     VALUES ($1, $2, $3)`,
    [electionId, 'reconciliation_failed', reason]
  );
}

// Main SR-13 reconciliation function.
async function reconcileElection(
  electionId,
  { pool = defaultPool, verify = verifyElection } = {}
) {
  if (!Number.isSafeInteger(electionId) || electionId < 1) {
    throw new ReconciliationError(
      'INVALID_ELECTION',
      'A valid election ID is required'
    );
  }

  const client = await pool.connect();

  let failureReason = null;
  let result = null;
  let transactionStarted = false;

  try {
    // Use one consistent database snapshot for all checks.
    await client.query('BEGIN ISOLATION LEVEL REPEATABLE READ READ ONLY');
    transactionStarted = true;

    // Reconciliation is permitted only after election closure.
    const election = await client.query(
      'SELECT status FROM public.elections WHERE id = $1',
      [electionId]
    );

    if (election.rowCount !== 1) {
      throw new ReconciliationError(
        'ELECTION_NOT_FOUND',
        'Election does not exist'
      );
    }

    if (!['closed', 'published'].includes(election.rows[0].status)) {
      throw new ReconciliationError(
        'ELECTION_NOT_CLOSED',
        'Election must be closed before reconciliation'
      );
    }

    // Count accepted submissions without reading voter identities.
    const participationResult = await client.query(
      'SELECT public.count_accepted_submissions($1)::text AS count',
      [electionId]
    );

    // Count all ballots belonging to this election.
    const ballotResult = await client.query(
      `SELECT COUNT(*)::text AS count
         FROM public.ballots
        WHERE election_id = $1`,
      [electionId]
    );

    // Verify one House and one Senate ballot per accepted submission.
    const chamberResult = await client.query(
      `SELECT
         COUNT(*) FILTER (
           WHERE ballot_type = 'house'
         )::text AS house_count,
         COUNT(*) FILTER (
           WHERE ballot_type = 'senate'
         )::text AS senate_count
       FROM public.ballots
       WHERE election_id = $1`,
      [electionId]
    );

    // Count integrity hashes belonging to this election.
    const hashResult = await client.query(
      `SELECT COUNT(*)::text AS count
         FROM public.ballot_hashes
        WHERE election_id = $1`,
      [electionId]
    );

    // Detect hash records associated with the wrong election.
    const hashElectionMismatchResult = await client.query(
      `SELECT COUNT(*)::text AS count
         FROM public.ballot_hashes h
         JOIN public.ballots b ON b.id = h.ballot_id
        WHERE (h.election_id = $1 OR b.election_id = $1)
          AND h.election_id <> b.election_id`,
      [electionId]
    );

    // Each accepted submission must have one receipt.
    const receiptResult = await client.query(
      `SELECT COUNT(*)::text AS count
         FROM public.bulletin_board
        WHERE election_id = $1`,
      [electionId]
    );

    // Convert query results into validated numeric counts.
    const acceptedSubmissions = readCount(participationResult);
    const storedBallots = readCount(ballotResult);
    const hashEntries = readCount(hashResult);
    const receiptEntries = readCount(receiptResult);

    const houseBallots = readCount({
      rows: [{ count: chamberResult.rows[0].house_count }]
    });

    const senateBallots = readCount({
      rows: [{ count: chamberResult.rows[0].senate_count }]
    });

    const hashElectionMismatches = readCount(
      hashElectionMismatchResult
    );

    // One accepted submission produces two anonymous ballots.
    const expectedBallots = acceptedSubmissions * 2;

    if (!Number.isSafeInteger(expectedBallots)) {
      throw new ReconciliationError(
        'INVALID_COUNT',
        'Expected ballot count exceeds the supported range'
      );
    }

    // Reuse SR-11 cryptographic ballot integrity verification.
    const integrity = await verify(client, electionId);

    if (
      !integrity ||
      typeof integrity.ok !== 'boolean' ||
      !Array.isArray(integrity.ballots)
    ) {
      throw new ReconciliationError(
        'INVALID_INTEGRITY_RESULT',
        'Ballot integrity verification returned an invalid result'
      );
    }

    const verifiedTallyInputs = integrity.ballots.length;

    // Check all reconciliation requirements.
    if (storedBallots !== expectedBallots) {
      failureReason = 'ballot_count_mismatch';

    } else if (
      houseBallots !== acceptedSubmissions ||
      senateBallots !== acceptedSubmissions
    ) {
      failureReason = 'ballot_count_mismatch';

    } else if (
      hashEntries !== storedBallots ||
      hashElectionMismatches !== 0
    ) {
      failureReason = 'hash_count_mismatch';

    } else if (receiptEntries !== acceptedSubmissions) {
      failureReason = 'receipt_count_mismatch';

    } else if (!integrity.ok) {
      failureReason = 'integrity_failure';

    } else if (verifiedTallyInputs !== storedBallots) {
      failureReason = 'tally_count_mismatch';
    }

    result = {
      electionId,
      ok: failureReason === null,

      counts: {
        acceptedSubmissions,
        expectedBallots,
        storedBallots,
        houseBallots,
        senateBallots,
        hashEntries,
        hashElectionMismatches,
        verifiedTallyInputs,
        receiptEntries
      },

      reason: failureReason,

      // Internal use only.
      // Never expose decrypted ballots through a public API.
      ballots: failureReason === null ? integrity.ballots : []
    };

    await client.query('COMMIT');
    transactionStarted = false;

  } catch (error) {
    if (transactionStarted) {
      try {
        await client.query('ROLLBACK');
      } catch (rollbackError) {
        // Preserve the original error.
      }
    }

    throw error;

  } finally {
    client.release();
  }

  // Record reconciliation alerts outside the read-only transaction.
  if (failureReason !== null) {
    try {
      await recordReconciliationAlert(
        pool,
        electionId,
        failureReason
      );
    } catch (error) {
      throw new ReconciliationError(
        'ALERT_WRITE_FAILED',
        'Reconciliation failed and the auditor alert could not be recorded'
      );
    }

    throw new ReconciliationError(
      'RECONCILIATION_FAILED',
      `Election reconciliation failed: ${failureReason}`
    );
  }

  return result;
}

module.exports = {
  reconcileElection,
  ReconciliationError
};