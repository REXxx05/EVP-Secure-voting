// AI-generated working implementation for review; see docs/ai-assisted-sr06.md.
// This service trusts identity supplied by the authentication boundary, not a request body.
const { pool: defaultPool } = require('../config/db');
const { checkEligibility: defaultEligibility } = require('./eligibilityService');
const { saveBallotAnonymously: defaultStorage } = require('./ballotStorage');
const { recordBallotHash: defaultRecordHash } = require('./ballotIntegrity');
const { issueReceipt: defaultIssueReceipt } = require('./receipts');

class SubmissionError extends Error {
  constructor(code, message, options) {
    super(message, options);
    this.name = 'SubmissionError';
    this.code = code;
  }
}

function createBallotSubmission({
  pool = defaultPool,
  checkEligibility = defaultEligibility,
  saveBallotAnonymously = defaultStorage,
  recordBallotHash = defaultRecordHash,
  issueReceipt = defaultIssueReceipt,
  validateBallots,
  finalizeSession
} = {}) {
  // SR-07 is not merged. Require explicit validation wiring; never accept a permissive default.
  if (typeof validateBallots !== 'function') {
    throw new TypeError('A server-side ballot validator is required');
  }
  if (finalizeSession !== undefined && typeof finalizeSession !== 'function') {
    throw new TypeError('Session finalizer must be a function');
  }

  return async function submitBallots({ voterId, electionId, house, senate, sessionId } = {}) {
    if (!Number.isSafeInteger(voterId) || voterId < 1 ||
        !Number.isSafeInteger(electionId) || electionId < 1) {
      throw new SubmissionError('INVALID_INPUT', 'Valid voter and election identifiers are required');
    }
    if (house == null || senate == null) {
      throw new SubmissionError('INVALID_BALLOT', 'Both chamber ballots are required');
    }
    if (finalizeSession && (!Number.isSafeInteger(sessionId) || sessionId < 1)) {
      throw new SubmissionError('INVALID_SESSION', 'A valid authenticated session is required');
    }

    const client = await pool.connect();
    let transactionStarted = false;
    let commitAttempted = false;
    let discardClient = false;
    try {
      await client.query('BEGIN');
      transactionStarted = true;
      const eligibility = await checkEligibility(voterId, electionId, { client, lock: true });
      if (!eligibility || eligibility.eligible !== true) {
        const error = new SubmissionError('INELIGIBLE', 'Voter is not eligible for this election');
        error.reason = eligibility && eligibility.reason;
        throw error;
      }
      if (eligibility.electionId !== electionId ||
          !Number.isSafeInteger(eligibility.divisionId) || eligibility.divisionId < 1) {
        throw new SubmissionError('INVALID_ELIGIBILITY', 'Eligibility result is inconsistent');
      }
      const valid = await validateBallots({
        client, electionId, divisionId: eligibility.divisionId, house, senate
      });
      if (valid !== true) {
        throw new SubmissionError('INVALID_BALLOT', 'Ballot validation failed');
      }

      try {
        // INSERT needs no participation SELECT privilege. The primary key is the race arbiter.
        await client.query(
          'INSERT INTO voter_participation (user_id, election_id) VALUES ($1, $2)',
          [voterId, electionId]
        );
      } catch (error) {
        if (error.code === '23505' && error.table === 'voter_participation' &&
            error.constraint === 'voter_participation_pkey') {
          throw new SubmissionError('ALREADY_VOTED', 'Participation already recorded', { cause: error });
        }
        throw error;
      }

      // Deliberately pass no identity/session fields to anonymous storage or the validator.
      const context = { electionId, divisionId: eligibility.divisionId };
      const houseId = await saveBallotAnonymously(client, { ...context, ballotType: 'house', ballotData: house });
      const senateId = await saveBallotAnonymously(client, { ...context, ballotType: 'senate', ballotData: senate });
      // SR-11: the ballots are only confirmed once both integrity hashes are
      // written in this same transaction; any failure here rolls everything back.
      await recordBallotHash(client, houseId);
      await recordBallotHash(client, senateId);
      // SR-12: signed anonymous receipt, recorded on the bulletin board in the
      // same transaction. It only depends on the election and the two ballot ids.
      const receipt = await issueReceipt(client, {
        electionId, houseBallotId: houseId, senateBallotId: senateId
      });
      if (finalizeSession) {
        // Route integration supplies SR-04's transaction-compatible implementation.
        // It must verify session ownership/validity and invalidate using THIS client.
        const ended = await finalizeSession({ client, sessionId, voterId });
        if (ended !== true) {
          throw new SubmissionError('INVALID_SESSION', 'Session could not be finalized');
        }
      }
      commitAttempted = true;
      const commitResult = await client.query('COMMIT');
      transactionStarted = false;
      if (commitResult.command !== 'COMMIT') {
        // PostgreSQL answers ROLLBACK to COMMIT on an already-aborted transaction.
        discardClient = true;
        throw new SubmissionError('TRANSACTION_NOT_COMMITTED', 'Submission transaction did not commit');
      }
      return { accepted: true, receipt };
    } catch (originalError) {
      if (!transactionStarted || commitAttempted) discardClient = true;
      let failure = originalError;
      if (commitAttempted && originalError.code !== 'TRANSACTION_NOT_COMMITTED') {
        // A network failure during COMMIT can occur after the server committed.
        failure = new SubmissionError('COMMIT_OUTCOME_UNKNOWN',
          'Submission outcome could not be confirmed', { cause: originalError });
      }
      if (transactionStarted) {
        try {
          await client.query('ROLLBACK');
        } catch (rollbackError) {
          discardClient = true;
          // Preserve the original failure; this internal field must not become a public response.
          failure.rollbackError = rollbackError;
        }
      }
      throw failure;
    } finally {
      client.release(discardClient);
    }
  };
}

module.exports = { createBallotSubmission, SubmissionError };
