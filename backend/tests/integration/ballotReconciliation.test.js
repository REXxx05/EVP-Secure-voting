// SR-13: PostgreSQL Integration Tests
//
// These tests verify ballot reconciliation using the real PostgreSQL database.
//
// Each test creates its own isolated election and voter.
// Existing election records are not modified.
//
// Tests cover:
// 1. Blocking reconciliation while an election is open.
// 2. Successful reconciliation of accepted ballots, hashes and receipts.
// 3. Detection of mismatched accepted-submission counts.
// 4. Detection of missing receipts and recording of auditor alerts.

const crypto = require('crypto');

const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');

const {
  purgeElectionBallots
} = require('../helpers/fixtures');

const {
  createBallotSubmission
} = require('../../src/services/ballotSubmission');

const {
  reconcileElection
} = require('../../src/services/ballotReconciliation');

jest.setTimeout(15000);

// Test-specific identifiers.
let voterId;
let electionId;

// Create the ballot submission service.
const submit = createBallotSubmission({
  validateBallots: async () => true
});

// Generate a valid House and Senate voting submission.
const vote = () => ({
  voterId,
  electionId,

  house: {
    preferences: [3, 1, 2]
  },

  senate: {
    above: [2]
  }
});

// Create a separate election and voter before each test.
beforeEach(async () => {
  voterId = undefined;
  electionId = undefined;

  const tag = crypto.randomUUID();

  const division = await adminDb.query(
    'SELECT id FROM divisions ORDER BY id LIMIT 1'
  );

  if (division.rowCount === 0) {
    throw new Error('No electoral divisions are available for testing');
  }

  // Create a test voter.
  voterId = (
    await adminDb.query(
      `INSERT INTO users
         (username, password_hash, role)
       VALUES ($1, 'test-only-not-a-login', 'voter')
       RETURNING id`,
      ['sr13_' + tag]
    )
  ).rows[0].id;

  // Create an isolated election.
  electionId = (
    await adminDb.query(
      `INSERT INTO elections
         (name, status)
       VALUES ($1, 'open')
       RETURNING id`,
      ['SR13 isolated ' + tag]
    )
  ).rows[0].id;

  // Enrol the test voter in the isolated election.
  await adminDb.query(
    `INSERT INTO enrolments
       (user_id, election_id, division_id)
     VALUES ($1, $2, $3)`,
    [voterId, electionId, division.rows[0].id]
  );
});

// Remove all test records after each test.
afterEach(async () => {
  if (electionId !== undefined) {

    // Remove SR-13 security alerts first because they reference elections.
    await adminDb.query(
      `DELETE FROM election_security_alerts
       WHERE election_id = $1`,
      [electionId]
    );

    // Remove receipts, hashes and ballots using the existing
    // test-only cleanup helper.
    await purgeElectionBallots(electionId);

    // Remove participation records.
    await adminDb.query(
      `DELETE FROM voter_participation
       WHERE election_id = $1`,
      [electionId]
    );

    // Remove enrolments.
    await adminDb.query(
      `DELETE FROM enrolments
       WHERE election_id = $1`,
      [electionId]
    );

    // Remove the isolated election.
    await adminDb.query(
      `DELETE FROM elections
       WHERE id = $1`,
      [electionId]
    );
  }

  // Remove the test voter.
  if (voterId !== undefined) {
    await adminDb.query(
      `DELETE FROM users
       WHERE id = $1`,
      [voterId]
    );
  }
});

// Close database connections after the tests finish.
afterAll(async () => {
  await db.pool.end();
  await adminDb.end();
});

// Close only the isolated test election.
async function closeElection() {
  await adminDb.query(
    `UPDATE elections
        SET status = 'closed'
      WHERE id = $1`,
    [electionId]
  );
}

// Retrieve auditor alerts for the isolated test election.
async function getAlerts() {
  const result = await adminDb.query(
    `SELECT alert_type, reason
       FROM election_security_alerts
      WHERE election_id = $1
      ORDER BY id`,
    [electionId]
  );

  return result.rows;
}

// Simulate a missing receipt in the isolated test election.
//
// The bulletin_board table is append-only.
// Its triggers prevent normal deletion.
//
// This helper temporarily bypasses those triggers using the
// administrator test connection, matching the existing fixture
// cleanup approach.
//
// IMPORTANT:
// This helper must only be used against a local test database.
async function simulateMissingReceipt() {
  const client = await adminDb.connect();

  try {
    await client.query('BEGIN');

    // Temporarily disable triggers for this transaction only.
    await client.query(
      "SET LOCAL session_replication_role = 'replica'"
    );

    // Remove only the receipt belonging to the test election.
    const result = await client.query(
      `DELETE FROM bulletin_board
       WHERE election_id = $1`,
      [electionId]
    );

    if (result.rowCount !== 1) {
      throw new Error(
        `Expected to remove one test receipt, removed ${result.rowCount}`
      );
    }

    await client.query('COMMIT');

  } catch (error) {
    await client.query('ROLLBACK');
    throw error;

  } finally {
    client.release();
  }
}

// ============================================================
// SR-13 PostgreSQL Integration Tests
// ============================================================

describe('SR-13 PostgreSQL ballot reconciliation', () => {

  // ----------------------------------------------------------
  // Test 1: Election must be closed before reconciliation.
  // ----------------------------------------------------------
  test('blocks reconciliation while the election is open', async () => {

    await expect(
      reconcileElection(electionId)
    ).rejects.toMatchObject({
      code: 'ELECTION_NOT_CLOSED'
    });

    // No security alert is required for an election that
    // has not yet reached the reconciliation stage.
    expect(await getAlerts()).toHaveLength(0);
  });

  // ----------------------------------------------------------
  // Test 2: Successful reconciliation.
  // ----------------------------------------------------------
  test(
    'passes when accepted submissions, ballots, hashes and receipts match',
    async () => {

      // Submit one valid combined House/Senate vote.
      await submit(vote());

      // Close the isolated election.
      await closeElection();

      // Run the real reconciliation service.
      const result = await reconcileElection(electionId);

      expect(result.ok).toBe(true);

      // One accepted submission produces:
      // - One House ballot
      // - One Senate ballot
      // - Two hashes
      // - One receipt
      expect(result.counts).toMatchObject({
        acceptedSubmissions: 1,
        expectedBallots: 2,
        storedBallots: 2,
        houseBallots: 1,
        senateBallots: 1,
        hashEntries: 2,
        hashElectionMismatches: 0,
        verifiedTallyInputs: 2,
        receiptEntries: 1
      });

      // Both ballots must pass integrity verification.
      expect(result.ballots).toHaveLength(2);

      // Successful reconciliation should not create alerts.
      expect(await getAlerts()).toHaveLength(0);
    }
  );

  // ----------------------------------------------------------
  // Test 3: Accepted-submission count mismatch.
  // ----------------------------------------------------------
  test(
    'blocks reconciliation when accepted ballot counts do not match',
    async () => {

      // Submit one valid combined House/Senate vote.
      await submit(vote());

      // Simulate a missing accepted-submission record.
      // Only the isolated test election is affected.
      await adminDb.query(
        `DELETE FROM voter_participation
         WHERE election_id = $1`,
        [electionId]
      );

      // Close the isolated election.
      await closeElection();

      // Reconciliation must reject the discrepancy.
      await expect(
        reconcileElection(electionId)
      ).rejects.toMatchObject({
        code: 'RECONCILIATION_FAILED'
      });

      // The failure must be recorded for an auditor.
      const alerts = await getAlerts();

      expect(alerts).toHaveLength(1);

      expect(alerts[0]).toMatchObject({
        alert_type: 'reconciliation_failed',
        reason: 'ballot_count_mismatch'
      });
    }
  );

  // ----------------------------------------------------------
  // Test 4: Missing receipt.
  // ----------------------------------------------------------
  test(
    'blocks reconciliation when a receipt is missing',
    async () => {

      // Submit one valid combined House/Senate vote.
      await submit(vote());

      // Simulate the disappearance of the test receipt.
      // The helper handles the append-only database protection.
      await simulateMissingReceipt();

      // Close the isolated election.
      await closeElection();

      // Reconciliation must reject the discrepancy.
      await expect(
        reconcileElection(electionId)
      ).rejects.toMatchObject({
        code: 'RECONCILIATION_FAILED'
      });

      // Verify that the auditor alert was saved.
      const alerts = await getAlerts();

      expect(alerts).toHaveLength(1);

      expect(alerts[0]).toMatchObject({
        alert_type: 'reconciliation_failed',
        reason: 'receipt_count_mismatch'
      });
    }
  );

});