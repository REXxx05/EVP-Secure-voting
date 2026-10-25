// Tests for SR-05 (voter eligibility).
// The Docker database needs to be running for these.

const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { checkEligibility } = require('../../src/services/eligibilityService');

// from our seed data (02_seed.sql)
const OPEN_ELECTION = 1;
const MELBOURNE = 1;

// ids of the fake stuff we make for testing
let enrolledVoter;
let notEnrolledVoter;
let adminUser;
let closedElection;

// adds a fake user and gives back their id
// (Date.now() makes the username unique each time we run the tests)
async function addTestUser(name, role) {
  const result = await adminDb.query(
    'INSERT INTO users (username, password_hash, role) VALUES ($1, $2, $3) RETURNING id',
    [name + '_' + Date.now(), 'not-a-real-hash', role]
  );
  return result.rows[0].id;
}

// runs once before all the tests: set up our fake data
beforeAll(async () => {
  enrolledVoter = await addTestUser('enrolled_voter', 'voter');
  notEnrolledVoter = await addTestUser('not_enrolled_voter', 'voter');
  adminUser = await addTestUser('admin_user', 'admin');

  // enrol one voter in Melbourne for the open election
  await adminDb.query(
    'INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [enrolledVoter, OPEN_ELECTION, MELBOURNE]
  );

  // make a closed election and enrol the same voter in it too
  const result = await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ('Old test election', 'closed') RETURNING id"
  );
  closedElection = result.rows[0].id;

  await adminDb.query(
    'INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [enrolledVoter, closedElection, MELBOURNE]
  );
});

// runs once after all the tests: delete our fake data so the database is clean again
afterAll(async () => {
  await adminDb.query('DELETE FROM enrolments WHERE user_id IN ($1, $2, $3)', [enrolledVoter, notEnrolledVoter, adminUser]);
  await adminDb.query('DELETE FROM users WHERE id IN ($1, $2, $3)', [enrolledVoter, notEnrolledVoter, adminUser]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [closedElection]);

  // close the database connections or jest won't finish
  await adminDb.end();
  await db.pool.end();
});

describe('SR-05 voter eligibility', () => {

  test('enrolled voter is allowed and gets their division', async () => {
    const result = await checkEligibility(enrolledVoter, OPEN_ELECTION);
    expect(result.eligible).toBe(true);
    expect(result.divisionId).toBe(MELBOURNE);
  });

  test('voter who is not enrolled is rejected', async () => {
    const result = await checkEligibility(notEnrolledVoter, OPEN_ELECTION);
    expect(result.eligible).toBe(false);
    expect(result.reason).toBe('not_enrolled');
  });

  test('admin is rejected because they are not a voter', async () => {
    const result = await checkEligibility(adminUser, OPEN_ELECTION);
    expect(result.eligible).toBe(false);
    expect(result.reason).toBe('not_a_voter');
  });

  test('voting in a closed election is rejected', async () => {
    const result = await checkEligibility(enrolledVoter, closedElection);
    expect(result.eligible).toBe(false);
    expect(result.reason).toBe('election_not_open');
  });

  test('user that does not exist is rejected', async () => {
    const result = await checkEligibility(999999, OPEN_ELECTION);
    expect(result.eligible).toBe(false);
    expect(result.reason).toBe('not_found');
  });

  test('random text instead of an id is rejected', async () => {
    const result = await checkEligibility('1 OR 1=1', OPEN_ELECTION);
    expect(result.eligible).toBe(false);
    expect(result.reason).toBe('invalid_input');
  });

  test('check is done within 2 seconds (from our acceptance criteria)', async () => {
    const start = Date.now();
    await checkEligibility(enrolledVoter, OPEN_ELECTION);
    const timeTaken = Date.now() - start;
    expect(timeTaken).toBeLessThan(2000);
  });

});

// ---- Using SR-05 inside SR-06's transaction (with row locking) ----
describe('SR-05 inside a voting transaction', () => {

  test('works with a transaction client and lock', async () => {
    const client = await db.pool.connect();
    try {
      await client.query('BEGIN');
      const result = await checkEligibility(enrolledVoter, OPEN_ELECTION, { client: client, lock: true });
      expect(result.eligible).toBe(true);
      expect(result.divisionId).toBe(MELBOURNE);
    } finally {
      await client.query('ROLLBACK');
      client.release();
    }
  });

  test('admin cannot close the election while a vote is in progress', async () => {
    const voteClient = await db.pool.connect();
    const adminClient = await adminDb.connect();
    try {
      // a voter's transaction checks eligibility and locks the election
      await voteClient.query('BEGIN');
      await checkEligibility(enrolledVoter, OPEN_ELECTION, { client: voteClient, lock: true });

      // meanwhile an admin tries to close the election.
      // it should have to wait, so we give up after half a second
      await adminClient.query("SET lock_timeout = '500ms'");
      await expect(
        adminClient.query("UPDATE elections SET status = 'closed' WHERE id = $1", [OPEN_ELECTION])
      ).rejects.toThrow('lock timeout');
    } finally {
      await voteClient.query('ROLLBACK');
      voteClient.release();
      adminClient.release();
    }
  });

  test('asking for a lock without a transaction is not allowed', async () => {
    await expect(checkEligibility(enrolledVoter, OPEN_ELECTION, { lock: true }))
      .rejects.toThrow('lock needs a transaction client');
  });

});