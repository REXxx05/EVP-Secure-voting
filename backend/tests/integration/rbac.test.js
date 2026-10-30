// SR-03: Integration tests for role-based access control.
// SR-17: Privacy-preserving logging for voter access-denied events.
//
// Uses the seeded users admin1, voter1 and auditor1.

const request = require('supertest');
const app = require('../../src/app');
const adminDb = require('../helpers/adminDb');
const pool = require('../../src/config/db');
const { purgeAuditRows } = require('../helpers/fixtures');
const { pseudonymiseVoter } = require('../../src/security/voterPseudonym');

const PASSWORD = 'Password123!';

let electionId;
let divisionId;
let candidateId;

const logins = {}; // username -> { userId, token }

// Log in a seeded user and store their session details.
async function login(username) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({
      username,
      password: PASSWORD,
    });

  expect(res.status).toBe(200);

  logins[username] = {
    userId: res.body.userId,
    token: res.body.sessionToken,
  };
}

// Build the candidate exclusion endpoint.
function exclusionUrl(id) {
  return `/api/admin/candidates/${id}/exclusion`;
}

// Count existing administrator audit records.
async function countAudit(actorId, outcome) {
  const result = await adminDb.query(
    `SELECT count(*)::int AS n
     FROM audit_log
     WHERE actor_id = $1
       AND outcome = $2`,
    [actorId, outcome]
  );

  return result.rows[0].n;
}

// Count privacy-preserving voter access-denied events.
async function countVoterPrivacyLogs(pseudonym, eventType) {
  const result = await adminDb.query(
    `SELECT count(*)::int AS n
     FROM voter_privacy_log
     WHERE voter_pseudonym = $1
       AND event_type = $2`,
    [pseudonym, eventType]
  );

  return result.rows[0].n;
}

// Check whether the candidate is currently excluded.
async function candidateExcluded() {
  const result = await adminDb.query(
    'SELECT excluded FROM candidates WHERE id = $1',
    [candidateId]
  );

  return result.rows[0].excluded;
}

// Prepare test data.
beforeAll(async () => {
  const election = await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'draft') RETURNING id",
    [`SR03 test election ${Date.now()}`]
  );

  electionId = election.rows[0].id;

  const division = await adminDb.query(
    'INSERT INTO divisions (name, state) VALUES ($1, $2) RETURNING id',
    [`SR03 test division ${Date.now()}`, 'VIC']
  );

  divisionId = division.rows[0].id;

  const candidate = await adminDb.query(
    `INSERT INTO candidates
     (election_id, division_id, full_name, party, ballot_order)
     VALUES ($1, $2, 'SR03 Test Candidate', 'Test Party', 1)
     RETURNING id`,
    [electionId, divisionId]
  );

  candidateId = candidate.rows[0].id;

  // Authenticate the seeded test users.
  await login('admin1');
  await login('voter1');
  await login('auditor1');

  // SR-02: Staff users require MFA before accessing administrator routes.
  // These tests focus on RBAC, so their sessions are marked MFA-verified.
  // MFA behaviour is tested separately.
  await adminDb.query(
    'UPDATE sessions SET mfa_verified = TRUE WHERE token = ANY($1)',
    [[logins.admin1.token, logins.auditor1.token]]
  );
});

// Clean up test data and database connections.
afterAll(async () => {
  // Log out test sessions through the application.
  for (const name of Object.keys(logins)) {
    await request(app)
      .post('/api/auth/logout')
      .set('x-session-token', logins[name].token);
  }

  // Remove administrator audit rows produced by the seeded users.
  await purgeAuditRows(
    Object.values(logins).map((login) => login.userId)
  );

  // Privacy logs are append-only and must not be deleted by tests.

  // Remove temporary election data.
  await adminDb.query(
    'DELETE FROM candidates WHERE id = $1',
    [candidateId]
  );

  await adminDb.query(
    'DELETE FROM divisions WHERE id = $1',
    [divisionId]
  );

  await adminDb.query(
    'DELETE FROM elections WHERE id = $1',
    [electionId]
  );

  await adminDb.end();
  await pool.pool.end();
});

describe('SR-03 role-based access control', () => {

  // Test 1: Unauthenticated requests must be rejected.
  test('rejects a request with no session token (401)', async () => {
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .send({ excluded: true });

    expect(res.status).toBe(401);

    // Unauthorised requests must not change election data.
    expect(await candidateExcluded()).toBe(false);
  });

  // Test 2: Administrator access requires MFA.
  test('SR-02: blocks an admin who only used a password (no MFA) with 403', async () => {
    const res1 = await request(app)
      .post('/api/auth/login')
      .send({
        username: 'admin1',
        password: PASSWORD,
      });

    expect(res1.status).toBe(200);

    const passwordOnlyToken = res1.body.sessionToken;

    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', passwordOnlyToken)
      .send({ excluded: true });

    expect(res.status).toBe(403);
    expect(res.body.mfaRequired).toBe(true);

    // The candidate must remain unchanged.
    expect(await candidateExcluded()).toBe(false);

    // Remove the temporary session.
    await request(app)
      .post('/api/auth/logout')
      .set('x-session-token', passwordOnlyToken);
  });

  // Test 3: SR-17 privacy-preserving voter access-denied logging.
  test('blocks a voter with 403, changes nothing and records a pseudonymised denial within 1 second', async () => {
    const voter = logins.voter1;

    // Convert the voter ID into an HMAC-SHA-256 pseudonym.
    const pseudonym = pseudonymiseVoter(voter.userId);

    // Count existing privacy log entries before the request.
    const before = await countVoterPrivacyLogs(
      pseudonym,
      'access.denied'
    );

    // Record the original administrator audit count.
    const oldAuditBefore = await countAudit(
      voter.userId,
      'failure'
    );

    const started = Date.now();

    // Attempt to access an administrator-only endpoint as a voter.
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', voter.token)
      .send({ excluded: true });

    const elapsed = Date.now() - started;

    // Count privacy log entries after the denied request.
    const after = await countVoterPrivacyLogs(
      pseudonym,
      'access.denied'
    );

    // Access must be denied.
    expect(res.status).toBe(403);

    // The denied request must not modify election data.
    expect(await candidateExcluded()).toBe(false);

    // Exactly one new privacy-preserving log entry must be recorded.
    expect(after).toBe(before + 1);

    // The original audit log must not receive a new voter denial.
    expect(
      await countAudit(voter.userId, 'failure')
    ).toBe(oldAuditBefore);

    // Preserve the original response-time requirement.
    expect(elapsed).toBeLessThan(1000);

    // Retrieve the privacy-preserving event using the administrator
    // test connection. The application user has INSERT-only access.
    const row = await adminDb.query(
      `SELECT voter_pseudonym, event_type, reason
       FROM voter_privacy_log
       WHERE voter_pseudonym = $1
         AND event_type = 'access.denied'
       ORDER BY id DESC
       LIMIT 1`,
      [pseudonym]
    );

    expect(row.rows).toHaveLength(1);

    // Confirm the correct pseudonym was stored.
    expect(row.rows[0].voter_pseudonym.trim()).toBe(pseudonym);

    // Confirm that the pseudonym has the expected HMAC format.
    expect(row.rows[0].voter_pseudonym.trim())
      .toMatch(/^[a-f0-9]{64}$/);

    // Confirm the event information.
    expect(row.rows[0].event_type).toBe('access.denied');
    expect(row.rows[0].reason).toBe('role_not_permitted');

    // The privacy log does not store raw voter IDs.
    expect(row.rows[0]).not.toHaveProperty('actor_id');
    expect(row.rows[0]).not.toHaveProperty('voter_id');
  });

  // Test 4: Auditor access-denied events use the original audit log.
  test('blocks an auditor with 403 and logs the denial', async () => {
    const auditor = logins.auditor1;

    const before = await countAudit(
      auditor.userId,
      'failure'
    );

    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', auditor.token)
      .send({ excluded: true });

    expect(res.status).toBe(403);

    // Auditor must not be able to modify candidate data.
    expect(await candidateExcluded()).toBe(false);

    // The existing administrator audit log must record the denial.
    expect(
      await countAudit(auditor.userId, 'failure')
    ).toBe(before + 1);
  });

  // Test 5: Invalid administrator input must be rejected.
  test('rejects bad input from an admin with 400', async () => {
    const admin = logins.admin1;

    const badFlag = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', admin.token)
      .send({ excluded: 'yes' });

    expect(badFlag.status).toBe(400);

    const badId = await request(app)
      .post(exclusionUrl('abc'))
      .set('x-session-token', admin.token)
      .send({ excluded: true });

    expect(badId.status).toBe(400);

    // Invalid requests must not change candidate information.
    expect(await candidateExcluded()).toBe(false);
  });

  // Test 6: Administrators can modify candidate exclusions.
  test('lets an admin exclude and re-include a candidate (200) and audits it', async () => {
    const admin = logins.admin1;

    const before = await countAudit(
      admin.userId,
      'success'
    );

    // Exclude the candidate.
    const excludeRes = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', admin.token)
      .send({ excluded: true });

    expect(excludeRes.status).toBe(200);
    expect(await candidateExcluded()).toBe(true);

    // Re-include the candidate.
    const includeRes = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', admin.token)
      .send({ excluded: false });

    expect(includeRes.status).toBe(200);
    expect(await candidateExcluded()).toBe(false);

    // Both administrator actions must be audited.
    expect(
      await countAudit(admin.userId, 'success')
    ).toBeGreaterThanOrEqual(before + 2);
  });
});