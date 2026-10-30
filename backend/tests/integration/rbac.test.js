
/**
 * SR-03: Role-based access control integration tests.
 * SR-02: MFA protection for administrator routes.
 * SR-17: Privacy-preserving voter access-denied logging.
 * SR-18: Digitally signed administrator candidate actions.
 *
 * IMPORTANT:
 * Run only against the disposable evp_sr18_compat database.
 */

if (process.env.DB_NAME !== 'evp_sr18_compat') {
  throw new Error(
    'RBAC compatibility tests must use evp_sr18_compat'
  );
}

const fs = require('fs');
const path = require('path');

const request = require('supertest');
const app = require('../../src/app');
const adminDb = require('../helpers/adminDb');
const pool = require('../../src/config/db');

const {
  pseudonymiseVoter
} = require('../../src/security/voterPseudonym');

const {
  signCandidateAction,
  verifyCandidateAction
} = require('../../src/security/adminSigning');

const PASSWORD = 'Password123!';

const adminPrivateKey = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../local-keys/admin1-private.pem'
  ),
  'utf8'
);

const adminPublicKey = fs.readFileSync(
  path.resolve(
    __dirname,
    '../../local-keys/admin1-public.pem'
  ),
  'utf8'
);

let electionId;
let divisionId;
let candidateId;

const logins = {};

/**
 * Log in a seeded user and save their session details.
 */
async function login(username) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({
      username,
      password: PASSWORD
    });

  expect(res.status).toBe(200);

  logins[username] = {
    userId: res.body.userId,
    token: res.body.sessionToken
  };
}

/**
 * Build the candidate exclusion endpoint.
 */
function exclusionUrl(id) {
  return `/api/admin/candidates/${id}/exclusion`;
}

/**
 * Count existing administrator audit records.
 */
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

/**
 * Count privacy-preserving voter access-denied events.
 */
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

/**
 * Check whether the candidate is excluded.
 */
async function candidateExcluded() {
  const result = await adminDb.query(
    'SELECT excluded FROM candidates WHERE id = $1',
    [candidateId]
  );

  return result.rows[0].excluded;
}

/**
 * Sign an exclusion or restoration action using
 * the acting administrator's private key.
 */
function makeSignedExclusion(excluded) {
  const admin = logins.admin1;

  const actionType = excluded
    ? 'candidate.exclude'
    : 'candidate.restore';

  const signedAction = signCandidateAction(
    {
      adminId: admin.userId,
      candidateId,
      actionType,
      newValue: String(excluded),
      signedAt: new Date().toISOString()
    },
    adminPrivateKey
  );

  expect(
    verifyCandidateAction(
      signedAction,
      adminPublicKey
    )
  ).toBe(true);

  return signedAction;
}

/**
 * Prepare test data.
 */
beforeAll(async () => {
  const election = await adminDb.query(
    `INSERT INTO elections (name, status)
     VALUES ($1, 'draft')
     RETURNING id`,
    [`SR03 test election ${Date.now()}`]
  );

  electionId = election.rows[0].id;

  const division = await adminDb.query(
    `INSERT INTO divisions (name, state)
     VALUES ($1, $2)
     RETURNING id`,
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

  // Authenticate seeded users.
  await login('admin1');
  await login('voter1');
  await login('auditor1');

  // SR-02: Mark staff sessions as MFA-verified.
  // MFA behaviour is tested separately below.
  await adminDb.query(
    `UPDATE sessions
     SET mfa_verified = TRUE
     WHERE token = ANY($1)`,
    [[
      logins.admin1.token,
      logins.auditor1.token
    ]]
  );

  // Confirm that the seeded administrator has a
  // registered signing key in this test database.
  const registeredKey = await adminDb.query(
    `SELECT id
     FROM admin_signing_keys
     WHERE admin_id = $1
       AND revoked_at IS NULL`,
    [logins.admin1.userId]
  );

  expect(registeredKey.rowCount).toBeGreaterThan(0);
});

/**
 * Close sessions and database connections.
 *
 * SR-16 and SR-18 evidence must remain append-only.
 * We deliberately do not delete audit records,
 * signed actions, candidates, divisions or elections.
 *
 * This leaves test fixtures in the disposable database.
 */
afterAll(async () => {
  try {
    for (const name of Object.keys(logins)) {
      await request(app)
        .post('/api/auth/logout')
        .set('x-session-token', logins[name].token);
    }
  } finally {
    await adminDb.end();
    await pool.pool.end();
  }
});

describe('SR-03 role-based access control', () => {

  /**
   * Test 1:
   * Unauthenticated requests must be rejected.
   */
  test('rejects a request with no session token (401)', async () => {
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .send({ excluded: true });

    expect(res.status).toBe(401);

    expect(await candidateExcluded()).toBe(false);
  });

  /**
   * Test 2:
   * Administrator access requires MFA.
   */
  test(
    'SR-02: blocks an admin who only used a password (no MFA) with 403',
    async () => {
      const res1 = await request(app)
        .post('/api/auth/login')
        .send({
          username: 'admin1',
          password: PASSWORD
        });

      expect(res1.status).toBe(200);

      const passwordOnlyToken = res1.body.sessionToken;

      const res = await request(app)
        .post(exclusionUrl(candidateId))
        .set('x-session-token', passwordOnlyToken)
        .send({ excluded: true });

      expect(res.status).toBe(403);
      expect(res.body.mfaRequired).toBe(true);

      expect(await candidateExcluded()).toBe(false);

      await request(app)
        .post('/api/auth/logout')
        .set('x-session-token', passwordOnlyToken);
    }
  );

  /**
   * Test 3:
   * SR-17 privacy-preserving voter access-denied logging.
   */
  test(
    'blocks a voter with 403, changes nothing and records a pseudonymised denial within 1 second',
    async () => {
      const voter = logins.voter1;

      const pseudonym = pseudonymiseVoter(
        voter.userId
      );

      const before = await countVoterPrivacyLogs(
        pseudonym,
        'access.denied'
      );

      const oldAuditBefore = await countAudit(
        voter.userId,
        'failure'
      );

      const started = Date.now();

      const res = await request(app)
        .post(exclusionUrl(candidateId))
        .set('x-session-token', voter.token)
        .send({ excluded: true });

      const elapsed = Date.now() - started;

      const after = await countVoterPrivacyLogs(
        pseudonym,
        'access.denied'
      );

      expect(res.status).toBe(403);

      expect(await candidateExcluded()).toBe(false);

      expect(after).toBe(before + 1);

      expect(
        await countAudit(voter.userId, 'failure')
      ).toBe(oldAuditBefore);

      expect(elapsed).toBeLessThan(1000);

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

      expect(
        row.rows[0].voter_pseudonym.trim()
      ).toBe(pseudonym);

      expect(
        row.rows[0].voter_pseudonym.trim()
      ).toMatch(/^[a-f0-9]{64}$/);

      expect(row.rows[0].event_type).toBe(
        'access.denied'
      );

      expect(row.rows[0].reason).toBe(
        'role_not_permitted'
      );

      expect(row.rows[0]).not.toHaveProperty(
        'actor_id'
      );

      expect(row.rows[0]).not.toHaveProperty(
        'voter_id'
      );
    }
  );

  /**
   * Test 4:
   * Auditor access-denied events use the audit log.
   */
  test(
    'blocks an auditor with 403 and logs the denial',
    async () => {
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

      expect(await candidateExcluded()).toBe(false);

      expect(
        await countAudit(auditor.userId, 'failure')
      ).toBe(before + 1);
    }
  );

  /**
   * Test 5:
   * Invalid administrator input must be rejected.
   */
  test(
    'rejects bad input from an admin with 400',
    async () => {
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

      expect(await candidateExcluded()).toBe(false);
    }
  );

  /**
   * Test 6:
   * A verified administrator can exclude and restore
   * a candidate using valid digital signatures.
   *
   * Both actions must be audited and signed.
   */
  test(
    'lets an admin exclude and re-include a candidate (200) and audits it',
    async () => {
      const admin = logins.admin1;

      const before = await countAudit(
        admin.userId,
        'success'
      );

      // SR-18: Sign the exclusion request.
      const excludeSignature = makeSignedExclusion(
        true
      );

      const excludeRes = await request(app)
        .post(exclusionUrl(candidateId))
        .set('x-session-token', admin.token)
        .send({
          excluded: true,
          signedAction: excludeSignature
        });

      expect(excludeRes.status).toBe(200);

      expect(await candidateExcluded()).toBe(true);

      // SR-18: Sign the restoration request.
      const restoreSignature = makeSignedExclusion(
        false
      );

      const includeRes = await request(app)
        .post(exclusionUrl(candidateId))
        .set('x-session-token', admin.token)
        .send({
          excluded: false,
          signedAction: restoreSignature
        });

      expect(includeRes.status).toBe(200);

      expect(await candidateExcluded()).toBe(false);

      // SR-15: Both actions must be audited.
      expect(
        await countAudit(admin.userId, 'success')
      ).toBeGreaterThanOrEqual(before + 2);

      // SR-18: Both actions must have signed evidence.
      const evidence = await adminDb.query(
        `SELECT action, signature
         FROM signed_candidate_actions
         WHERE candidate_id = $1
           AND admin_id = $2
         ORDER BY id DESC
         LIMIT 2`,
        [candidateId, admin.userId]
      );

      expect(evidence.rowCount).toBe(2);

      expect(evidence.rows[0].action).toBe(
        'candidate.restore'
      );

      expect(evidence.rows[1].action).toBe(
        'candidate.exclude'
      );

      for (const row of evidence.rows) {
        expect(row.signature).toBeTruthy();
      }
    }
  );
});
