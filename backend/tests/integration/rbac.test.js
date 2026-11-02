
/**
 * SR-03: Role-based access control integration tests.
 * SR-02: MFA protection for administrator routes.
 * SR-17: Privacy-preserving voter access-denied logging.
 * SR-18: Digitally signed administrator candidate actions.
 *
 * Run only against the disposable evp_sr18_compat database.
 */

if (process.env.DB_NAME !== 'evp_sr18_compat') {
  throw new Error(
    'RBAC compatibility tests must use evp_sr18_compat'
  );
}

const crypto = require('crypto');

const request = require('supertest');
const app = require('../../src/app');
const adminDb = require('../helpers/adminDb');
const pool = require('../../src/config/db');

const {
  pseudonymiseVoter
} = require('../../src/security/voterPseudonym');

const {
  signCandidateAction,
  keyIdOf,
  verifyCandidateAction
} = require('../../src/security/adminSigning');

const PASSWORD = 'Password123!';

const testKeyPair = crypto.generateKeyPairSync('ed25519');
const adminPrivateKey = testKeyPair.privateKey;
const adminPublicKey = testKeyPair.publicKey;

let electionId;
let divisionId;
let candidateId;

const logins = {};

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

function exclusionUrl(id) {
  return `/api/admin/candidates/${id}/exclusion`;
}

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

async function candidateExcluded() {
  const result = await adminDb.query(
    'SELECT excluded FROM candidates WHERE id = $1',
    [candidateId]
  );

  return result.rows[0].excluded;
}

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

  await login('admin1');
  await login('voter1');
  await login('auditor1');

  // Mark staff sessions as MFA-verified.
  await adminDb.query(
    `UPDATE sessions
     SET mfa_verified = TRUE
     WHERE token = ANY($1)`,
    [[
      logins.admin1.token,
      logins.auditor1.token
    ]]
  );

  // Register a temporary test signing key.
  await adminDb.query(
    `INSERT INTO admin_signing_keys
       (admin_id, public_key_pem, key_id)
     VALUES ($1, $2, $3)`,
    [
      logins.admin1.userId,
      adminPublicKey.export({
        type: 'spki',
        format: 'pem'
      }),
      keyIdOf(adminPublicKey)
    ]
  );

  const registeredKey = await adminDb.query(
    `SELECT id
     FROM admin_signing_keys
     WHERE admin_id = $1
       AND revoked_at IS NULL`,
    [logins.admin1.userId]
  );

  expect(registeredKey.rowCount).toBeGreaterThan(0);
});

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

  test('rejects a request with no session token (401)', async () => {
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .send({ excluded: true });

    expect(res.status).toBe(401);
    expect(await candidateExcluded()).toBe(false);
  });

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

  test(
    'lets an admin exclude and re-include a candidate (200) and audits it',
    async () => {
      const admin = logins.admin1;

      const before = await countAudit(
        admin.userId,
        'success'
      );

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

      expect(
        await countAudit(admin.userId, 'success')
      ).toBeGreaterThanOrEqual(before + 2);

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
