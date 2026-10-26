// SR-03: integration tests for role-based access control.
// Uses the seeded users admin1, voter1 and auditor1 (password Password123!).

const request = require('supertest');
const app = require('../../src/app');
const adminDb = require('../helpers/adminDb');
const pool = require('../../src/config/db');
const { purgeAuditRows } = require('../helpers/fixtures');

const PASSWORD = 'Password123!';

let electionId;
let divisionId;
let candidateId;
const logins = {}; // username -> { userId, token }

async function login(username) {
  const res = await request(app)
    .post('/api/auth/login')
    .send({ username, password: PASSWORD });
  expect(res.status).toBe(200);
  logins[username] = { userId: res.body.userId, token: res.body.sessionToken };
}

function exclusionUrl(id) {
  return `/api/admin/candidates/${id}/exclusion`;
}

async function countAudit(actorId, outcome) {
  const result = await adminDb.query(
    'SELECT count(*)::int AS n FROM audit_log WHERE actor_id = $1 AND outcome = $2',
    [actorId, outcome]
  );
  return result.rows[0].n;
}

async function candidateExcluded() {
  const result = await adminDb.query('SELECT excluded FROM candidates WHERE id = $1', [candidateId]);
  return result.rows[0].excluded;
}

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
    `INSERT INTO candidates (election_id, division_id, full_name, party, ballot_order)
     VALUES ($1, $2, 'SR03 Test Candidate', 'Test Party', 1) RETURNING id`,
    [electionId, divisionId]
  );
  candidateId = candidate.rows[0].id;

  await login('admin1');
  await login('voter1');
  await login('auditor1');
});

afterAll(async () => {
  // Log the test sessions out through the API
  for (const name of Object.keys(logins)) {
    await request(app).post('/api/auth/logout').set('x-session-token', logins[name].token);
  }

  // Remove the audit rows these seeded users produced, then the fake data
  await purgeAuditRows(Object.values(logins).map((l) => l.userId));
  await adminDb.query('DELETE FROM candidates WHERE id = $1', [candidateId]);
  await adminDb.query('DELETE FROM divisions WHERE id = $1', [divisionId]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  await adminDb.end();
  await pool.pool.end();
});

describe('SR-03 role-based access control', () => {
  test('rejects a request with no session token (401)', async () => {
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .send({ excluded: true });

    expect(res.status).toBe(401);
    expect(await candidateExcluded()).toBe(false);
  });

  test('blocks a voter with 403, changes nothing and logs the denial within 1 second', async () => {
    const voter = logins.voter1;
    const before = await countAudit(voter.userId, 'failure');

    const started = Date.now();
    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', voter.token)
      .send({ excluded: true });
    const after = await countAudit(voter.userId, 'failure');
    const elapsed = Date.now() - started;

    expect(res.status).toBe(403);
    expect(await candidateExcluded()).toBe(false);
    expect(after).toBe(before + 1);
    expect(elapsed).toBeLessThan(1000);

    const row = await adminDb.query(
      `SELECT action, outcome FROM audit_log
       WHERE actor_id = $1 AND action = 'access.denied'
       ORDER BY id DESC LIMIT 1`,
      [voter.userId]
    );
    expect(row.rows[0].outcome).toBe('failure');
  });

  test('blocks an auditor with 403 and logs the denial', async () => {
    const auditor = logins.auditor1;
    const before = await countAudit(auditor.userId, 'failure');

    const res = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', auditor.token)
      .send({ excluded: true });

    expect(res.status).toBe(403);
    expect(await candidateExcluded()).toBe(false);
    expect(await countAudit(auditor.userId, 'failure')).toBe(before + 1);
  });

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

    expect(await candidateExcluded()).toBe(false);
  });

  test('lets an admin exclude and re-include a candidate (200) and audits it', async () => {
    const admin = logins.admin1;
    const before = await countAudit(admin.userId, 'success');

    const excludeRes = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', admin.token)
      .send({ excluded: true });
    expect(excludeRes.status).toBe(200);
    expect(await candidateExcluded()).toBe(true);

    const includeRes = await request(app)
      .post(exclusionUrl(candidateId))
      .set('x-session-token', admin.token)
      .send({ excluded: false });
    expect(includeRes.status).toBe(200);
    expect(await candidateExcluded()).toBe(false);

    expect(await countAudit(admin.userId, 'success')).toBeGreaterThanOrEqual(before + 2);
  });
});