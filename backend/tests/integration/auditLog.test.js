// SR-15 PostgreSQL tests: every privileged action is audit-logged (success and
// failure), with the action blocked if the log cannot be written.
const crypto = require('crypto');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { purgeAuditRows } = require('../helpers/fixtures');
const { createAuditedRunner } = require('../../src/services/auditLog');
const { setCandidateExclusion } = require('../../src/services/adminActions');

jest.setTimeout(15000);
let adminId; let voterId; let auditorId; let electionId; let candidateId;
const runAudited = createAuditedRunner({ pool: db.pool });

async function addUser(role) {
  return (await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'test-only-not-a-login', $2) RETURNING id",
    [`sr15_${role}_${crypto.randomUUID()}`, role])).rows[0].id;
}
const rowsFor = async actorIds => (await adminDb.query(
  'SELECT * FROM audit_log WHERE actor_id = ANY($1) ORDER BY id', [actorIds])).rows;
const excludedNow = async () => (await adminDb.query(
  'SELECT excluded FROM candidates WHERE id = $1', [candidateId])).rows[0].excluded;

beforeEach(async () => {
  adminId = await addUser('admin');
  voterId = await addUser('voter');
  auditorId = await addUser('auditor');
  electionId = (await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'draft') RETURNING id",
    ['SR15 isolated ' + crypto.randomUUID()])).rows[0].id;
  const division = (await adminDb.query('SELECT id FROM divisions ORDER BY id LIMIT 1')).rows[0].id;
  candidateId = (await adminDb.query(
    "INSERT INTO candidates (election_id, division_id, full_name, ballot_order) VALUES ($1, $2, 'Test Candidate', 1) RETURNING id",
    [electionId, division])).rows[0].id;
});
afterEach(async () => {
  await purgeAuditRows([adminId, voterId, auditorId]);
  await adminDb.query('DELETE FROM candidates WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  await adminDb.query('DELETE FROM users WHERE id = ANY($1)', [[adminId, voterId, auditorId]]);
});
afterAll(async () => { await db.pool.end(); await adminDb.end(); });

test('a successful privileged action is logged with actor, action, target, outcome and UTC time within 1s', async () => {
  const before = Date.now();
  const { result, audited } = await setCandidateExclusion({ actorId: adminId, candidateId, excluded: true }, runAudited);
  const elapsed = Date.now() - before;
  expect(result).toEqual({ candidateId, excluded: true });
  expect(elapsed).toBeLessThan(1000);
  expect(await excludedNow()).toBe(true);

  const [row] = await rowsFor([adminId]);
  expect(row).toMatchObject({
    actor_id: adminId, action: 'candidate.exclude', target: `candidate:${candidateId}`,
    outcome: 'success', detail: null
  });
  expect(row.occurred_at.getTime()).toBeGreaterThanOrEqual(before - 1000);
  expect(row.occurred_at.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
  expect(row.occurred_at.toISOString()).toMatch(/Z$/);
  expect(audited).toBe(true);
  // stored as an absolute instant: its UTC reading matches the JS instant
  const utc = (await adminDb.query(
    "SELECT to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS') AS t FROM audit_log WHERE id = $1",
    [row.id])).rows[0].t;
  expect(utc).toBe(row.occurred_at.toISOString().slice(0, 19));
});

test('a failed privileged action is rolled back and logged as a failure', async () => {
  await expect(setCandidateExclusion({ actorId: adminId, candidateId: 2147483000, excluded: true }, runAudited))
    .rejects.toThrow('Candidate not found');
  const rows = await rowsFor([adminId]);
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({
    actor_id: adminId, action: 'candidate.exclude', target: 'candidate:2147483000',
    outcome: 'failure', detail: 'action_error'
  });
  expect(rows[0].detail).not.toContain('Candidate');
});

test('an action that did some work and then failed leaves no change, only a failure row', async () => {
  await expect(runAudited({ actorId: adminId, action: 'candidate.exclude', target: `candidate:${candidateId}` },
    async client => {
      await client.query('UPDATE candidates SET excluded = TRUE WHERE id = $1', [candidateId]);
      throw new Error('boom after write');
    })).rejects.toThrow('boom after write');
  expect(await excludedNow()).toBe(false);
  expect((await rowsFor([adminId])).map(r => r.outcome)).toEqual(['failure']);
});

test.each([['voter'], ['auditor']])('unauthorised %s is blocked and the attempt is logged against them', async role => {
  const actorId = role === 'voter' ? voterId : auditorId;
  await expect(setCandidateExclusion({ actorId, candidateId, excluded: true }, runAudited))
    .rejects.toMatchObject({ code: 'FORBIDDEN' });
  expect(await excludedNow()).toBe(false);
  const rows = await rowsFor([actorId]);
  expect(rows).toHaveLength(1);
  expect(rows[0]).toMatchObject({ actor_id: actorId, outcome: 'failure', detail: 'not_authorised',
    action: 'candidate.exclude', target: `candidate:${candidateId}` });
});

test('roles can be widened per action', async () => {
  const widened = { actorId: auditorId, action: 'report.view', target: 'election:1', allowedRoles: ['admin', 'auditor'] };
  await expect(runAudited(widened, async () => 'ok')).resolves.toMatchObject({ result: 'ok' });
  expect((await rowsFor([auditorId]))[0]).toMatchObject({ outcome: 'success', action: 'report.view' });
});

// Wraps the real pool but makes the audit INSERT fail, like an unavailable log store.
function poolFailingAudit({ failTransactionalInsert = true, failStandaloneInsert = false } = {}) {
  const isAudit = sql => typeof sql === 'string' && sql.includes('INSERT INTO audit_log');
  return {
    connect: async () => {
      const client = await db.pool.connect();
      return {
        query: (sql, params) => (failTransactionalInsert && isAudit(sql)
          ? Promise.reject(new Error('audit store unavailable')) : client.query(sql, params)),
        release: discard => client.release(discard)
      };
    },
    query: (sql, params) => (failStandaloneInsert && isAudit(sql)
      ? Promise.reject(new Error('audit store unavailable')) : db.pool.query(sql, params))
  };
}

test('if the success record cannot be written the action is blocked and rolled back', async () => {
  const blocked = createAuditedRunner({ pool: poolFailingAudit() });
  const outcome = await setCandidateExclusion({ actorId: adminId, candidateId, excluded: true }, blocked)
    .catch(e => e);
  expect(outcome).toMatchObject({ name: 'AuditError', code: 'AUDIT_WRITE_FAILED' });
  expect(await excludedNow()).toBe(false);
  // The recorded failure row is written separately only if the log works at all;
  // here the store is down for the transactional insert only.
  expect((await rowsFor([adminId])).every(r => r.outcome === 'failure')).toBe(true);
});

test('if a failure record cannot be written the caller still gets an audit error and nothing changed', async () => {
  const blocked = createAuditedRunner({ pool: poolFailingAudit({ failStandaloneInsert: true }) });
  const outcome = await blocked({ actorId: voterId, action: 'candidate.exclude', target: `candidate:${candidateId}` },
    async () => 'should not run').catch(e => e);
  expect(outcome).toMatchObject({ code: 'AUDIT_WRITE_FAILED' });
  expect(await excludedNow()).toBe(false);
});

test('an unknown actor is rejected and nothing is changed', async () => {
  await expect(runAudited({ actorId: 2147483000, action: 'candidate.exclude', target: 'candidate:1' },
    async () => 'should not run')).rejects.toMatchObject({ code: 'INVALID_ACTOR' });
});

test.each([
  [{ actorId: 'x', action: 'a.b', target: 't' }],
  [{ actorId: 1, action: 'Bad Action', target: 't' }],
  [{ actorId: 1, action: 'a.b', target: 'has space' }],
  [{ actorId: 1, action: 'a.b', target: '' }],
  [{ actorId: 1, action: 'a.b' }]
])('invalid audit input %j is refused before any work', async input => {
  const work = jest.fn();
  await expect(runAudited(input, work)).rejects.toMatchObject({ code: 'INVALID_AUDIT_INPUT' });
  expect(work).not.toHaveBeenCalled();
});

test('audit rows cannot be changed or removed by the app or the admin; the app cannot read them', async () => {
  await setCandidateExclusion({ actorId: adminId, candidateId, excluded: true }, runAudited);
  await expect(db.query('UPDATE audit_log SET outcome = $1', ['failure'])).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('DELETE FROM audit_log')).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('SELECT * FROM audit_log')).rejects.toMatchObject({ code: '42501' });
  await expect(adminDb.query('UPDATE audit_log SET outcome = $1 WHERE actor_id = $2', ['failure', adminId]))
    .rejects.toThrow('append-only');
  await expect(adminDb.query('DELETE FROM audit_log WHERE actor_id = $1', [adminId])).rejects.toThrow('append-only');
  await expect(adminDb.query('TRUNCATE audit_log')).rejects.toThrow('append-only');
  expect(await rowsFor([adminId])).toHaveLength(1);
});

test('restoring a candidate is logged as a separate action', async () => {
  await setCandidateExclusion({ actorId: adminId, candidateId, excluded: true }, runAudited);
  await setCandidateExclusion({ actorId: adminId, candidateId, excluded: false }, runAudited);
  expect((await rowsFor([adminId])).map(r => r.action)).toEqual(['candidate.exclude', 'candidate.restore']);
  expect(await excludedNow()).toBe(false);
});
