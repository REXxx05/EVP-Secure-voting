// AI-generated SR-06 tests. Identity and SR-07 validation are simulated ONLY here.
// Eligibility, anonymous storage, encryption, transactions and races use real PostgreSQL.
const crypto = require('crypto');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { createBallotSubmission } = require('../../src/services/ballotSubmission');
const { saveBallotAnonymously } = require('../../src/services/ballotStorage');

jest.setTimeout(15000);
let voterId; let electionId; let divisionId;
const simulatedValidator = async () => true; // Not a production SR-07 implementation.
const makeSubmit = overrides => createBallotSubmission({ validateBallots: simulatedValidator, ...overrides });
const input = () => ({ voterId, electionId, house: { preferences: [1, 2, 3] }, senate: { above: [1] } });

beforeEach(async () => {
  const tag = crypto.randomUUID();
  const division = await adminDb.query('SELECT id FROM divisions ORDER BY id LIMIT 1');
  divisionId = division.rows[0].id;
  const voter = await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'test-only-not-a-login', 'voter') RETURNING id",
    ['sr06_' + tag]
  );
  voterId = voter.rows[0].id;
  const election = await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'open') RETURNING id", ['SR06 isolated ' + tag]
  );
  electionId = election.rows[0].id;
  await adminDb.query('INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [voterId, electionId, divisionId]);
});
afterEach(async () => {
  // Scope every cleanup to this test's generated fixture; never reset the database/volume.
  if (electionId) {
    await adminDb.query('DELETE FROM ballots WHERE election_id = $1', [electionId]);
    await adminDb.query('DELETE FROM voter_participation WHERE election_id = $1', [electionId]);
    await adminDb.query('DELETE FROM enrolments WHERE election_id = $1', [electionId]);
    await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  }
  if (voterId) await adminDb.query('DELETE FROM users WHERE id = $1', [voterId]);
  voterId = electionId = undefined;
});
afterAll(async () => { await db.pool.end(); await adminDb.end(); });

async function counts() {
  const result = await adminDb.query(
    `SELECT
      (SELECT count(*)::int FROM voter_participation WHERE election_id = $1) AS participation,
      (SELECT count(*)::int FROM ballots WHERE election_id = $1 AND ballot_type = 'house') AS house,
      (SELECT count(*)::int FROM ballots WHERE election_id = $1 AND ballot_type = 'senate') AS senate`,
    [electionId]
  );
  return result.rows[0];
}
const empty = { participation: 0, house: 0, senate: 0 };
const complete = { participation: 1, house: 1, senate: 1 };

test('accepts one complete pair and rejects a duplicate without additional ballots', async () => {
  const submit = makeSubmit();
  await expect(submit(input())).resolves.toEqual({ accepted: true });
  expect(await counts()).toEqual(complete);
  await expect(submit(input())).rejects.toMatchObject({ code: 'ALREADY_VOTED' });
  expect(await counts()).toEqual(complete);
});

test('Senate SQL failure rolls back real House and participation writes; retry succeeds', async () => {
  const submit = makeSubmit({ saveBallotAnonymously: async (client, ballot) => {
    if (ballot.ballotType === 'senate') {
      // Real PostgreSQL constraint failure after the House write, not just a mocked rejection.
      await client.query(
        "INSERT INTO ballots (election_id, division_id, ballot_type, ballot_data_enc) VALUES ($1,$2,'invalid','test')",
        [ballot.electionId, ballot.divisionId]
      );
    }
    return saveBallotAnonymously(client, ballot);
  } });
  await expect(submit(input())).rejects.toMatchObject({ code: '23514' });
  expect(await counts()).toEqual(empty);
  await expect(makeSubmit()(input())).resolves.toEqual({ accepted: true });
  expect(await counts()).toEqual(complete);
});

test('ineligible voter leaves no participation or chamber records', async () => {
  await adminDb.query('DELETE FROM enrolments WHERE user_id = $1 AND election_id = $2', [voterId, electionId]);
  await expect(makeSubmit()(input())).rejects.toMatchObject({ code: 'INELIGIBLE', reason: 'not_enrolled' });
  expect(await counts()).toEqual(empty);
});

test('missing Senate cannot consume participation or store House', async () => {
  await expect(makeSubmit()({ ...input(), senate: undefined })).rejects.toMatchObject({ code: 'INVALID_BALLOT' });
  expect(await counts()).toEqual(empty);
});

test('transactional finalizer success persists its test marker with both ballots', async () => {
  // Marker in existing test user's row exercises transaction sharing, not SR-04 semantics.
  const submit = makeSubmit({ finalizeSession: async ({ client, sessionId, voterId: owner }) => {
    expect(sessionId).toBe(123);
    await client.query('UPDATE users SET failed_logins = 1 WHERE id = $1', [owner]);
    return true;
  } });
  await expect(submit({ ...input(), sessionId: 123 })).resolves.toEqual({ accepted: true });
  expect(await counts()).toEqual(complete);
  expect((await adminDb.query('SELECT failed_logins FROM users WHERE id = $1', [voterId])).rows[0].failed_logins).toBe(1);
});

test('transactional finalizer denial rolls back its test marker and the complete ballot pair', async () => {
  const submit = makeSubmit({ finalizeSession: async ({ client, voterId: owner }) => {
    await client.query('UPDATE users SET failed_logins = 1 WHERE id = $1', [owner]);
    return false;
  } });
  await expect(submit({ ...input(), sessionId: 123 })).rejects.toMatchObject({ code: 'INVALID_SESSION' });
  expect(await counts()).toEqual(empty);
  expect((await adminDb.query('SELECT failed_logins FROM users WHERE id = $1', [voterId])).rows[0].failed_logins).toBe(0);
});

test('a swallowed SQL failure cannot turn PostgreSQL COMMIT-as-ROLLBACK into acceptance', async () => {
  const submit = makeSubmit({ saveBallotAnonymously: async (client, ballot) => {
    if (ballot.ballotType === 'senate') {
      // Deliberately broken test collaborator: suppress a real SQL error.
      try { await client.query('SELECT 1 / 0'); } catch (_) { /* test-only swallowed error */ }
      return;
    }
    return saveBallotAnonymously(client, ballot);
  } });
  await expect(submit(input())).rejects.toMatchObject({ code: 'TRANSACTION_NOT_COMMITTED' });
  expect(await counts()).toEqual(empty);
});

function deferred() {
  let resolve;
  const promise = new Promise(r => { resolve = r; });
  return { promise, resolve };
}

async function assertDatabaseWait(pid) {
  const deadline = Date.now() + 5000;
  while (Date.now() < deadline) {
    const result = await adminDb.query('SELECT cardinality(pg_blocking_pids($1)) > 0 AS blocked', [pid]);
    if (result.rows[0].blocked) return;
    await new Promise(resolve => setTimeout(resolve, 20));
  }
  throw new Error('Second submission never entered an observed PostgreSQL lock wait');
}

test.each([false, true])('overlapping submissions: first rolls back=%s; exactly one complete pair persists', async rollbackFirst => {
  const houseWritten = deferred(); const releaseFirst = deferred(); const secondInsert = deferred();
  const first = makeSubmit({ saveBallotAnonymously: async (client, ballot) => {
    if (ballot.ballotType === 'senate' && rollbackFirst) throw new Error('Injected first Senate failure');
    const id = await saveBallotAnonymously(client, ballot);
    if (ballot.ballotType === 'house') { houseWritten.resolve(); await releaseFirst.promise; }
    return id;
  } });
  let secondPid;
  const second = makeSubmit({ pool: { connect: async () => {
    const client = await db.pool.connect();
    try {
      secondPid = (await client.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;
    } catch (error) { client.release(true); throw error; }
    return {
      query: (sql, params) => {
        const pending = client.query(sql, params);
        if (sql.startsWith('INSERT INTO voter_participation')) secondInsert.resolve();
        return pending;
      },
      release: destroy => client.release(destroy)
    };
  } } });
  // Attach rejection handlers immediately; tests must not leak unhandled rejections.
  const outcome = promise => promise.then(value => ({ value }), error => ({ error }));
  const firstResult = outcome(first(input()));
  let secondResult;
  try {
    await houseWritten.promise;
    secondResult = outcome(second(input()));
    await secondInsert.promise;
    await assertDatabaseWait(secondPid); // Proves overlap; Promise.all alone would not.
    expect(await counts()).toEqual(empty); // Uncommitted first writes are invisible externally.
  } finally {
    releaseFirst.resolve();
    await firstResult;
    if (secondResult) await secondResult;
  }
  const a = await firstResult; const b = await secondResult;
  expect([a, b].filter(x => x.value && x.value.accepted)).toHaveLength(1);
  if (rollbackFirst) {
    expect(a.error.message).toBe('Injected first Senate failure');
    expect(b.value).toEqual({ accepted: true });
  } else {
    expect(a.value).toEqual({ accepted: true });
    expect(b.error.code).toBe('ALREADY_VOTED');
  }
  expect(await counts()).toEqual(complete);
});
