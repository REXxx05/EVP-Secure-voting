// SR-11 PostgreSQL tests: real hash store, append-only enforcement, tamper detection
// before tally, and ballot confirmation only after both hashes are saved.
const crypto = require('crypto');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { purgeElectionBallots } = require('../helpers/fixtures');
const { createBallotSubmission } = require('../../src/services/ballotSubmission');
const { loadBallotsForTally, IntegrityError, recordBallotHash } = require('../../src/services/ballotIntegrity');
const { encrypt } = require('../../src/security/encryption');

jest.setTimeout(15000);
let voterId; let electionId;
const submit = overrides => createBallotSubmission({ validateBallots: async () => true, ...overrides });
const vote = () => ({ voterId, electionId, house: { preferences: [3, 1, 2] }, senate: { above: [2] } });

beforeEach(async () => {
  const tag = crypto.randomUUID();
  const division = await adminDb.query('SELECT id FROM divisions ORDER BY id LIMIT 1');
  voterId = (await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'test-only-not-a-login', 'voter') RETURNING id",
    ['sr11_' + tag])).rows[0].id;
  electionId = (await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'open') RETURNING id", ['SR11 isolated ' + tag])).rows[0].id;
  await adminDb.query('INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [voterId, electionId, division.rows[0].id]);
});
afterEach(async () => {
  await purgeElectionBallots(electionId);
  await adminDb.query('DELETE FROM voter_participation WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM enrolments WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  await adminDb.query('DELETE FROM users WHERE id = $1', [voterId]);
});
afterAll(async () => { await db.pool.end(); await adminDb.end(); });

const hashCount = async () => (await adminDb.query(
  'SELECT count(*)::int AS n FROM ballot_hashes WHERE election_id = $1', [electionId])).rows[0].n;

test('accepting a vote records a hash for both ballots within one second', async () => {
  const started = Date.now();
  await expect(submit()(vote())).resolves.toMatchObject({ accepted: true });
  expect(Date.now() - started).toBeLessThan(1000);
  expect(await hashCount()).toBe(2);
  const rows = (await adminDb.query('SELECT hash FROM ballot_hashes WHERE election_id = $1', [electionId])).rows;
  rows.forEach(r => expect(r.hash).toMatch(/^[0-9a-f]{64}$/));
});

test('hash failure after both ballots rolls back ballots, hashes and participation', async () => {
  let calls = 0;
  const failing = submit({ recordBallotHash: async (client, id) => {
    if (++calls === 2) throw new Error('hash store unavailable');
    return recordBallotHash(client, id);
  } });
  await expect(failing(vote())).rejects.toThrow('hash store unavailable');
  const left = await adminDb.query(
    `SELECT (SELECT count(*)::int FROM ballots WHERE election_id = $1) AS b,
            (SELECT count(*)::int FROM ballot_hashes WHERE election_id = $1) AS h,
            (SELECT count(*)::int FROM voter_participation WHERE election_id = $1) AS p`, [electionId]);
  expect(left.rows[0]).toEqual({ b: 0, h: 0, p: 0 });
  await expect(submit()(vote())).resolves.toMatchObject({ accepted: true });
});

test('untampered ballots pass the tally gate', async () => {
  await submit()(vote());
  const ballots = await loadBallotsForTally(db.pool, electionId);
  expect(ballots).toHaveLength(2);
  expect(ballots.map(b => b.ballotType).sort()).toEqual(['house', 'senate']);
  expect(ballots.find(b => b.ballotType === 'house').ballotData).toEqual({ preferences: [3, 1, 2] });
});

test('the app user cannot update, delete or truncate hashes; admin is blocked by the trigger', async () => {
  await submit()(vote());
  await expect(db.query('UPDATE ballot_hashes SET hash = $1', ['0'.repeat(64)])).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('DELETE FROM ballot_hashes')).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('TRUNCATE ballot_hashes')).rejects.toMatchObject({ code: '42501' });
  await expect(adminDb.query('UPDATE ballot_hashes SET hash = $1 WHERE election_id = $2', ['0'.repeat(64), electionId]))
    .rejects.toThrow('append-only');
  await expect(adminDb.query('DELETE FROM ballot_hashes WHERE election_id = $1', [electionId]))
    .rejects.toThrow('append-only');
  expect(await hashCount()).toBe(2);
});

// Tampering is done as the admin: the app user cannot modify ballots at all.
test('replacing ballot content with a validly encrypted different ballot blocks the tally', async () => {
  await submit()(vote());
  await adminDb.query("UPDATE ballots SET ballot_data_enc = $1 WHERE election_id = $2 AND ballot_type = 'house'",
    [encrypt(JSON.stringify({ preferences: [1, 2, 3] })), electionId]);
  const error = await loadBallotsForTally(db.pool, electionId).catch(e => e);
  expect(error).toBeInstanceOf(IntegrityError);
  expect(error.mismatches).toHaveLength(1);
  expect(error.mismatches[0].reason).toBe('hash_mismatch');
});

test('corrupting ciphertext blocks the tally', async () => {
  await submit()(vote());
  await adminDb.query(
    "UPDATE ballots SET ballot_data_enc = '1:AAAAAAAAAAAAAAAA:AAAAAAAAAAAAAAAAAAAAAA==:AAAA' WHERE election_id = $1 AND ballot_type = 'senate'",
    [electionId]);
  const error = await loadBallotsForTally(db.pool, electionId).catch(e => e);
  expect(error).toBeInstanceOf(IntegrityError);
  expect(error.mismatches[0].reason).toBe('undecryptable');
});

test('moving a ballot to another chamber is detected', async () => {
  await submit()(vote());
  await adminDb.query("UPDATE ballots SET ballot_type = 'senate' WHERE election_id = $1 AND ballot_type = 'house'", [electionId]);
  await expect(loadBallotsForTally(db.pool, electionId)).rejects.toBeInstanceOf(IntegrityError);
});

test('an injected ballot without a hash blocks the tally', async () => {
  await submit()(vote());
  const division = (await adminDb.query(
    'SELECT division_id FROM enrolments WHERE user_id = $1 AND election_id = $2', [voterId, electionId])).rows[0].division_id;
  await adminDb.query(
    "INSERT INTO ballots (election_id, division_id, ballot_type, ballot_data_enc, key_version) VALUES ($1,$2,'house',$3,1)",
    [electionId, division, encrypt('{"preferences":[1]}')]);
  const error = await loadBallotsForTally(db.pool, electionId).catch(e => e);
  expect(error).toBeInstanceOf(IntegrityError);
  expect(error.mismatches.map(m => m.reason)).toEqual(['missing_hash']);
});

test('a deleted ballot whose hash remains blocks the tally', async () => {
  await submit()(vote());
  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query("DELETE FROM ballots WHERE election_id = $1 AND ballot_type = 'senate'", [electionId]);
    await client.query('COMMIT');
  } finally { client.release(); }
  const error = await loadBallotsForTally(db.pool, electionId).catch(e => e);
  expect(error).toBeInstanceOf(IntegrityError);
  expect(error.mismatches.map(m => m.reason)).toEqual(['ballot_missing']);
});

test('the hash store links only to the anonymous ballot id, never to a voter', async () => {
  const columns = await adminDb.query(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'ballot_hashes' ORDER BY column_name");
  expect(columns.rows.map(r => r.column_name)).toEqual(['ballot_id', 'election_id', 'hash']);
});
