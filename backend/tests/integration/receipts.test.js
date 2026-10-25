// SR-12 PostgreSQL + HTTP tests: receipt issued with the vote, public bulletin
// board lookup, tampered/incorrect receipts, privacy, and counted status.
const crypto = require('crypto');
const request = require('supertest');
const app = require('../../src/app');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { purgeElectionBallots } = require('../helpers/fixtures');
const { createBallotSubmission } = require('../../src/services/ballotSubmission');
const { markElectionCounted, newVerificationCode } = require('../../src/services/receipts');
const { IntegrityError } = require('../../src/services/ballotIntegrity');
const { getPublicKey, verifyReceiptSignature } = require('../../src/security/receiptSigning');

jest.setTimeout(20000);
let voters = []; let electionId; let divisionId;
const submit = createBallotSubmission({ validateBallots: async () => true });

async function addVoter() {
  const id = (await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'test-only-not-a-login', 'voter') RETURNING id",
    ['sr12_' + crypto.randomUUID()])).rows[0].id;
  await adminDb.query('INSERT INTO enrolments (user_id, election_id, division_id) VALUES ($1, $2, $3)',
    [id, electionId, divisionId]);
  voters.push(id);
  return id;
}
const vote = voterId => ({ voterId, electionId, house: { preferences: [1, 2] }, senate: { above: [1] } });

beforeEach(async () => {
  divisionId = (await adminDb.query('SELECT id FROM divisions ORDER BY id LIMIT 1')).rows[0].id;
  electionId = (await adminDb.query(
    "INSERT INTO elections (name, status) VALUES ($1, 'open') RETURNING id",
    ['SR12 isolated ' + crypto.randomUUID()])).rows[0].id;
});
afterEach(async () => {
  await purgeElectionBallots(electionId);
  await adminDb.query('DELETE FROM voter_participation WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM enrolments WHERE election_id = $1', [electionId]);
  await adminDb.query('DELETE FROM elections WHERE id = $1', [electionId]);
  if (voters.length) await adminDb.query('DELETE FROM users WHERE id = ANY($1)', [voters]);
  voters = [];
});
afterAll(async () => { await db.pool.end(); await adminDb.end(); });

const verify = receipt => request(app).post('/api/bulletin-board/verify').send({ receipt });

test('a vote returns a signed receipt within two seconds that verifies against the public key', async () => {
  const started = Date.now();
  const result = await submit(vote(await addVoter()));
  expect(Date.now() - started).toBeLessThan(2000);
  expect(verifyReceiptSignature(result.receipt, getPublicKey())).toBe(true);
  expect(result.receipt.electionId).toBe(electionId);
  const key = await request(app).get('/api/bulletin-board/public-key');
  expect(key.status).toBe(200);
  expect(verifyReceiptSignature(result.receipt, key.body.publicKeyPem)).toBe(true);
});

test('each receipt has a unique verification code', async () => {
  const a = await submit(vote(await addVoter()));
  const b = await submit(vote(await addVoter()));
  expect(a.receipt.verificationCode).not.toBe(b.receipt.verificationCode);
  expect(a.receipt.commitment).not.toBe(b.receipt.commitment);
});

test('the public bulletin board confirms an accepted receipt, without authentication', async () => {
  const { receipt } = await submit(vote(await addVoter()));
  const res = await verify(receipt);
  expect(res.status).toBe(200);
  expect(res.headers['cache-control']).toBe('no-store');
  expect(res.body).toEqual({ authentic: true, found: true, status: 'accepted' });
});

test('after the integrity-checked count the board shows the receipt as counted', async () => {
  const { receipt } = await submit(vote(await addVoter()));
  await expect(markElectionCounted(db.pool, electionId)).rejects.toMatchObject({ code: 'ELECTION_NOT_CLOSED' });
  await adminDb.query("UPDATE elections SET status = 'closed' WHERE id = $1", [electionId]);
  await expect(markElectionCounted(db.pool, electionId)).resolves.toEqual({ counted: 1 });
  expect((await verify(receipt)).body).toEqual({ authentic: true, found: true, status: 'counted' });
});

test('tampered ballots stop receipts being marked counted', async () => {
  const { receipt } = await submit(vote(await addVoter()));
  await adminDb.query("UPDATE elections SET status = 'closed' WHERE id = $1", [electionId]);
  await adminDb.query("UPDATE ballots SET ballot_data_enc = $1 WHERE election_id = $2 AND ballot_type = 'house'",
    [require('../../src/security/encryption').encrypt('{"preferences":[9]}'), electionId]);
  await expect(markElectionCounted(db.pool, electionId)).rejects.toBeInstanceOf(IntegrityError);
  expect((await verify(receipt)).body.status).toBe('accepted');
});

test('a receipt count that does not match the ballots is not marked counted', async () => {
  await submit(vote(await addVoter()));
  await adminDb.query("UPDATE elections SET status = 'closed' WHERE id = $1", [electionId]);
  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('DELETE FROM bulletin_board WHERE election_id = $1', [electionId]);
    await client.query('COMMIT');
  } finally { client.release(); }
  await expect(markElectionCounted(db.pool, electionId)).rejects.toMatchObject({ code: 'RECEIPT_COUNT_MISMATCH' });
});

test('tampered or incorrect receipt data is not confirmed', async () => {
  const { receipt } = await submit(vote(await addVoter()));
  const forged = { ...receipt, verificationCode: newVerificationCode() };
  expect((await verify(forged)).body).toEqual({ authentic: false, found: false });
  expect((await verify({ ...receipt, commitment: 'a'.repeat(64) })).body).toEqual({ authentic: false, found: false });
  expect((await verify({ ...receipt, electionId: electionId + 1 })).body).toEqual({ authentic: false, found: false });
  expect((await verify({ ...receipt, signature: 'AAAA' })).body).toEqual({ authentic: false, found: false });
});

test('a genuine signature with no board entry is reported as not found', async () => {
  const { receipt } = await submit(vote(await addVoter()));
  const client = await adminDb.connect();
  try {
    await client.query('BEGIN');
    await client.query("SET LOCAL session_replication_role = 'replica'");
    await client.query('DELETE FROM bulletin_board WHERE election_id = $1', [electionId]);
    await client.query('COMMIT');
  } finally { client.release(); }
  expect((await verify(receipt)).body).toEqual({ authentic: true, found: false });
});

test('verify rejects a missing or non-object receipt', async () => {
  expect((await request(app).post('/api/bulletin-board/verify').send({})).status).toBe(400);
  expect((await request(app).post('/api/bulletin-board/verify').send({ receipt: 'x' })).status).toBe(400);
  expect((await request(app).post('/api/bulletin-board/verify').send({ receipt: [] })).status).toBe(400);
});

test('the receipt is rolled back with the vote if it cannot be issued', async () => {
  const voterId = await addVoter();
  const failing = createBallotSubmission({ validateBallots: async () => true,
    issueReceipt: async () => { throw new Error('signing unavailable'); } });
  await expect(failing(vote(voterId))).rejects.toThrow('signing unavailable');
  const left = await adminDb.query(
    `SELECT (SELECT count(*)::int FROM ballots WHERE election_id = $1) AS b,
            (SELECT count(*)::int FROM bulletin_board WHERE election_id = $1) AS r,
            (SELECT count(*)::int FROM voter_participation WHERE election_id = $1) AS p`, [electionId]);
  expect(left.rows[0]).toEqual({ b: 0, r: 0, p: 0 });
  await expect(submit(vote(voterId))).resolves.toMatchObject({ accepted: true });
});

test('the board and receipt reveal neither identity nor choice', async () => {
  const voterId = await addVoter();
  const { receipt } = await submit({ ...vote(voterId), house: { preferences: [4242, 1717] } });
  const board = await request(app).get(`/api/bulletin-board/elections/${electionId}`);
  expect(board.status).toBe(200);
  expect(board.body.count).toBe(1);
  expect(Object.keys(board.body.entries[0]).sort()).toEqual(['receiptRef', 'status']);
  const published = JSON.stringify([board.body, receipt]);
  expect(published).not.toContain('4242');
  expect(published).not.toContain('1717');
  expect(published).not.toContain('sr12_');
  expect(published).not.toContain(String(voterId) + ',');
  const columns = await adminDb.query(
    "SELECT column_name FROM information_schema.columns WHERE table_name = 'bulletin_board' ORDER BY column_name");
  expect(columns.rows.map(r => r.column_name)).toEqual(['commitment', 'election_id', 'receipt_ref', 'status']);
  // the public board lists a hash of the code, never the code the voter holds
  expect(JSON.stringify(board.body)).not.toContain(receipt.verificationCode);
  expect(JSON.stringify(board.body)).not.toContain(receipt.commitment);
});

test('the bulletin board table only allows adding rows and accepted -> counted', async () => {
  await submit(vote(await addVoter()));
  await expect(db.query("UPDATE bulletin_board SET status = 'accepted'")).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('UPDATE bulletin_board SET commitment = $1', ['b'.repeat(64)])).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('DELETE FROM bulletin_board')).rejects.toMatchObject({ code: '42501' });
  await expect(db.query('TRUNCATE bulletin_board')).rejects.toMatchObject({ code: '42501' });
  await expect(adminDb.query("UPDATE bulletin_board SET status = 'counted' WHERE election_id = $1", [electionId])).resolves.toBeDefined();
  await expect(adminDb.query("UPDATE bulletin_board SET status = 'accepted' WHERE election_id = $1", [electionId]))
    .rejects.toThrow('only allows');
});

test('election id in the board URL is validated', async () => {
  expect((await request(app).get('/api/bulletin-board/elections/abc')).status).toBe(400);
  expect((await request(app).get('/api/bulletin-board/elections/0')).status).toBe(400);
});
