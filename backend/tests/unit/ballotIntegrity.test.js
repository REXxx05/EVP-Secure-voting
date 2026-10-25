// SR-11 unit tests: hash computation and the tally gate, without a database.
const { computeBallotHash, verifyElection, loadBallotsForTally, IntegrityError } =
  require('../../src/services/ballotIntegrity');
const { encrypt } = require('../../src/security/encryption');

const base = { id: '11111111-1111-1111-1111-111111111111', electionId: 1, divisionId: 2,
  ballotType: 'house', plaintext: '{"preferences":[1,2]}' };

test('hash is 64 lowercase hex characters and deterministic', () => {
  const hash = computeBallotHash(base);
  expect(hash).toMatch(/^[0-9a-f]{64}$/);
  expect(computeBallotHash({ ...base })).toBe(hash);
});

test.each([
  ['content', { plaintext: '{"preferences":[2,1]}' }],
  ['ballot id', { id: '22222222-2222-2222-2222-222222222222' }],
  ['election', { electionId: 9 }],
  ['division', { divisionId: 9 }],
  ['chamber', { ballotType: 'senate' }]
])('changing the %s changes the hash', (_name, change) => {
  expect(computeBallotHash({ ...base, ...change })).not.toBe(computeBallotHash(base));
});

test('hash depends on the secret key held outside the database', () => {
  const original = process.env.BALLOT_INTEGRITY_KEY;
  const before = computeBallotHash(base);
  process.env.BALLOT_INTEGRITY_KEY = Buffer.alloc(32, 7).toString('base64');
  try {
    expect(computeBallotHash(base)).not.toBe(before);
  } finally {
    process.env.BALLOT_INTEGRITY_KEY = original;
  }
});

test('fails closed when the key is missing or short', () => {
  const original = process.env.BALLOT_INTEGRITY_KEY;
  try {
    delete process.env.BALLOT_INTEGRITY_KEY;
    expect(() => computeBallotHash(base)).toThrow('BALLOT_INTEGRITY_KEY is missing');
    process.env.BALLOT_INTEGRITY_KEY = Buffer.alloc(8).toString('base64');
    expect(() => computeBallotHash(base)).toThrow('at least 32 bytes');
  } finally {
    process.env.BALLOT_INTEGRITY_KEY = original;
  }
});

function rowFor(plaintext, overrides = {}) {
  const row = { id: base.id, election_id: 1, division_id: 2, ballot_type: 'house',
    ballot_data_enc: encrypt(plaintext), ...overrides };
  row.hash = 'hash' in overrides ? overrides.hash : computeBallotHash({ ...base, id: row.id, plaintext });
  return row;
}
const runnerWith = (rows, orphans = []) => ({
  query: jest.fn(async sql => (sql.includes('LEFT JOIN')
    ? { rows, rowCount: rows.length } : { rows: orphans, rowCount: orphans.length }))
});

test('verifyElection accepts untampered ballots and returns decrypted data', async () => {
  const result = await verifyElection(runnerWith([rowFor(base.plaintext)]), 1);
  expect(result.ok).toBe(true);
  expect(result.ballots).toEqual([{ id: base.id, divisionId: 2, ballotType: 'house', ballotData: { preferences: [1, 2] } }]);
});

test('verifyElection flags missing hash, mismatch, undecryptable data and missing ballot', async () => {
  const rows = [
    rowFor(base.plaintext, { hash: null }),
    rowFor(base.plaintext, { id: 'b', hash: 'f'.repeat(64) }),
    rowFor(base.plaintext, { id: 'c', ballot_data_enc: '1:AAAA:BBBB:CCCC' })
  ];
  const result = await verifyElection(runnerWith(rows, [{ ballot_id: 'gone' }]), 1);
  expect(result.ok).toBe(false);
  expect(result.ballots).toEqual([]);
  expect(result.mismatches.map(m => m.reason).sort())
    .toEqual(['ballot_missing', 'hash_mismatch', 'missing_hash', 'undecryptable']);
});

test('verifyElection rejects an invalid election id', async () => {
  await expect(verifyElection(runnerWith([]), 'x')).rejects.toThrow(TypeError);
});

test('loadBallotsForTally throws IntegrityError and returns nothing on a mismatch', async () => {
  const client = runnerWith([rowFor(base.plaintext, { hash: 'f'.repeat(64) })]);
  client.release = jest.fn();
  const pool = { connect: jest.fn().mockResolvedValue(client) };
  await expect(loadBallotsForTally(pool, 1)).rejects.toBeInstanceOf(IntegrityError);
  expect(client.release).toHaveBeenCalledTimes(1);
});
