// AI-generated tests for the AI-assisted SR-06 working branch.
const { createBallotSubmission } = require('../../src/services/ballotSubmission');
const db = require('../../src/config/db');

const input = { voterId: 1, electionId: 2, house: { preferences: [1] }, senate: { above: [1] } };
function setup() {
  const client = { query: jest.fn(async sql => ({ rowCount: 1, command: sql === 'COMMIT' ? 'COMMIT' : undefined })), release: jest.fn() };
  const pool = { connect: jest.fn().mockResolvedValue(client) };
  const eligibility = jest.fn().mockResolvedValue({ eligible: true, electionId: 2, divisionId: 3 });
  const storage = jest.fn().mockResolvedValue('anonymous-uuid');
  const validate = jest.fn().mockResolvedValue(true);
  const issueReceipt = jest.fn().mockResolvedValue({ verificationCode: 'test-receipt' });
  const recordHash = jest.fn().mockResolvedValue('0'.repeat(64));
  const submit = createBallotSubmission({ pool, checkEligibility: eligibility,
    saveBallotAnonymously: storage, recordBallotHash: recordHash, issueReceipt, validateBallots: validate });
  return { client, pool, eligibility, storage, validate, recordHash, issueReceipt, submit };
}
afterAll(() => db.pool.end());

test('requires an explicitly configured validator', () => {
  expect(() => createBallotSubmission()).toThrow('validator is required');
});
test('uses one client, locked eligibility and anonymous storage; commits before acceptance', async () => {
  const s = setup();
  await expect(s.submit(input)).resolves.toMatchObject({ accepted: true });
  expect(s.pool.connect).toHaveBeenCalledTimes(1);
  expect(s.eligibility).toHaveBeenCalledWith(1, 2, { client: s.client, lock: true });
  expect(s.storage.mock.calls.map(c => c[1])).toEqual([
    { electionId: 2, divisionId: 3, ballotType: 'house', ballotData: input.house },
    { electionId: 2, divisionId: 3, ballotType: 'senate', ballotData: input.senate }
  ]);
  expect(s.storage.mock.calls.every(c => c[0] === s.client)).toBe(true);
  expect(s.client.query.mock.calls.map(c => c[0])).toEqual([
    'BEGIN', 'INSERT INTO voter_participation (user_id, election_id) VALUES ($1, $2)', 'COMMIT'
  ]);
  expect(s.client.release).toHaveBeenCalledWith(false);
  expect(s.client.release).toHaveBeenCalledTimes(1);
});
test('acquisition failure does not attempt cleanup on a missing client', async () => {
  const s = setup(); const error = new Error('connection failed');
  s.pool.connect.mockRejectedValue(error);
  await expect(s.submit(input)).rejects.toBe(error);
  expect(s.client.query).not.toHaveBeenCalled();
  expect(s.client.release).not.toHaveBeenCalled();
});
test('BEGIN failure discards the client without ROLLBACK', async () => {
  const s = setup(); s.client.query.mockRejectedValueOnce(new Error('begin failed'));
  await expect(s.submit(input)).rejects.toThrow('begin failed');
  expect(s.client.query).toHaveBeenCalledTimes(1);
  expect(s.client.release).toHaveBeenCalledWith(true);
});
test('ineligibility preserves reason and rolls back without writes', async () => {
  const s = setup(); s.eligibility.mockResolvedValue({ eligible: false, reason: 'not_enrolled' });
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'INELIGIBLE', reason: 'not_enrolled' });
  expect(s.storage).not.toHaveBeenCalled();
  expect(s.client.query.mock.calls.map(c => c[0])).toEqual(['BEGIN', 'ROLLBACK']);
});
test('eligibility exceptions roll back and remain the original failure', async () => {
  const s = setup(); const error = new Error('eligibility failed'); s.eligibility.mockRejectedValue(error);
  await expect(s.submit(input)).rejects.toBe(error);
  expect(s.client.query).toHaveBeenLastCalledWith('ROLLBACK');
});
test('inconsistent eligibility cannot write participation', async () => {
  const s = setup(); s.eligibility.mockResolvedValue({ eligible: true, electionId: 99, divisionId: 3 });
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'INVALID_ELIGIBILITY' });
  expect(s.storage).not.toHaveBeenCalled();
});
test('invalid selections roll back before participation', async () => {
  const s = setup(); s.validate.mockResolvedValue(false);
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'INVALID_BALLOT' });
  expect(s.client.query.mock.calls.map(c => c[0])).toEqual(['BEGIN', 'ROLLBACK']);
});
test.each([{ ...input, senate: undefined }, { ...input, voterId: '1' }])(
  'invalid envelope acquires no client', async data => {
    const s = setup(); await expect(s.submit(data)).rejects.toBeInstanceOf(Error);
    expect(s.pool.connect).not.toHaveBeenCalled();
  }
);
test('only the participation constraint becomes a duplicate', async () => {
  const s = setup();
  s.client.query.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('unique'), {
    code: '23505', table: 'voter_participation', constraint: 'voter_participation_pkey'
  }));
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'ALREADY_VOTED' });
  expect(s.storage).not.toHaveBeenCalled();
  expect(s.client.query).toHaveBeenLastCalledWith('ROLLBACK');
});
test('an unrelated unique failure is not a duplicate-vote error', async () => {
  const s = setup(); const error = Object.assign(new Error('unique'), { code: '23505', table: 'other' });
  s.client.query.mockResolvedValueOnce({}).mockRejectedValueOnce(error);
  await expect(s.submit(input)).rejects.toBe(error);
});
test('Senate failure rolls back and does not commit', async () => {
  const s = setup(); s.storage.mockResolvedValueOnce('house').mockRejectedValueOnce(new Error('senate failed'));
  await expect(s.submit(input)).rejects.toThrow('senate failed');
  expect(s.client.query).toHaveBeenLastCalledWith('ROLLBACK');
  expect(s.client.query.mock.calls.some(c => c[0] === 'COMMIT')).toBe(false);
});
test('rollback failure preserves the original error and discards connection', async () => {
  const s = setup(); const original = new Error('storage'); const rollback = new Error('rollback');
  s.storage.mockRejectedValue(original);
  s.client.query.mockImplementation(async sql => { if (sql === 'ROLLBACK') throw rollback; return {}; });
  await expect(s.submit(input)).rejects.toBe(original);
  expect(original.rollbackError).toBe(rollback);
  expect(s.client.release).toHaveBeenCalledWith(true);
});
test('does not resolve acceptance or release while COMMIT is pending', async () => {
  const s = setup(); let releaseCommit; let enteredCommit;
  const entered = new Promise(resolve => { enteredCommit = resolve; });
  const pending = new Promise(resolve => { releaseCommit = resolve; });
  s.client.query.mockImplementation(sql => {
    if (sql === 'COMMIT') { enteredCommit(); return pending; }
    return Promise.resolve({});
  });
  let accepted = false;
  const result = s.submit(input).then(value => { accepted = true; return value; });
  await entered;
  expect(accepted).toBe(false); expect(s.client.release).not.toHaveBeenCalled();
  releaseCommit({ command: 'COMMIT' }); await expect(result).resolves.toMatchObject({ accepted: true });
});
test('a resolved COMMIT that actually rolled back is not accepted', async () => {
  const s = setup();
  s.client.query.mockImplementation(async sql => ({ command: sql === 'COMMIT' ? 'ROLLBACK' : undefined }));
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'TRANSACTION_NOT_COMMITTED' });
  expect(s.client.release).toHaveBeenCalledWith(true);
});
test('commit failure reports uncertainty rather than acceptance and discards connection', async () => {
  const s = setup();
  s.client.query.mockImplementation(async sql => { if (sql === 'COMMIT') throw new Error('lost connection'); return {}; });
  await expect(s.submit(input)).rejects.toMatchObject({ code: 'COMMIT_OUTCOME_UNKNOWN' });
  expect(s.client.release).toHaveBeenCalledWith(true);
});
