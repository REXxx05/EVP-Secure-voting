// AI-generated route integration tests. Authentication/CSRF/session/validation
// are explicit test doubles. No claim of real login or production SR-07 coverage.
const express = require('express');
const request = require('supertest');
const { createBallotsRouter } = require('../../src/routes/ballots');
const db = require('../../src/config/db');

const body = { house: { preferences: [1] }, senate: { above: [1] } };
function setup(overrides = {}) {
  const client = { query: jest.fn(async sql => ({ command: sql === 'COMMIT' ? 'COMMIT' : undefined })), release: jest.fn() };
  const deps = {
    pool: { connect: jest.fn().mockResolvedValue(client) },
    authenticateVoter: (req, res, next) => { req.user = { id: 5, role: 'voter' }; req.session = { id: 8 }; next(); },
    verifyCsrf: (req, res, next) => next(),
    checkEligibility: jest.fn().mockResolvedValue({ eligible: true, electionId: 1, divisionId: 2 }),
    validateBallots: jest.fn().mockResolvedValue(true),
    saveBallotAnonymously: jest.fn().mockResolvedValue('uuid'),
    issueReceipt: jest.fn().mockResolvedValue({ verificationCode: 'test-receipt' }),
    recordBallotHash: jest.fn().mockResolvedValue('0'.repeat(64)),
    invalidateSession: jest.fn().mockResolvedValue(true),
    ...overrides
  };
  const app = express(); app.use(express.json()); app.use(createBallotsRouter(deps));
  return { app, client, deps };
}
afterAll(() => db.pool.end());

test('production route construction fails closed without real dependencies', () => {
  expect(() => createBallotsRouter()).toThrow('authenticateVoter');
  for (const key of ['authenticateVoter', 'verifyCsrf', 'validateBallots', 'invalidateSession']) {
    const configured = { authenticateVoter() {}, verifyCsrf() {}, validateBallots() {}, invalidateSession() {} };
    configured[key] = undefined;
    expect(() => createBallotsRouter(configured)).toThrow(key);
  }
});
test('maps trusted identity, invalidates the session on the same client and returns minimal 201', async () => {
  const s = setup(); const res = await request(s.app).post('/api/elections/1/ballots').send(body);
  expect(res.status).toBe(201); expect(res.body).toMatchObject({ accepted: true });
  expect(res.headers['cache-control']).toBe('no-store');
  expect(s.deps.checkEligibility).toHaveBeenCalledWith(5, 1, { client: s.client, lock: true });
  expect(s.deps.invalidateSession).toHaveBeenCalledWith({ client: s.client, sessionId: 8, voterId: 5 });
  expect(s.deps.invalidateSession.mock.invocationCallOrder[0]).toBeLessThan(s.client.query.mock.invocationCallOrder.at(-1));
});
test('missing authentication does not reach the database', async () => {
  const s = setup({ authenticateVoter: (req, res, next) => next() });
  expect((await request(s.app).post('/api/elections/1/ballots').send(body)).status).toBe(401);
  expect(s.deps.pool.connect).not.toHaveBeenCalled();
});
test('non-voter cannot submit', async () => {
  const s = setup({ authenticateVoter: (req, res, next) => { req.user = { id: 5, role: 'admin' }; req.session = { id: 8 }; next(); } });
  expect((await request(s.app).post('/api/elections/1/ballots').send(body)).status).toBe(403);
  expect(s.deps.pool.connect).not.toHaveBeenCalled();
});
test('CSRF denial does not reach submission', async () => {
  const s = setup({ verifyCsrf: (req, res) => res.status(403).json({ error: 'CSRF rejected' }) });
  expect((await request(s.app).post('/api/elections/1/ballots').send(body)).status).toBe(403);
  expect(s.deps.pool.connect).not.toHaveBeenCalled();
});
test.each(['0', '-1', '1.5', '1e0', '9007199254740992'])('rejects invalid election ID %s', async id => {
  const s = setup(); expect((await request(s.app).post(`/api/elections/${id}/ballots`).send(body)).status).toBe(400);
  expect(s.deps.pool.connect).not.toHaveBeenCalled();
});
test.each(['voterId', 'divisionId', 'sessionId'])('rejects client-supplied %s', async key => {
  const s = setup(); expect((await request(s.app).post('/api/elections/1/ballots').send({ ...body, [key]: 99 })).status).toBe(400);
  expect(s.deps.pool.connect).not.toHaveBeenCalled();
});
test('missing chamber and validator denial map to 422 without storage', async () => {
  const s = setup();
  expect((await request(s.app).post('/api/elections/1/ballots').send({ house: body.house })).status).toBe(422);
  const denied = setup({ validateBallots: jest.fn().mockResolvedValue(false) });
  expect((await request(denied.app).post('/api/elections/1/ballots').send(body)).status).toBe(422);
  expect(denied.deps.saveBallotAnonymously).not.toHaveBeenCalled();
});
test('eligibility denial maps to 403 without session finalization', async () => {
  const s = setup({ checkEligibility: jest.fn().mockResolvedValue({ eligible: false, reason: 'not_enrolled' }) });
  expect((await request(s.app).post('/api/elections/1/ballots').send(body)).status).toBe(403);
  expect(s.deps.invalidateSession).not.toHaveBeenCalled();
});
test('specific participation conflict maps to 409 with no SQL/identity leak', async () => {
  const s = setup();
  s.client.query.mockResolvedValueOnce({}).mockRejectedValueOnce(Object.assign(new Error('secret voter=5 SQL detail'), {
    code: '23505', table: 'voter_participation', constraint: 'voter_participation_pkey'
  }));
  const res = await request(s.app).post('/api/elections/1/ballots').send(body);
  expect(res.status).toBe(409); expect(res.text).not.toMatch(/secret|SQL|voter=5/);
});
test('storage errors are generic 500 and roll back', async () => {
  const s = setup({ saveBallotAnonymously: jest.fn().mockRejectedValue(new Error('private preferences')) });
  const res = await request(s.app).post('/api/elections/1/ballots').send(body);
  expect(res.status).toBe(500); expect(res.text).not.toContain('preferences');
  expect(s.client.query).toHaveBeenLastCalledWith('ROLLBACK');
});
test('session finalization failure prevents commit', async () => {
  const s = setup({ invalidateSession: jest.fn().mockResolvedValue(false) });
  const res = await request(s.app).post('/api/elections/1/ballots').send(body);
  expect(res.status).toBe(401); expect(s.client.query).toHaveBeenLastCalledWith('ROLLBACK');
  expect(s.client.query.mock.calls.some(c => c[0] === 'COMMIT')).toBe(false);
});
test('commit uncertainty maps to 503 instead of acceptance', async () => {
  const s = setup(); s.client.query.mockImplementation(async sql => { if (sql === 'COMMIT') throw new Error('connection lost'); return {}; });
  const res = await request(s.app).post('/api/elections/1/ballots').send(body);
  expect(res.status).toBe(503); expect(res.body.code).toBe('COMMIT_OUTCOME_UNKNOWN');
});
test('HTTP acceptance waits for COMMIT resolution', async () => {
  const s = setup(); let resolveCommit; let signalCommit;
  const committed = new Promise(resolve => { resolveCommit = resolve; });
  const entered = new Promise(resolve => { signalCommit = resolve; });
  s.client.query.mockImplementation(sql => {
    if (sql === 'COMMIT') { signalCommit(); return committed; }
    return Promise.resolve({});
  });
  let responseReceived = false;
  const response = request(s.app).post('/api/elections/1/ballots').send(body)
    .then(value => { responseReceived = true; return value; });
  await entered;
  expect(responseReceived).toBe(false);
  resolveCommit({ command: 'COMMIT' });
  expect((await response).status).toBe(201);
});
