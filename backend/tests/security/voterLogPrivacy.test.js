// SR-17: Privacy-Preserving Logs
// Security tests for voter pseudonymisation and access-denied logging.

const path = require('path');
const crypto = require('crypto');

// Load the HMAC key from the project's root .env file.
require('dotenv').config({
  path: path.resolve(__dirname, '../../../.env'),
  quiet: true,
});

// Mock database access to avoid changing real database records.
jest.mock('../../src/config/db', () => ({
  query: jest.fn(),
}));

const db = require('../../src/config/db');
const requireRole = require('../../src/middleware/requireRole');
const {
  pseudonymiseVoter,
} = require('../../src/security/voterPseudonym');

// Create a mock Express response.
function makeRes() {
  const res = {};

  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);

  return res;
}

// Create a mock request containing an authenticated voter.
function makeVoterRequest(voterId) {
  return {
    user: {
      id: voterId,
      role: 'voter',
    },
    method: 'POST',
    baseUrl: '/api/admin',
    path: '/candidates/3/exclusion',
    ip: '192.0.2.15',
  };
}

describe('SR-17: Voter pseudonymisation', () => {
  test('produces a 64-character SHA-256 HMAC pseudonym', () => {
    const pseudonym = pseudonymiseVoter(12345);

    expect(pseudonym).toMatch(/^[a-f0-9]{64}$/);
  });

  test('produces the same pseudonym for the same voter', () => {
    const first = pseudonymiseVoter(12345);
    const second = pseudonymiseVoter(12345);

    expect(first).toBe(second);
  });

  test('produces different pseudonyms for different voters', () => {
    const first = pseudonymiseVoter(12345);
    const second = pseudonymiseVoter(67890);

    expect(first).not.toBe(second);
  });

  test('uses HMAC-SHA-256 rather than plain SHA-256', () => {
    const voterId = 12345;

    const pseudonym = pseudonymiseVoter(voterId);

    const plainHash = crypto
      .createHash('sha256')
      .update(String(voterId))
      .digest('hex');

    expect(pseudonym).not.toBe(plainHash);
  });

  test('rejects invalid voter identifiers', () => {
    expect(() => pseudonymiseVoter(null)).toThrow();
    expect(() => pseudonymiseVoter(undefined)).toThrow();
    expect(() => pseudonymiseVoter('12345')).toThrow();
    expect(() => pseudonymiseVoter(-1)).toThrow();
    expect(() => pseudonymiseVoter(0)).toThrow();
  });
});

describe('SR-17: Privacy-preserving voter access-denied logs', () => {
  beforeEach(() => {
    db.query.mockReset();
    db.query.mockResolvedValue({ rows: [] });
  });

  test('stores the pseudonym instead of the raw voter ID', async () => {
    const voterId = 12345;
    const req = makeVoterRequest(voterId);
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO voter_privacy_log');

    expect(params[0]).toBe(pseudonymiseVoter(voterId));
    expect(params[0]).not.toBe(String(voterId));

    expect(params).not.toContain(voterId);
  });

  test('does not store voter IP addresses in the privacy log', async () => {
    const req = makeVoterRequest(12345);
    const res = makeRes();

    await requireRole('admin')(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    expect(sql).not.toMatch(/\bip_address\b/i);
    expect(sql).not.toMatch(/\bclient_ip\b/i);

    expect(JSON.stringify(params)).not.toContain(req.ip);
  });

  test('does not include timestamps or ballot identifiers in the voter log insert', async () => {
    const req = makeVoterRequest(12345);

    req.body = {
      ballotId: 'BALLOT-PRIVATE-123',
    };

    const res = makeRes();

    await requireRole('admin')(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    expect(sql).not.toMatch(/\btimestamp\b/i);
    expect(sql).not.toMatch(/\bcreated_at\b/i);
    expect(sql).not.toMatch(/\bballot_id\b/i);

    const loggedValues = JSON.stringify(params);

    expect(loggedValues).not.toContain('BALLOT-PRIVATE-123');
    expect(loggedValues).not.toContain(req.ip);
  });

  test('does not insert voter denials into the administrator audit log', async () => {
    const req = makeVoterRequest(12345);
    const res = makeRes();

    await requireRole('admin')(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO voter_privacy_log');
    expect(sql).not.toContain('INSERT INTO audit_log');
  });

  test('records only the expected privacy-safe event information', async () => {
    const req = makeVoterRequest(12345);
    const res = makeRes();

    await requireRole('admin')(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [, params] = db.query.mock.calls[0];

    expect(params).toEqual([
      pseudonymiseVoter(12345),
      'access.denied',
      'role_not_permitted',
    ]);
  });
});