// SR-17: Privacy-preserving eligibility-denied logging tests.

const path = require('path');

// Load the project's HMAC key without displaying it.
require('dotenv').config({
  path: path.resolve(__dirname, '../../../.env'),
  quiet: true,
});

// Mock database access to avoid modifying real records.
jest.mock('../../src/config/db', () => ({
  query: jest.fn(),
}));

// Mock eligibility checks.
jest.mock('../../src/services/eligibilityService', () => ({
  checkEligibility: jest.fn(),
}));

const db = require('../../src/config/db');

const {
  checkEligibility,
} = require('../../src/services/eligibilityService');

const requireEligibleVoter = require(
  '../../src/middleware/requireEligibleVoter'
);

const {
  pseudonymiseVoter,
} = require('../../src/security/voterPseudonym');

function makeRes() {
  const res = {};

  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);

  return res;
}

function makeRequest(voterId = 12345) {
  return {
    user: {
      id: voterId,
      role: 'voter',
    },
    params: {
      electionId: '7',
    },
    ip: '192.0.2.15',
    body: {
      ballotId: 'BALLOT-PRIVATE-123',
    },
  };
}

describe('SR-17: Privacy-preserving eligibility-denied logging', () => {
  beforeEach(() => {
    jest.clearAllMocks();

    db.query.mockResolvedValue({
      rows: [],
    });

    checkEligibility.mockResolvedValue({
      eligible: false,
      reason: 'not_enrolled',
    });
  });

  test('stores an HMAC pseudonym instead of the raw voter ID', async () => {
    const voterId = 12345;

    const req = makeRequest(voterId);
    const res = makeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO voter_privacy_log');

    expect(params[0]).toBe(pseudonymiseVoter(voterId));
    expect(params[0]).toMatch(/^[a-f0-9]{64}$/);

    expect(params).not.toContain(voterId);
    expect(params).not.toContain(String(voterId));
  });

  test('does not expose IP addresses or ballot identifiers', async () => {
    const req = makeRequest();
    const res = makeRes();

    await requireEligibleVoter(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    const loggedValues = JSON.stringify(params);

    expect(sql).not.toMatch(/\bip_address\b/i);
    expect(sql).not.toMatch(/\bballot_id\b/i);
    expect(sql).not.toMatch(/\belection_id\b/i);
    expect(sql).not.toMatch(/\bcreated_at\b/i);

    expect(loggedValues).not.toContain(req.ip);
    expect(loggedValues).not.toContain(req.body.ballotId);
  });

  test('records only the expected privacy-safe event information', async () => {
    const req = makeRequest();
    const res = makeRes();

    await requireEligibleVoter(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [, params] = db.query.mock.calls[0];

    expect(params).toEqual([
      pseudonymiseVoter(12345),
      'eligibility.denied',
      'not_enrolled',
    ]);
  });

  test('does not write eligibility denials to the administrator audit log', async () => {
    const req = makeRequest();
    const res = makeRes();

    await requireEligibleVoter(req, res, jest.fn());

    const [sql] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO voter_privacy_log');
    expect(sql).not.toContain('INSERT INTO audit_log');
  });

  test('does not log direct voter identifiers through console methods', async () => {
    const logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    const warnSpy = jest.spyOn(console, 'warn').mockImplementation(() => {});
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});

    try {
      const req = makeRequest();
      const res = makeRes();

      await requireEligibleVoter(req, res, jest.fn());

      expect(logSpy).not.toHaveBeenCalled();
      expect(warnSpy).not.toHaveBeenCalled();
      expect(errorSpy).not.toHaveBeenCalled();
    } finally {
      logSpy.mockRestore();
      warnSpy.mockRestore();
      errorSpy.mockRestore();
    }
  });

  test('does not create a voter privacy log for unauthenticated requests', async () => {
    const req = makeRequest();

    delete req.user;

    const res = makeRes();

    await requireEligibleVoter(req, res, jest.fn());

    expect(res.status).toHaveBeenCalledWith(401);
    expect(db.query).not.toHaveBeenCalled();
  });

  test('does not record raw voter IDs when the eligibility reason is unexpected', async () => {
    checkEligibility.mockResolvedValue({
      eligible: false,
      reason: 'unexpected_internal_reason',
    });

    const req = makeRequest();
    const res = makeRes();

    await requireEligibleVoter(req, res, jest.fn());

    expect(db.query).toHaveBeenCalledTimes(1);

    const [, params] = db.query.mock.calls[0];

    expect(params).toEqual([
      pseudonymiseVoter(12345),
      'eligibility.denied',
      'invalid_input',
    ]);

    expect(res.status).toHaveBeenCalledWith(403);
  });
});