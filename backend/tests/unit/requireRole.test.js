// SR-03: Unit tests for role-based access control.
// SR-17: Privacy-preserving logging for voter access-denied events.

const path = require('path');

// Load environment variables before running privacy-related tests.
require('dotenv').config({
  path: path.resolve(__dirname, '../../../.env'),
  quiet: true,
});

// Mock database queries so tests focus on middleware behaviour.
jest.mock('../../src/config/db', () => ({
  query: jest.fn(),
}));

const db = require('../../src/config/db');
const requireRole = require('../../src/middleware/requireRole');
const { pseudonymiseVoter } = require('../../src/security/voterPseudonym');

// Create a mock Express response object.
function makeRes() {
  const res = {};

  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);

  return res;
}

// Create a mock Express request object.
function makeReq(user) {
  return {
    user,
    method: 'POST',
    baseUrl: '/api/admin',
    path: '/candidates/3/exclusion',
  };
}

describe('requireRole', () => {
  beforeEach(() => {
    db.query.mockReset();
    db.query.mockResolvedValue({ rows: [] });
  });

  // Test 1: Requests without authentication must be rejected.
  test('returns 401 when there is no logged-in user', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(
      makeReq(undefined),
      res,
      next
    );

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
    expect(db.query).not.toHaveBeenCalled();
  });

  // Test 2: Authorised administrators must be allowed through.
  test('lets an allowed role through without logging anything', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(
      makeReq({ id: 1, role: 'admin' }),
      res,
      next
    );

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(db.query).not.toHaveBeenCalled();
  });

  // Test 3: Multiple permitted roles must be supported.
  test('accepts any role from a list of several', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin', 'auditor')(
      makeReq({ id: 2, role: 'auditor' }),
      res,
      next
    );

    expect(next).toHaveBeenCalledTimes(1);
    expect(db.query).not.toHaveBeenCalled();
  });

  // Test 4: Voter access denials must use HMAC-SHA-256 pseudonyms.
  test('blocks a voter with 403 and records a privacy-preserving denial', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(
      makeReq({ id: 5, role: 'voter' }),
      res,
      next
    );

    // Confirm the request was denied.
    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();

    // Exactly one privacy-preserving database entry should be written.
    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    // Voter events must use the privacy log.
    expect(sql).toContain('INSERT INTO voter_privacy_log');

    // Voter events must not use the administrator audit log.
    expect(sql).not.toContain('INSERT INTO audit_log');

    // Verify the pseudonym and event details.
    expect(params).toEqual([
      pseudonymiseVoter(5),
      'access.denied',
      'role_not_permitted',
    ]);

    // HMAC-SHA-256 produces a 64-character hexadecimal value.
    expect(params[0]).toMatch(/^[a-f0-9]{64}$/);

    // The original voter identifier must not be logged.
    expect(params).not.toContain(5);
  });

  // Test 5: Auditor access denials retain the existing audit mechanism.
  test('blocks an auditor with 403 and writes an administrator audit row', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(
      makeReq({ id: 2, role: 'auditor' }),
      res,
      next
    );

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    // Privileged-user denials continue using the administrator audit log.
    expect(sql).toContain('INSERT INTO audit_log');

    expect(params).toEqual([
      2,
      'access.denied',
      'POST:/api/admin/candidates/3/exclusion',
      'failure',
      'role_not_permitted',
    ]);
  });

  // Test 6: A database logging failure must not bypass access control.
  test('still returns 403 if the privacy log write fails', async () => {
    db.query.mockRejectedValue(new Error('db down'));

    // Suppress the expected error message during this test.
    const errorSpy = jest
      .spyOn(console, 'error')
      .mockImplementation(() => {});

    try {
      const res = makeRes();
      const next = jest.fn();

      await requireRole('admin')(
        makeReq({ id: 5, role: 'voter' }),
        res,
        next
      );

      expect(res.status).toHaveBeenCalledWith(403);
      expect(next).not.toHaveBeenCalled();

      // Confirm the middleware handles logging failures safely.
      expect(errorSpy).toHaveBeenCalledWith(
        'Could not write access-denied audit row'
      );
    } finally {
      errorSpy.mockRestore();
    }
  });

  // Test 7: Administrator audit targets must be sanitised.
  test('replaces unsafe characters in the audit target', async () => {
    const res = makeRes();
    const next = jest.fn();

    const req = makeReq({
      id: 5,
      role: 'auditor',
    });

    // Simulate unsafe characters in the request path.
    req.path = '/x y;<script>';

    await requireRole('admin')(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();

    expect(db.query).toHaveBeenCalledTimes(1);

    const [sql, params] = db.query.mock.calls[0];

    expect(sql).toContain('INSERT INTO audit_log');

    const target = params[2];

    // Only permitted characters should appear in audit targets.
    expect(target).toMatch(/^[A-Za-z0-9_.:/-]{1,200}$/);

    expect(target).not.toContain('<');
    expect(target).not.toContain('>');
    expect(target).not.toContain(';');
  });
});