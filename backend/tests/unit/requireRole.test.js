// SR-03: unit tests for the requireRole middleware.
// The database is mocked, so these tests only check the decision logic.

jest.mock('../../src/config/db', () => ({
  query: jest.fn(),
}));

const db = require('../../src/config/db');
const requireRole = require('../../src/middleware/requireRole');

function makeRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

function makeReq(user) {
  return { user, method: 'POST', baseUrl: '/api/admin', path: '/candidates/3/exclusion' };
}

describe('requireRole', () => {
  beforeEach(() => {
    db.query.mockReset();
    db.query.mockResolvedValue({ rows: [] });
  });

  test('returns 401 when there is no logged-in user', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(makeReq(undefined), res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
    expect(db.query).not.toHaveBeenCalled();
  });

  test('lets an allowed role through without logging anything', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(makeReq({ id: 1, role: 'admin' }), res, next);

    expect(next).toHaveBeenCalledTimes(1);
    expect(res.status).not.toHaveBeenCalled();
    expect(db.query).not.toHaveBeenCalled();
  });

  test('accepts any role from a list of several', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin', 'auditor')(makeReq({ id: 2, role: 'auditor' }), res, next);

    expect(next).toHaveBeenCalledTimes(1);
  });

  test('blocks a role that is not allowed with 403 and writes an audit row', async () => {
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(makeReq({ id: 5, role: 'voter' }), res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    expect(db.query).toHaveBeenCalledTimes(1);

    const params = db.query.mock.calls[0][1];
    expect(params).toEqual([
      5,
      'access.denied',
      'POST:/api/admin/candidates/3/exclusion',
      'failure',
      'role_not_permitted',
    ]);
  });

  test('still returns 403 if the audit log write fails', async () => {
    db.query.mockRejectedValue(new Error('db down'));
    const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const res = makeRes();
    const next = jest.fn();

    await requireRole('admin')(makeReq({ id: 5, role: 'voter' }), res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
    errorSpy.mockRestore();
  });

  test('replaces unsafe characters in the audit target', async () => {
    const res = makeRes();
    const req = makeReq({ id: 5, role: 'voter' });
    req.path = '/x y;<script>';

    await requireRole('admin')(req, res, jest.fn());

    const target = db.query.mock.calls[0][1][2];
    expect(target).toMatch(/^[A-Za-z0-9_.:/-]{1,200}$/);
  });
});