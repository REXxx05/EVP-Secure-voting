// Unit tests for the SR-02 middleware.
// We just fake req.user like requireAuth would set it.

const requireMfa = require('../../src/middleware/requireMfa');

// makes a fake "res" object so we can check what status got sent
function makeFakeRes() {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  return res;
}

describe('SR-02 requireMfa middleware', () => {

  test('admin with only a password (no MFA yet) is blocked', () => {
    const req = { user: { id: 1, role: 'admin', mfaVerified: false } };
    const res = makeFakeRes();
    const next = jest.fn();

    requireMfa(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('admin who has done MFA is let through', () => {
    const req = { user: { id: 1, role: 'admin', mfaVerified: true } };
    const res = makeFakeRes();
    const next = jest.fn();

    requireMfa(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  test('commissioner without MFA is also blocked', () => {
    const req = { user: { id: 2, role: 'commissioner', mfaVerified: false } };
    const res = makeFakeRes();
    const next = jest.fn();

    requireMfa(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('voters do not need MFA', () => {
    const req = { user: { id: 3, role: 'voter', mfaVerified: false } };
    const res = makeFakeRes();
    const next = jest.fn();

    requireMfa(req, res, next);

    expect(next).toHaveBeenCalled();
  });

  test('not logged in gets 401', () => {
    const req = {};
    const res = makeFakeRes();
    const next = jest.fn();

    requireMfa(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

});