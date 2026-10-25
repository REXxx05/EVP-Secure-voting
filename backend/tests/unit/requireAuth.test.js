// The session model is replaced with fakes, so no database is needed here.
jest.mock('../../src/models/sessionModel', () => ({
  findValidSession: jest.fn(),
  touchSession: jest.fn()
}));

const sessionModel = require('../../src/models/sessionModel');
const requireAuth = require('../../src/middleware/requireAuth');

function mockRes() {
  const res = {};
  res.status = jest.fn().mockReturnValue(res);
  res.json = jest.fn().mockReturnValue(res);
  return res;
}

describe('requireAuth middleware', () => {
  beforeEach(() => jest.resetAllMocks());

  it('rejects a request with no session token', async () => {
    const req = { headers: {} };
    const res = mockRes();
    const next = jest.fn();

    await requireAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('rejects an invalid, expired or logged-out token', async () => {
    sessionModel.findValidSession.mockResolvedValue(undefined);
    const req = { headers: { 'x-session-token': 'bad-token' } };
    const res = mockRes();
    const next = jest.fn();

    await requireAuth(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  it('lets a valid session through and extends its timeout', async () => {
    sessionModel.findValidSession.mockResolvedValue({ id: 7, user_id: 3, role: 'voter' });
    const req = { headers: { 'x-session-token': 'good-token' } };
    const res = mockRes();
    const next = jest.fn();

    await requireAuth(req, res, next);

    expect(sessionModel.touchSession).toHaveBeenCalledWith(7);
    expect(req.session).toEqual({ id: 7, user_id: 3, role: 'voter' });
    expect(req.user).toEqual({ id: 3, role: 'voter' });
    expect(next).toHaveBeenCalled();
  });
});