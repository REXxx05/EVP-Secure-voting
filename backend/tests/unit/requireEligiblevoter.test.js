// Unit tests for the SR-05 middleware.
// We fake req.user (normally set by Dhanush's login, SR-04)
// and we fake checkEligibility, so we're only testing the middleware itself.

// tell jest to replace the real eligibility check with a fake one
jest.mock('../../src/services/eligibilityService');
const { checkEligibility } = require('../../src/services/eligibilityService');
const requireEligibleVoter = require('../../src/middleware/requireEligiblevoter');

// makes a fake "res" object so we can check what status and message got sent
function makeFakeRes() {
  const res = {};
  res.status = jest.fn(() => res);
  res.json = jest.fn(() => res);
  return res;
}

// hide the console.warn messages so the test output stays clean
beforeAll(() => {
  jest.spyOn(console, 'warn').mockImplementation(() => {});
});

describe('SR-05 requireEligibleVoter middleware', () => {

  test('eligible voter goes through and gets their division', async () => {
    checkEligibility.mockResolvedValue({ eligible: true, electionId: 1, divisionId: 2 });

    const req = { user: { id: 5, role: 'voter' }, params: { electionId: '1' } };
    const res = makeFakeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    expect(next).toHaveBeenCalled();
    expect(req.eligibility).toEqual({ electionId: 1, divisionId: 2 });
  });

  test('not logged in gets 401', async () => {
    const req = { params: { electionId: '1' } };   // no req.user
    const res = makeFakeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    expect(res.status).toHaveBeenCalledWith(401);
    expect(next).not.toHaveBeenCalled();
  });

  test('voter not enrolled gets 403 with a clear message', async () => {
    checkEligibility.mockResolvedValue({ eligible: false, reason: 'not_enrolled' });

    const req = { user: { id: 5, role: 'voter' }, params: { electionId: '1' } };
    const res = makeFakeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith({ error: 'You are not enrolled to vote in this election.' });
    expect(next).not.toHaveBeenCalled();
  });

  test('closed election gets 403', async () => {
    checkEligibility.mockResolvedValue({ eligible: false, reason: 'election_not_open' });

    const req = { user: { id: 5, role: 'voter' }, params: { electionId: '1' } };
    const res = makeFakeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(next).not.toHaveBeenCalled();
  });

  test('division sent by the browser is ignored', async () => {
    checkEligibility.mockResolvedValue({ eligible: true, electionId: 1, divisionId: 2 });

    // someone trying to sneak in a different division
    const req = {
      user: { id: 5, role: 'voter' },
      params: { electionId: '1' },
      body: { divisionId: 3 }
    };
    const res = makeFakeRes();
    const next = jest.fn();

    await requireEligibleVoter(req, res, next);

    // division should come from their enrolment (2), not the browser (3)
    expect(req.eligibility.divisionId).toBe(2);
  });

});