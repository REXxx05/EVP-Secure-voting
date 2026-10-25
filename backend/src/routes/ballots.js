// AI-generated SR-06 integration factory. Deliberately unmounted until real
// SR-01/04 authentication, CSRF, SR-07 validation and session finalization exist.
const express = require('express');
const { createBallotSubmission, SubmissionError } = require('../services/ballotSubmission');

const publicErrors = {
  INVALID_INPUT: [400, 'Invalid submission.'],
  INVALID_BALLOT: [422, 'Both ballots must satisfy voting rules.'],
  INVALID_SESSION: [401, 'Please log in again.'],
  INELIGIBLE: [403, 'You are not eligible for this election.'],
  ALREADY_VOTED: [409, 'A submission has already been accepted for this election.'],
  COMMIT_OUTCOME_UNKNOWN: [503, 'Acceptance could not be confirmed. Check participation before retrying.']
};

function createBallotsRouter({ authenticateVoter, verifyCsrf, validateBallots,
  invalidateSession, pool, checkEligibility, saveBallotAnonymously, recordBallotHash, issueReceipt } = {}) {
  for (const [name, value] of Object.entries({ authenticateVoter, verifyCsrf, validateBallots, invalidateSession })) {
    if (typeof value !== 'function') throw new TypeError(`${name} must be explicitly configured`);
  }
  const submit = createBallotSubmission({ pool, checkEligibility, saveBallotAnonymously, recordBallotHash, issueReceipt,
    validateBallots, finalizeSession: invalidateSession });
  const router = express.Router();
  router.post('/api/elections/:electionId/ballots', authenticateVoter, verifyCsrf, async (req, res) => {
    res.set('Cache-Control', 'no-store');
    if (!req.user || !Number.isSafeInteger(req.user.id) || req.user.id < 1 ||
        !req.session || !Number.isSafeInteger(req.session.id) || req.session.id < 1) {
      return res.status(401).json({ error: 'Please log in first.' });
    }
    if (req.user.role !== 'voter') return res.status(403).json({ error: 'Only voters may submit ballots.' });
    const electionId = Number(req.params.electionId);
    if (!/^[1-9]\d*$/.test(req.params.electionId) || !Number.isSafeInteger(electionId) ||
        !req.body || typeof req.body !== 'object' || Array.isArray(req.body) ||
        Object.keys(req.body).some(key => !['house', 'senate'].includes(key))) {
      return res.status(400).json({ error: 'Invalid submission.' });
    }
    try {
      const result = await submit({ voterId: req.user.id, sessionId: req.session.id,
        electionId, house: req.body.house, senate: req.body.senate });
      return res.status(201).json(result);
    } catch (error) {
      const mapped = error instanceof SubmissionError && publicErrors[error.code];
      if (mapped) return res.status(mapped[0]).json({ error: mapped[1], code: error.code });
      // Never forward SQL detail, raw identity, ballot content, or error causes to
      // the generic application's console logger or response serializer.
      return res.status(500).json({ error: 'Submission failed.' });
    }
  });
  return router;
}

module.exports = { createBallotsRouter };
