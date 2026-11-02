
/**
 * SR-03 / SR-02 / SR-18:
 * Protected administrator candidate-management routes.
 */

const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const requireMfa = require('../middleware/requireMfa');
const requireRole = require('../middleware/requireRole');

const {
  setCandidateExclusion,
  setCandidateOrder
} = require('../services/adminActions');

const router = express.Router();

const adminProtection = [
  requireAuth,
  requireMfa,
  requireRole('admin')
];

function validId(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function handleActionError(error, res, next) {
  if (
    error.message === 'Missing or mismatched administrator signature' ||
    error.message === 'Invalid administrator digital signature' ||
    error.message === 'Administrator signing key is not registered'
  ) {
    return res.status(403).json({
      error: 'Valid administrator digital signature required'
    });
  }

  return next(error);
}

/**
 * POST /api/admin/candidates/:id/exclusion
 *
 * Body:
 * {
 *   "excluded": true,
 *   "signedAction": {
 *     "adminId": 3,
 *     "candidateId": 1,
 *     "actionType": "candidate.exclude",
 *     "newValue": "true",
 *     "signedAt": "...",
 *     "keyId": "...",
 *     "signature": "..."
 *   }
 * }
 */
router.post(
  '/candidates/:id/exclusion',
  ...adminProtection,
  async (req, res, next) => {
    const candidateId = Number(req.params.id);
    const excluded = req.body?.excluded;

    if (
      !validId(candidateId) ||
      typeof excluded !== 'boolean'
    ) {
      return res.status(400).json({
        error: 'A valid candidate id and boolean excluded flag are required'
      });
    }

    try {
      await setCandidateExclusion({
        actorId: req.user.id,
        candidateId,
        excluded,
        signedAction: req.body?.signedAction
      });

      return res.json({ candidateId, excluded });
    } catch (error) {
      return handleActionError(error, res, next);
    }
  }
);

/**
 * POST /api/admin/candidates/:id/order
 *
 * Body:
 * {
 *   "ballotOrder": 2,
 *   "signedAction": {
 *     "adminId": 3,
 *     "candidateId": 1,
 *     "actionType": "candidate.order",
 *     "newValue": "2",
 *     "signedAt": "...",
 *     "keyId": "...",
 *     "signature": "..."
 *   }
 * }
 */
router.post(
  '/candidates/:id/order',
  ...adminProtection,
  async (req, res, next) => {
    const candidateId = Number(req.params.id);
    const ballotOrder = req.body?.ballotOrder;

    if (
      !validId(candidateId) ||
      !validId(ballotOrder)
    ) {
      return res.status(400).json({
        error: 'A valid candidate id and positive ballot order are required'
      });
    }

    try {
      await setCandidateOrder({
        actorId: req.user.id,
        candidateId,
        ballotOrder,
        signedAction: req.body?.signedAction
      });

      return res.json({ candidateId, ballotOrder });
    } catch (error) {
      return handleActionError(error, res, next);
    }
  }
);

module.exports = router;
