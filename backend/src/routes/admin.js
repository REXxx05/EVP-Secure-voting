// SR-03: admin-only routes. requireAuth proves who you are,
// requireRole('admin') proves you are allowed to do this.

const express = require('express');
const requireAuth = require('../middleware/requireAuth');
const requireRole = require('../middleware/requireRole');
const { setCandidateExclusion } = require('../services/adminActions');
const requireMfa = require('../middleware/requireMfa');   // SR-02

const router = express.Router();

// POST /api/admin/candidates/:id/exclusion   body: { "excluded": true|false }
router.post(
  '/candidates/:id/exclusion',
  requireAuth,
  requireMfa,          // SR-02: staff must pass MFA before any admin action
  requireRole('admin'),
  async (req, res, next) => {
    try {
      const candidateId = Number(req.params.id);
      const excluded = req.body ? req.body.excluded : undefined;

      if (!Number.isInteger(candidateId) || candidateId < 1 || typeof excluded !== 'boolean') {
        return res.status(400).json({ error: 'A valid candidate id and boolean excluded flag are required' });
      }

      await setCandidateExclusion({
        actorId: req.user.id,
        candidateId,
        excluded,
      });

      return res.json({ candidateId, excluded });
    } catch (err) {
      return next(err);
    }
  }
);

module.exports = router;