// SR-02: routes for admin MFA.
//   GET  /api/mfa/status  - is MFA set up, and has this session passed it?
//   POST /api/mfa/setup   - first time only: get a QR code to scan
//   POST /api/mfa/verify  - type in the 6 digit code
// All of these need the user to be logged in with their password first (requireAuth).

const express = require('express');
const db = require('../config/db');
const requireAuth = require('../middleware/requireAuth');
const { loginIpLimiter } = require('../middleware/rateLimiters');
const sessionModel = require('../models/sessionModel');
const { startMfaSetup, verifyMfaCode } = require('../services/mfaService');

const router = express.Router();

// MFA is only for staff (admins etc.), voters don't use it
function staffOnly(req, res, next) {
  if (req.user.role === 'voter') {
    return res.status(403).json({ error: 'MFA is only for staff accounts.' });
  }
  next();
}

// tells the frontend whether to show the "scan QR code" screen or the "enter code" screen
router.get('/status', requireAuth, staffOnly, async (req, res, next) => {
  try {
    const result = await db.query('SELECT mfa_enabled FROM users WHERE id = $1', [req.user.id]);
    res.json({
      mfaEnabled: result.rows[0].mfa_enabled,
      mfaVerified: req.user.mfaVerified
    });
  } catch (err) {
    next(err);
  }
});

// first time setup: gives back a QR code for the authenticator app
router.post('/setup', requireAuth, staffOnly, async (req, res, next) => {
  try {
    const result = await db.query('SELECT username FROM users WHERE id = $1', [req.user.id]);
    const setup = await startMfaSetup(req.user.id, result.rows[0].username);
    res.json({ qrCode: setup.qrCode });
  } catch (err) {
    // already set up = not allowed to set it up again
    if (err.message === 'MFA is already set up') {
      return res.status(409).json({ error: 'MFA is already set up for this account.' });
    }
    next(err);
  }
});

// checks the 6 digit code.
// loginIpLimiter (SR-19) stops someone from guessing codes over and over.
router.post('/verify', loginIpLimiter, requireAuth, staffOnly, async (req, res, next) => {
  try {
    const isValid = await verifyMfaCode(req.user.id, req.body.code);

    if (!isValid) {
      return res.status(401).json({ error: 'That code is not right. Please try again.' });
    }

    // code was right, so this session now has full access
    await sessionModel.markMfaVerified(req.session.id);
    res.json({ mfaVerified: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;