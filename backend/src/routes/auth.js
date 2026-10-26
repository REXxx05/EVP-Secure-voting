// SR-01: Voter/admin login.
// SR-04: Session issuance and logout.

const express = require('express');
const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const { verifyPassword } = require('../security/password');
const requireAuth = require('../middleware/requireAuth');
const { loginIpLimiter, loginAccountLimiter } = require('../middleware/rateLimiters');


const router = express.Router();

// POST /api/auth/login
// Body: { username, password }
router.post('/login', loginIpLimiter, loginAccountLimiter, async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await userModel.findByUsername(username);

    // Same error message whether the username doesn't exist or the
    // password is wrong, so an attacker can't use this endpoint to
    // find out which usernames are real.
    const invalidCredentials = () =>
      res.status(401).json({ error: 'Invalid username or password' });

    if (!user) {
      return invalidCredentials();
    }

    // Account locked from too many recent failed attempts (SR-01):
    // reject even a correct password until the lockout expires.
    if (userModel.isLocked(user)) {
      return res.status(401).json({
        error: `Account locked. Try again in ${userModel.LOCKOUT_MINUTES} minutes.`
      });
    }

    const passwordOk = await verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      await userModel.recordFailedLogin(user.id);
      return invalidCredentials();
    }

    await userModel.clearFailedLogins(user.id);

    // SR-04: issue a fresh session token - this is what the client
    // sends back on every later request to prove it's still logged in.
    const sessionToken = await sessionModel.createSession(user.id);

    // SR-02: anyone who isn't a voter (admins etc.) must do MFA next,
    // so we tell the frontend to show the 6 digit code screen
    res.json({
      userId: user.id,
      role: user.role,
      sessionToken,
      mfaRequired: user.role !== 'voter'
    });
  } catch (err) {
    next(err);
  }
});

// POST /api/auth/logout
// SR-04: invalidates the session immediately rather than waiting for
// it to expire, so a submitted ballot's token can't be reused.
router.post('/logout', async (req, res, next) => {
  try {
    const sessionToken = req.headers['x-session-token'];
    if (!sessionToken) {
      return res.status(400).json({ error: 'Missing session token' });
    }

    const session = await sessionModel.findValidSession(sessionToken);
    if (session) {
      await sessionModel.invalidateSession(session.id);
    }

    // Logging out an already-invalid token isn't an error - the end
    // result (no valid session) is the same either way.
    res.json({ loggedOut: true });
  } catch (err) {
    next(err);
  }
});

// GET /api/auth/me
// SR-04: a protected route. Only a valid, non-expired session gets through.
router.get('/me', requireAuth, (req, res) => {
  res.json({ userId: req.session.user_id });
});

module.exports = router;