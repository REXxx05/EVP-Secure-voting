// SR-01: Voter/admin login.

const express = require('express');
const userModel = require('../models/userModel');
const sessionModel = require('../models/sessionModel');
const { verifyPassword } = require('../security/password');

const router = express.Router();

// POST /api/auth/login
// Body: { username, password }
router.post('/login', async (req, res, next) => {
  try {
    const { username, password } = req.body || {};

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const user = await userModel.findByUsername(username);

    // Same error message whether the username doesn't exist or the
    // password is wrong, so an attacker can't use this endpoint to find out which usernames are real.
    const invalidCredentials = () =>
      res.status(401).json({ error: 'Invalid username or password' });

    if (!user) {
      return invalidCredentials();
    }

    const passwordOk = await verifyPassword(password, user.password_hash);
    if (!passwordOk) {
      return invalidCredentials();
    }

    // SR-04: issue a fresh session token - this is what the client
    // sends back on every later request to prove it's still logged in.
    const sessionToken = await sessionModel.createSession(user.id);

    res.json({ userId: user.id, role: user.role, sessionToken });
  } catch (err) {
    next(err);
  }
});

module.exports = router;