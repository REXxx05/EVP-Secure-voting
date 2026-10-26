// SR-04: Checks the session token on every protected request.
// The server decides whether a session is valid - never the browser.
const sessionModel = require('../models/sessionModel');

async function requireAuth(req, res, next) {
  try {
    const token = req.headers['x-session-token'];
    if (!token) {
      return res.status(401).json({ error: 'Not logged in' });
    }

    // Returns nothing if the token is unknown, expired or already logged out
    const session = await sessionModel.findValidSession(token);
    if (!session) {
      return res.status(401).json({ error: 'Session invalid or expired' });
    }

    // Active users stay logged in: push the 30-minute idle timeout forward
    await sessionModel.touchSession(session.id);

    req.session = session; // later code can read who is logged in

    // the logged in user, in the shape the team agreed on (SR-05 and SR-06 use this).
    // mfaVerified is for SR-02: admins can't use admin stuff until it's true.
    req.user = {
      id: session.user_id,
      role: session.role,
      mfaVerified: session.mfa_verified
    };

    next();
  } catch (err) {
    next(err);
  }
}

module.exports = requireAuth;