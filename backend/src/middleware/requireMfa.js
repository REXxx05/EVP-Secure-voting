// SR-02: blocks staff (admins etc.) from using anything until they've
// entered their 6 digit MFA code in this session.
// This is what makes "password only" admin access impossible.
//
// It goes AFTER requireAuth (which sets req.user) on admin routes, e.g.
//   router.post('/candidates', requireAuth, requireMfa, requireRole('admin'), ...)
// Checking WHICH role is allowed is SR-03 (Dhanush), this only checks MFA.

function requireMfa(req, res, next) {
  // not logged in at all
  if (!req.user) {
    return res.status(401).json({ error: 'Please log in first.' });
  }

  // voters don't use MFA, so let them through
  if (req.user.role === 'voter') {
    return next();
  }

  // staff who haven't done their MFA code yet get stopped here
  if (!req.user.mfaVerified) {
    return res.status(403).json({
      error: 'Please enter your MFA code first.',
      mfaRequired: true
    });
  }

  // password AND MFA done, good to go
  next();
}

module.exports = requireMfa;