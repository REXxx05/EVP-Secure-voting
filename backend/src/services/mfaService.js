// SR-02: Multi-factor authentication (MFA) for admins.
// Admins need their password AND a 6 digit code from an authenticator app
// (like Google Authenticator). The code changes every 30 seconds (this is called TOTP).
//
// How it works:
//   1. startMfaSetup: makes a secret, saves it ENCRYPTED, and makes a QR code
//   2. the admin scans the QR code with their authenticator app
//   3. verifyMfaCode: checks the 6 digit code they type in.
//      The first time it works, MFA gets turned on for their account.

const { authenticator } = require('otplib');
const QRCode = require('qrcode');
const db = require('../config/db');
const { encrypt, decrypt } = require('../security/encryption');

// accept the code from one 30 second step before or after,
// in case the phone's clock is a little bit off
authenticator.options = { window: 1 };

// Step 1 of setting up MFA for an admin
async function startMfaSetup(userId, username) {
  // check they don't already have MFA turned on.
  // If we allowed setting it up again, someone who stole an admin's password
  // could just set up MFA on their own phone and get in.
  const existing = await db.query('SELECT mfa_enabled FROM users WHERE id = $1', [userId]);

  if (existing.rowCount === 0) {
    throw new Error('User not found');
  }
  if (existing.rows[0].mfa_enabled) {
    throw new Error('MFA is already set up');
  }

  // make a new random secret for this admin
  const secret = authenticator.generateSecret();

  // save it ENCRYPTED (SR-09), never as plain text.
  // MFA stays off until they prove it works by entering a code.
  await db.query(
    'UPDATE users SET mfa_secret_enc = $1 WHERE id = $2',
    [encrypt(secret), userId]
  );

  // this link is what the authenticator app reads from the QR code
  const setupLink = authenticator.keyuri(username, 'EVP Secure Voting', secret);

  // turn the link into a QR code image the browser can show
  const qrCode = await QRCode.toDataURL(setupLink);

  return { qrCode: qrCode };
}

// Checks the 6 digit code an admin typed in
async function verifyMfaCode(userId, code) {
  // the code must be exactly 6 numbers, anything else is rejected straight away
  if (typeof code !== 'string' || !/^[0-9]{6}$/.test(code)) {
    return false;
  }

  const result = await db.query(
    'SELECT mfa_secret_enc, mfa_enabled FROM users WHERE id = $1',
    [userId]
  );

  // no user, or they haven't started MFA setup yet
  if (result.rowCount === 0 || !result.rows[0].mfa_secret_enc) {
    return false;
  }

  // decrypt their secret and check the code against it
  const secret = decrypt(result.rows[0].mfa_secret_enc);
  const isValid = authenticator.check(code, secret);

  // first correct code = MFA is now turned on for this admin
  if (isValid && !result.rows[0].mfa_enabled) {
    await db.query('UPDATE users SET mfa_enabled = TRUE WHERE id = $1', [userId]);
  }

  return isValid;
}

module.exports = { startMfaSetup, verifyMfaCode };