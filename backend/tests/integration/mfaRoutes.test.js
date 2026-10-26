// End-to-end tests for SR-02 through the real API routes.
// Shows that an admin with only a password is blocked, and that the
// right MFA code unlocks access.

const express = require('express');
const request = require('supertest');
const { authenticator } = require('otplib');
const app = require('../../src/app');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const sessionModel = require('../../src/models/sessionModel');
const requireAuth = require('../../src/middleware/requireAuth');
const requireMfa = require('../../src/middleware/requireMfa');
const { decrypt } = require('../../src/security/encryption');

let adminId, voterId, adminToken, voterToken;

// a pretend admin page, protected the way real admin routes should be
const adminApp = express();
adminApp.get('/admin-only', requireAuth, requireMfa, (req, res) => {
  res.json({ ok: true });
});

// adds a fake user straight into the database
async function addUser(name, role) {
  const result = await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'not-a-real-hash', $2) RETURNING id",
    [name + '_' + Date.now(), role]
  );
  return result.rows[0].id;
}

beforeAll(async () => {
  adminId = await addUser('mfa_route_admin', 'admin');
  voterId = await addUser('mfa_route_voter', 'voter');

  // pretend they've both logged in with their password (SR-04 makes these sessions)
  adminToken = await sessionModel.createSession(adminId);
  voterToken = await sessionModel.createSession(voterId);
});

afterAll(async () => {
  await adminDb.query('DELETE FROM sessions WHERE user_id IN ($1, $2)', [adminId, voterId]);
  await adminDb.query('DELETE FROM users WHERE id IN ($1, $2)', [adminId, voterId]);
  await adminDb.end();
  await db.pool.end();
});

describe('SR-02 MFA through the API', () => {

  test('admin with only a password cannot get into admin pages', async () => {
    const res = await request(adminApp).get('/admin-only').set('x-session-token', adminToken);
    expect(res.status).toBe(403);
    expect(res.body.mfaRequired).toBe(true);
  });

  test('admin can start MFA setup and gets a QR code', async () => {
    const res = await request(app).post('/api/mfa/setup').set('x-session-token', adminToken);
    expect(res.status).toBe(200);
    expect(res.body.qrCode).toMatch(/^data:image\/png;base64,/);
  });

  test('wrong code is rejected', async () => {
    const res = await request(app)
      .post('/api/mfa/verify')
      .set('x-session-token', adminToken)
      .send({ code: '000000' });
    expect(res.status).toBe(401);
  });

  test('right code unlocks admin pages for this session', async () => {
    // get the secret from the database to make a real code (only the admin's phone would have this normally)
    const result = await adminDb.query('SELECT mfa_secret_enc FROM users WHERE id = $1', [adminId]);
    const code = authenticator.generate(decrypt(result.rows[0].mfa_secret_enc));

    const verify = await request(app)
      .post('/api/mfa/verify')
      .set('x-session-token', adminToken)
      .send({ code: code });
    expect(verify.status).toBe(200);

    const res = await request(adminApp).get('/admin-only').set('x-session-token', adminToken);
    expect(res.status).toBe(200);
  });

  test('cannot set up MFA again once it is on', async () => {
    const res = await request(app).post('/api/mfa/setup').set('x-session-token', adminToken);
    expect(res.status).toBe(409);
  });

  test('voters cannot use the MFA routes', async () => {
    const res = await request(app).post('/api/mfa/setup').set('x-session-token', voterToken);
    expect(res.status).toBe(403);
  });

  test('not logged in cannot use the MFA routes', async () => {
    const res = await request(app).post('/api/mfa/setup');
    expect(res.status).toBe(401);
  });

});