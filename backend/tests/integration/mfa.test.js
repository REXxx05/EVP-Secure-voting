// Tests for SR-02 (admin MFA).
// Needs the Docker database running.

const { authenticator } = require('otplib');
const db = require('../../src/config/db');
const adminDb = require('../helpers/adminDb');
const { decrypt } = require('../../src/security/encryption');
const { startMfaSetup, verifyMfaCode } = require('../../src/services/mfaService');

let adminId;

// gets the admin's real secret out of the database so the test can make codes
// (in real life only the admin's phone would know this)
async function getSecret() {
  const result = await adminDb.query('SELECT mfa_secret_enc FROM users WHERE id = $1', [adminId]);
  return decrypt(result.rows[0].mfa_secret_enc);
}

// make a fake admin before the tests
beforeAll(async () => {
  const result = await adminDb.query(
    "INSERT INTO users (username, password_hash, role) VALUES ($1, 'not-a-real-hash', 'admin') RETURNING id",
    ['mfa_test_admin_' + Date.now()]
  );
  adminId = result.rows[0].id;
});

// delete the fake admin and close connections after
afterAll(async () => {
  await adminDb.query('DELETE FROM users WHERE id = $1', [adminId]);
  await adminDb.end();
  await db.pool.end();
});

// these tests run in order, one after the other
describe('SR-02 admin MFA', () => {

  test('setup gives back a QR code image', async () => {
    const setup = await startMfaSetup(adminId, 'test_admin');
    expect(setup.qrCode).toMatch(/^data:image\/png;base64,/);
  });

  test('MFA secret is stored encrypted, not as plain text', async () => {
    const result = await adminDb.query('SELECT mfa_secret_enc FROM users WHERE id = $1', [adminId]);
    const stored = result.rows[0].mfa_secret_enc;
    const realSecret = await getSecret();

    expect(stored).not.toContain(realSecret);
  });

  test('MFA is not turned on until a code is checked', async () => {
    const result = await adminDb.query('SELECT mfa_enabled FROM users WHERE id = $1', [adminId]);
    expect(result.rows[0].mfa_enabled).toBe(false);
  });

  test('wrong code is rejected', async () => {
    const realCode = authenticator.generate(await getSecret());
    // pick a code that's definitely different from the real one
    const wrongCode = realCode === '000000' ? '111111' : '000000';
    expect(await verifyMfaCode(adminId, wrongCode)).toBe(false);
  });

  test('expired code (from 5 minutes ago) is rejected', async () => {
    const secret = await getSecret();
    // make a code as if it was 5 minutes ago
    const oldCode = authenticator.clone({ epoch: Date.now() - 5 * 60 * 1000 }).generate(secret);
    expect(await verifyMfaCode(adminId, oldCode)).toBe(false);
  });

  test('anything that is not 6 numbers is rejected', async () => {
    expect(await verifyMfaCode(adminId, 'abcdef')).toBe(false);
    expect(await verifyMfaCode(adminId, '12345')).toBe(false);
    expect(await verifyMfaCode(adminId, "1' OR '1'='1")).toBe(false);
  });

  test('correct code is accepted and turns MFA on', async () => {
    const code = authenticator.generate(await getSecret());
    expect(await verifyMfaCode(adminId, code)).toBe(true);

    const result = await adminDb.query('SELECT mfa_enabled FROM users WHERE id = $1', [adminId]);
    expect(result.rows[0].mfa_enabled).toBe(true);
  });

  test('cannot set up MFA again once it is on (stops someone with a stolen password re-enrolling)', async () => {
    await expect(startMfaSetup(adminId, 'test_admin')).rejects.toThrow('MFA is already set up');
  });

});