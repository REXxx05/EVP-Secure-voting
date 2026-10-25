// Unit tests for SR-01 password hashing helpers.

const { hashPassword, verifyPassword } = require('../../src/security/password');

describe('password hashing (SR-01)', () => {

  // Confirms we never store the password itself, only a hash of it.
  it('hashes a password to something different from the original', async () => {
    const hash = await hashPassword('Correct-Horse-Battery-1');
    expect(hash).not.toBe('Correct-Horse-Battery-1');
    expect(typeof hash).toBe('string');
  });

  // bcrypt uses a random salt each time, so even identical passwords
  // should never produce identical hashes in the database.
  it('produces a different hash each time for the same password', async () => {
    const hash1 = await hashPassword('same-password');
    const hash2 = await hashPassword('same-password');
    expect(hash1).not.toBe(hash2);
  });

  // The actual login scenario: right password against its own hash.
  it('verifies a correct password against its hash', async () => {
    const hash = await hashPassword('my-real-password');
    const ok = await verifyPassword('my-real-password', hash);
    expect(ok).toBe(true);
  });

  // A wrong guess must be rejected, not accidentally accepted.
  it('rejects an incorrect password', async () => {
    const hash = await hashPassword('my-real-password');
    const ok = await verifyPassword('guessed-password', hash);
    expect(ok).toBe(false);
  });

  // Edge case: an empty submission shouldn't crash the login route.
  it('rejects an empty password instead of throwing', async () => {
    const hash = await hashPassword('my-real-password');
    const ok = await verifyPassword('', hash);
    expect(ok).toBe(false);
  });

});