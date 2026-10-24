// Unit tests for SR-09 (AES-256-GCM encryption at rest)

const { encrypt, decrypt } = require('../../src/security/encryption');

// Small helper: flips one byte inside one part of an encrypted string,
// to pretend someone tampered with it in the database
function tamper(encrypted, partIndex) {
  const parts = encrypted.split(':');
  const buf = Buffer.from(parts[partIndex], 'base64');
  buf[0] = buf[0] ^ 0xff;   // flip all the bits in the first byte
  parts[partIndex] = buf.toString('base64');
  return parts.join(':');
}

describe('SR-09 encryption at rest', () => {

  it('decrypts back to the original text', () => {
    const original = '12 Swanston St, Melbourne VIC 3000';
    const encrypted = encrypt(original);
    expect(decrypt(encrypted)).toBe(original);
  });

  it('does not store the plain text inside the encrypted value', () => {
    const encrypted = encrypt('Alex Turner');
    expect(encrypted).not.toContain('Alex Turner');
  });

  it('gives a different result each time for the same text (random IV)', () => {
    const a = encrypt('same text');
    const b = encrypt('same text');
    expect(a).not.toBe(b);
  });

  it('stores the key version at the start for key rotation', () => {
    const encrypted = encrypt('hello');
    expect(encrypted.split(':')[0]).toBe('1');
  });

  it('rejects data that has been changed', () => {
    const encrypted = encrypt('ballot data');
    expect(() => decrypt(tamper(encrypted, 3))).toThrow();
  });

  it('rejects a changed auth tag', () => {
    const encrypted = encrypt('ballot data');
    expect(() => decrypt(tamper(encrypted, 2))).toThrow();
  });

  it('rejects values in the wrong format', () => {
    expect(() => decrypt('not-encrypted-at-all')).toThrow('Invalid encrypted value');
  });

  it('returns null for empty values instead of crashing', () => {
    expect(encrypt(null)).toBeNull();
    expect(decrypt(null)).toBeNull();
  });

  it('refuses to encrypt if the key is missing (fails securely)', () => {
    const savedKey = process.env.DATA_ENCRYPTION_KEY;
    delete process.env.DATA_ENCRYPTION_KEY;

    expect(() => encrypt('secret')).toThrow('missing');

    // put the key back so the other tests still work
    process.env.DATA_ENCRYPTION_KEY = savedKey;
  });

});

// ---- Key rotation tests (SR-09: keys rotated every 90 days) ----
const crypto = require('crypto');
const { reencrypt } = require('../../src/security/encryption');

describe('SR-09 key rotation', () => {

  // Remove the test key settings after each test so other tests aren't affected
  afterEach(() => {
    delete process.env.DATA_ENCRYPTION_KEY_V2;
    delete process.env.DATA_ENCRYPTION_KEY_VERSION;
  });

  it('re-encrypts old data with the new key and it still decrypts', () => {
    const oldValue = encrypt('12 Swanston St');        // made with key 1

    // pretend we've rotated to a new key 2
    process.env.DATA_ENCRYPTION_KEY_V2 = crypto.randomBytes(32).toString('base64');
    process.env.DATA_ENCRYPTION_KEY_VERSION = '2';

    const newValue = reencrypt(oldValue);

    expect(newValue.split(':')[0]).toBe('2');           // now uses key 2
    expect(decrypt(newValue)).toBe('12 Swanston St');   // same original text
  });

  it('can still read old data during rotation', () => {
    const oldValue = encrypt('old data');               // key 1
    process.env.DATA_ENCRYPTION_KEY_V2 = crypto.randomBytes(32).toString('base64');
    process.env.DATA_ENCRYPTION_KEY_VERSION = '2';

    expect(decrypt(oldValue)).toBe('old data');         // key 1 still works
  });

});