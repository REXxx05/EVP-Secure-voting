// SR-09: Encryption at rest.
// Encrypts sensitive data (voter details, ballots, MFA secrets) before it's
// saved in the database, and decrypts it when the app needs to read it.
//
// We use AES-256-GCM:
//  - AES-256 = strong encryption with a 256-bit (32 byte) key
//  - GCM = also adds an "auth tag", so if anyone changes the encrypted
//    data in the database, decrypting it fails instead of giving wrong data

const crypto = require('crypto');
const path = require('path');

// Load the key from .env. The key is NEVER stored in the code or the database.
require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12;   // 12 random bytes is the recommended IV size for GCM
const TAG_LENGTH = 16;  // GCM auth tag is 16 bytes

// Which key we use for NEW data.
// For key rotation (every 90 days), we add DATA_ENCRYPTION_KEY_V2 to .env
// and change this to 2. Old data still decrypts with key 1 because
// every encrypted value remembers which key version it used.
const CURRENT_KEY_VERSION = 1;

// Gets the key for a version from .env and checks it's the right size
function getKey(version) {
  // version 1 is DATA_ENCRYPTION_KEY, later ones are DATA_ENCRYPTION_KEY_V2, _V3...
  const envName = version === 1 ? 'DATA_ENCRYPTION_KEY' : `DATA_ENCRYPTION_KEY_V${version}`;
  const keyBase64 = process.env[envName];

  // Fail securely: if the key is missing or wrong, stop instead of
  // saving data unencrypted
  if (!keyBase64) {
    throw new Error(`Encryption key ${envName} is missing`);
  }

  const key = Buffer.from(keyBase64, 'base64');
  if (key.length !== 32) {
    throw new Error(`Encryption key ${envName} must be 32 bytes`);
  }

  return key;
}

// Encrypts a piece of text.
// Returns one string in the format  version:iv:tag:ciphertext
// so we can store it in a single TEXT column.
function encrypt(plainText) {
  // Nothing to encrypt (e.g. an empty optional field)
  if (plainText === null || plainText === undefined) {
    return null;
  }

  const key = getKey(CURRENT_KEY_VERSION);

  // A new random IV every time, so encrypting the same text twice
  // gives different results (stops people spotting matching values)
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plainText), 'utf8'),
    cipher.final()
  ]);
  const tag = cipher.getAuthTag();

  return [
    CURRENT_KEY_VERSION,
    iv.toString('base64'),
    tag.toString('base64'),
    encrypted.toString('base64')
  ].join(':');
}

// Decrypts a string made by encrypt() back into the original text.
// Throws an error if the data was changed (tampered) or is in the wrong format.
function decrypt(encryptedText) {
  if (encryptedText === null || encryptedText === undefined) {
    return null;
  }

  const parts = String(encryptedText).split(':');
  if (parts.length !== 4) {
    throw new Error('Invalid encrypted value');
  }

  const [versionStr, ivB64, tagB64, dataB64] = parts;
  const version = Number(versionStr);
  if (!Number.isInteger(version) || version < 1) {
    throw new Error('Invalid key version');
  }

  const key = getKey(version);
  const iv = Buffer.from(ivB64, 'base64');
  const tag = Buffer.from(tagB64, 'base64');
  const data = Buffer.from(dataB64, 'base64');

  // Check the sizes so nobody can sneak in a shortened auth tag
  if (iv.length !== IV_LENGTH || tag.length !== TAG_LENGTH) {
    throw new Error('Invalid encrypted value');
  }

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(tag);

  // If the data or tag was changed, final() throws an error here
  const decrypted = Buffer.concat([decipher.update(data), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = { encrypt, decrypt, CURRENT_KEY_VERSION };