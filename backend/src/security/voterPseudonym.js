const crypto = require('crypto');
require('../config/db');

const KEY_NAME = 'VOTER_LOG_HMAC_KEY';

function getHmacKey() {
  const encoded = process.env.VOTER_LOG_HMAC_KEY;

  if (typeof encoded !== 'string') {
    throw new Error(`${KEY_NAME} is not configured`);
  }

  const key = Buffer.from(encoded, 'base64');

  if (
    key.length !== 32 ||
    key.toString('base64') !== encoded
  ) {
    throw new Error(`${KEY_NAME} must be a base64-encoded 32-byte key`);
  }

  return key;
}

function pseudonymiseVoter(voterId) {
  if (!Number.isSafeInteger(voterId) || voterId < 1) {
    throw new TypeError('A valid voter identifier is required');
  }

  const key = getHmacKey();

  return crypto
    .createHmac('sha256', key)
    .update(`evp:voter-log:v1:${voterId}`, 'utf8')
    .digest('hex');
}

module.exports = {
  pseudonymiseVoter
};