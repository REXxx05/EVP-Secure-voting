// SR-12: digital signatures for voting receipts.
//
// Receipts are signed with Ed25519 (Node's built-in crypto, no custom crypto).
// The private key is read from RECEIPT_SIGNING_PRIVATE_KEY in .env (a
// base64-encoded PKCS#8 PEM) and is never stored in the code or the database.
// The matching public key is published so anyone can verify a receipt.
//
// To make a key:
//   node -e "const c=require('crypto');const k=c.generateKeyPairSync('ed25519').privateKey.export({type:'pkcs8',format:'pem'});console.log(Buffer.from(k).toString('base64'))"

const crypto = require('crypto');
const path = require('path');

require('dotenv').config({ path: path.resolve(__dirname, '../../../.env'), quiet: true });

const RECEIPT_VERSION = 1;
const CODE_PATTERN = /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/;
const HEX64 = /^[0-9a-f]{64}$/;

function loadPrivateKey() {
  const encoded = process.env.RECEIPT_SIGNING_PRIVATE_KEY;
  if (!encoded) {
    throw new Error('RECEIPT_SIGNING_PRIVATE_KEY is missing');
  }
  let key;
  try {
    key = crypto.createPrivateKey(Buffer.from(encoded, 'base64').toString('utf8'));
  } catch {
    throw new Error('RECEIPT_SIGNING_PRIVATE_KEY is not a valid private key');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new Error('RECEIPT_SIGNING_PRIVATE_KEY must be an Ed25519 key');
  }
  return key;
}

function getPublicKey() {
  return crypto.createPublicKey(loadPrivateKey());
}

function getPublicKeyPem() {
  return getPublicKey().export({ type: 'spki', format: 'pem' });
}

// Short id of a public key so receipts say which key signed them (for rotation)
function keyIdOf(publicKey) {
  const der = publicKey.export({ type: 'spki', format: 'der' });
  return crypto.createHash('sha256').update(der).digest('hex').slice(0, 16);
}

function getKeyId() {
  return keyIdOf(getPublicKey());
}

// A fixed text form, so signing and verifying always cover exactly the same bytes
function canonicalReceipt({ version, electionId, verificationCode, commitment, keyId }) {
  return ['evp-receipt', version, electionId, verificationCode, commitment, keyId].join('\n');
}

function signReceipt(fields) {
  const privateKey = loadPrivateKey();
  const unsigned = { version: RECEIPT_VERSION, keyId: keyIdOf(crypto.createPublicKey(privateKey)), ...fields };
  const signature = crypto.sign(null, Buffer.from(canonicalReceipt(unsigned), 'utf8'), privateKey);
  return { ...unsigned, signature: signature.toString('base64') };
}

// Returns true only for a well-formed receipt whose signature verifies against
// the given public key (a KeyObject or PEM string). Never throws on bad input.
function verifyReceiptSignature(receipt, publicKey) {
  try {
    if (!receipt || typeof receipt !== 'object') return false;
    const { version, electionId, verificationCode, commitment, keyId, signature } = receipt;
    if (version !== RECEIPT_VERSION || !Number.isSafeInteger(electionId) || electionId < 1) return false;
    if (typeof verificationCode !== 'string' || !CODE_PATTERN.test(verificationCode)) return false;
    if (typeof commitment !== 'string' || !HEX64.test(commitment)) return false;
    if (typeof keyId !== 'string' || typeof signature !== 'string') return false;
    const key = typeof publicKey === 'string' ? crypto.createPublicKey(publicKey) : publicKey;
    if (keyIdOf(key) !== keyId) return false;
    return crypto.verify(null, Buffer.from(canonicalReceipt(receipt), 'utf8'), key, Buffer.from(signature, 'base64'));
  } catch {
    return false;
  }
}

module.exports = {
  RECEIPT_VERSION, CODE_PATTERN, HEX64,
  signReceipt, verifyReceiptSignature, getPublicKey, getPublicKeyPem, getKeyId, keyIdOf
};
