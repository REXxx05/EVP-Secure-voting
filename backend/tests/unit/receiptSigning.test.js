// SR-12 unit tests: Ed25519 receipt signatures and verification-code format.
const crypto = require('crypto');
const { signReceipt, verifyReceiptSignature, getPublicKey, getPublicKeyPem, getKeyId } =
  require('../../src/security/receiptSigning');
const { newVerificationCode, receiptRefOf, commitmentOf } = require('../../src/services/receipts');

const fields = () => ({
  electionId: 7,
  verificationCode: newVerificationCode(),
  commitment: commitmentOf('X', 'a', 'b')
});

test('verification codes are unique, 128-bit and well formed', () => {
  const codes = new Set(Array.from({ length: 2000 }, newVerificationCode));
  expect(codes.size).toBe(2000);
  codes.forEach(code => expect(code).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/));
});

test('board reference is the SHA-256 of the code, not the code itself', () => {
  const code = newVerificationCode();
  expect(receiptRefOf(code)).toMatch(/^[0-9a-f]{64}$/);
  expect(receiptRefOf(code)).not.toContain(code.replace(/-/g, '').toLowerCase());
});

test('a signed receipt verifies against the published public key (object and PEM)', () => {
  const receipt = signReceipt(fields());
  expect(verifyReceiptSignature(receipt, getPublicKey())).toBe(true);
  expect(verifyReceiptSignature(receipt, getPublicKeyPem())).toBe(true);
  expect(receipt.keyId).toBe(getKeyId());
});

test.each([
  ['election', r => ({ ...r, electionId: r.electionId + 1 })],
  ['code', r => ({ ...r, verificationCode: newVerificationCode() })],
  ['commitment', r => ({ ...r, commitment: 'f'.repeat(64) })],
  ['version', r => ({ ...r, version: 2 })],
  ['signature', r => ({ ...r, signature: Buffer.alloc(64, 1).toString('base64') })],
  ['key id', r => ({ ...r, keyId: '0'.repeat(16) })]
])('a receipt with a modified %s fails verification', (_name, mutate) => {
  const receipt = signReceipt(fields());
  expect(verifyReceiptSignature(mutate(receipt), getPublicKey())).toBe(false);
});

test('a receipt signed by a different key fails verification', () => {
  const receipt = signReceipt(fields());
  const other = crypto.generateKeyPairSync('ed25519').publicKey;
  expect(verifyReceiptSignature(receipt, other)).toBe(false);
});

test.each([null, undefined, 'text', 42, {}, { version: 1 }, []])(
  'malformed receipt %p is rejected without throwing', bad => {
    expect(verifyReceiptSignature(bad, getPublicKey())).toBe(false);
  });

test('receipt fields carry no voter identity or ballot choice', () => {
  const receipt = signReceipt(fields());
  expect(Object.keys(receipt).sort())
    .toEqual(['commitment', 'electionId', 'keyId', 'signature', 'verificationCode', 'version']);
});

test('signing fails closed when the key is missing or wrong type', () => {
  const original = process.env.RECEIPT_SIGNING_PRIVATE_KEY;
  try {
    delete process.env.RECEIPT_SIGNING_PRIVATE_KEY;
    expect(() => signReceipt(fields())).toThrow('RECEIPT_SIGNING_PRIVATE_KEY is missing');
    process.env.RECEIPT_SIGNING_PRIVATE_KEY = 'bm90LWEta2V5';
    expect(() => signReceipt(fields())).toThrow('not a valid private key');
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      .export({ type: 'pkcs8', format: 'pem' });
    process.env.RECEIPT_SIGNING_PRIVATE_KEY = Buffer.from(rsa).toString('base64');
    expect(() => signReceipt(fields())).toThrow('Ed25519');
  } finally {
    process.env.RECEIPT_SIGNING_PRIVATE_KEY = original;
  }
});
