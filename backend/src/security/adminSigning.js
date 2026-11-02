
/**
 * SR-18: Digital signatures for candidate orders and exclusions.
 *
 * Uses Ed25519 digital signatures.
 *
 * Every signed action identifies:
 * - The acting administrator
 * - The affected candidate
 * - The action performed
 * - The new value
 * - The signing timestamp
 *
 * Private keys must be protected and must never be committed
 * to source control or stored in the application database.
 */

const crypto = require('crypto');

const VERSION = 1;
const DOMAIN = 'evp-admin-candidate-action';

const ALLOWED_ACTIONS = [
  'candidate.order',
  'candidate.exclude',
  'candidate.restore'
];

/**
 * Validate an administrator action and produce a consistent
 * representation for signing and verification.
 */
function canonicalAction(action) {
  if (
    !action ||
    typeof action !== 'object' ||
    Array.isArray(action)
  ) {
    throw new TypeError('Invalid candidate action');
  }

  const {
    adminId,
    candidateId,
    actionType,
    newValue,
    signedAt
  } = action;

  if (
    !Number.isSafeInteger(adminId) ||
    adminId < 1 ||
    !Number.isSafeInteger(candidateId) ||
    candidateId < 1 ||
    !ALLOWED_ACTIONS.includes(actionType) ||
    typeof newValue !== 'string' ||
    typeof signedAt !== 'string' ||
    !Number.isFinite(Date.parse(signedAt)) ||
    new Date(signedAt).toISOString() !== signedAt
  ) {
    throw new TypeError('Invalid candidate action fields');
  }

  if (actionType === 'candidate.order') {
    if (
      !/^[1-9][0-9]*$/.test(newValue) ||
      !Number.isSafeInteger(Number(newValue))
    ) {
      throw new TypeError('Invalid candidate order');
    }
  } else {
    const expectedValue =
      actionType === 'candidate.exclude' ? 'true' : 'false';

    if (newValue !== expectedValue) {
      throw new TypeError('Invalid exclusion value');
    }
  }

  return JSON.stringify({
    domain: DOMAIN,
    version: VERSION,
    adminId,
    candidateId,
    actionType,
    newValue,
    signedAt
  });
}

/**
 * Generate a stable SHA-256 identifier for an Ed25519 public key.
 *
 * Accepts either a public KeyObject or a PEM string.
 */
function keyIdOf(publicKey) {
  const key = typeof publicKey === 'string'
    ? crypto.createPublicKey(publicKey)
    : publicKey;

  if (
    !key ||
    key.type !== 'public' ||
    key.asymmetricKeyType !== 'ed25519'
  ) {
    throw new TypeError(
      'Administrator public key must be Ed25519'
    );
  }

  const publicKeyDer = key.export({
    type: 'spki',
    format: 'der'
  });

  return crypto
    .createHash('sha256')
    .update(publicKeyDer)
    .digest('hex');
}

/**
 * Sign a candidate action using the administrator's private key.
 *
 * The private key is supplied by a separate secure key-management
 * mechanism. It is not retrieved from the candidate database.
 */
function signCandidateAction(action, privateKeyPem) {
  const privateKey = typeof privateKeyPem === 'string'
    ? crypto.createPrivateKey(privateKeyPem)
    : privateKeyPem;

  if (
    !privateKey ||
    privateKey.type !== 'private' ||
    privateKey.asymmetricKeyType !== 'ed25519'
  ) {
    throw new TypeError(
      'Administrator private key must be Ed25519'
    );
  }

  const payload = canonicalAction(action);

  const publicKey = crypto.createPublicKey(privateKey);

  const signature = crypto.sign(
    null,
    Buffer.from(payload, 'utf8'),
    privateKey
  );

  return {
    ...action,
    keyId: keyIdOf(publicKey),
    signature: signature.toString('base64')
  };
}

/**
 * Verify a signed candidate action against a trusted public key.
 *
 * The public key must be retrieved from the administrator's
 * registered key record, not from an untrusted API request.
 *
 * Returns false if the signature or signed data is invalid.
 */
function verifyCandidateAction(
  signedAction,
  trustedPublicKeyPem
) {
  try {
    if (
      !signedAction ||
      typeof signedAction !== 'object' ||
      Array.isArray(signedAction) ||
      typeof signedAction.signature !== 'string' ||
      typeof signedAction.keyId !== 'string'
    ) {
      return false;
    }

    const publicKey =
      typeof trustedPublicKeyPem === 'string'
        ? crypto.createPublicKey(trustedPublicKeyPem)
        : trustedPublicKeyPem;

    if (
      !publicKey ||
      publicKey.type !== 'public' ||
      publicKey.asymmetricKeyType !== 'ed25519'
    ) {
      return false;
    }

    if (keyIdOf(publicKey) !== signedAction.keyId) {
      return false;
    }

    const payload = canonicalAction(signedAction);

    const signature = Buffer.from(
      signedAction.signature,
      'base64'
    );

    // Ed25519 signatures are exactly 64 bytes.
    // Also reject malformed or non-canonical Base64.
    if (
      signature.length !== 64 ||
      signature.toString('base64') !== signedAction.signature
    ) {
      return false;
    }

    return crypto.verify(
      null,
      Buffer.from(payload, 'utf8'),
      publicKey,
      signature
    );
  } catch {
    return false;
  }
}

module.exports = {
  VERSION,
  DOMAIN,
  canonicalAction,
  keyIdOf,
  signCandidateAction,
  verifyCandidateAction
};
