const crypto = require('crypto');

const {
  signResults,
  verifyResultsSignature,
  getPublicKey
} = require('../../src/security/resultSigning');

describe('SR-14: Election results digital signatures', () => {
  const originalKey = process.env.RESULT_SIGNING_PRIVATE_KEY;

  beforeAll(() => {
    const { privateKey } = crypto.generateKeyPairSync('ed25519');

    process.env.RESULT_SIGNING_PRIVATE_KEY = Buffer.from(
      privateKey.export({
        type: 'pkcs8',
        format: 'pem'
      })
    ).toString('base64');
  });

  afterAll(() => {
    if (originalKey === undefined) {
      delete process.env.RESULT_SIGNING_PRIVATE_KEY;
    } else {
      process.env.RESULT_SIGNING_PRIVATE_KEY = originalKey;
    }
  });

  const sampleResults = {
    electionId: 1,
    results: [
      { candidateId: 101, votes: 120 },
      { candidateId: 102, votes: 95 }
    ]
  };

  test('signs valid election results', () => {
    const signed = signResults(sampleResults);

    expect(signed.signature).toBeDefined();
    expect(signed.keyId).toBeDefined();

    expect(
      verifyResultsSignature(signed, getPublicKey())
    ).toBe(true);
  });

  test('rejects results when vote counts are modified', () => {
    const signed = signResults(sampleResults);

    const tampered = {
      ...signed,
      results: [
        { candidateId: 101, votes: 999 },
        { candidateId: 102, votes: 95 }
      ]
    };

    expect(
      verifyResultsSignature(tampered, getPublicKey())
    ).toBe(false);
  });

  test('rejects results when election ID is modified', () => {
    const signed = signResults(sampleResults);

    const tampered = {
      ...signed,
      electionId: 999
    };

    expect(
      verifyResultsSignature(tampered, getPublicKey())
    ).toBe(false);
  });

  test('rejects signatures verified with an incorrect public key', () => {
    const signed = signResults(sampleResults);

    const { publicKey: wrongPublicKey } =
      crypto.generateKeyPairSync('ed25519');

    expect(
      verifyResultsSignature(signed, wrongPublicKey)
    ).toBe(false);
  });

  test('rejects invalid result data', () => {
    expect(() => signResults({
      electionId: -1,
      results: []
    })).toThrow('Invalid election ID');
  });
});