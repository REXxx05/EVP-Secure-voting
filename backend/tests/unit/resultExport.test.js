// SR-14: Unit tests for digitally signed election results export.

const crypto = require('crypto');

const {
  signResults,
  getPublicKeyPem
} = require('../../src/security/resultSigning');

const {
  verifyResultsForExport,
  prepareResultsForExport
} = require('../../src/services/resultExport');

describe('SR-14: Secure election results export', () => {
  let originalPrivateKey;
  let trustedPublicKey;
  let signedResults;

  const electionId = 101;

  const results = {
    electionId,
    results: [
      { candidateId: 1, votes: 150 },
      { candidateId: 2, votes: 100 }
    ]
  };

  beforeAll(() => {
    originalPrivateKey = process.env.RESULT_SIGNING_PRIVATE_KEY;

    // Generate a temporary signing key for testing.
    // No production private keys are used.
    const { privateKey } = crypto.generateKeyPairSync('ed25519');

    const privateKeyPem = privateKey.export({
      type: 'pkcs8',
      format: 'pem'
    });

    process.env.RESULT_SIGNING_PRIVATE_KEY =
      Buffer.from(privateKeyPem).toString('base64');

    trustedPublicKey = getPublicKeyPem();
  });

  afterAll(() => {
    if (originalPrivateKey === undefined) {
      delete process.env.RESULT_SIGNING_PRIVATE_KEY;
    } else {
      process.env.RESULT_SIGNING_PRIVATE_KEY = originalPrivateKey;
    }
  });

  beforeEach(() => {
    signedResults = signResults(results);
  });

  // -------------------------------------------------------
  // Digital signature verification
  // -------------------------------------------------------

  test('accepts correctly signed election results', () => {
    const verified = verifyResultsForExport(
      signedResults,
      trustedPublicKey
    );

    expect(verified).toEqual(signedResults);
  });

  test('rejects modified vote counts', () => {
    const altered = {
      ...signedResults,
      results: [
        { candidateId: 1, votes: 999 },
        { candidateId: 2, votes: 100 }
      ]
    };

    expect(() =>
      verifyResultsForExport(altered, trustedPublicKey)
    ).toThrow('Election results signature verification failed');
  });

  test('rejects verification with an incorrect public key', () => {
    const { publicKey } = crypto.generateKeyPairSync('ed25519');

    expect(() =>
      verifyResultsForExport(
        signedResults,
        publicKey.export({
          type: 'spki',
          format: 'pem'
        })
      )
    ).toThrow('Election results signature verification failed');
  });

  test('rejects export when the trusted public key is missing', () => {
    expect(() =>
      verifyResultsForExport(signedResults, null)
    ).toThrow('Trusted results verification key is unavailable');
  });

  test('rejects invalid signatures', () => {
    const altered = {
      ...signedResults,
      signature: 'invalid-signature'
    };

    expect(() =>
      verifyResultsForExport(altered, trustedPublicKey)
    ).toThrow('Election results signature verification failed');
  });

  // -------------------------------------------------------
  // SR-13 reconciliation integration
  // -------------------------------------------------------

  test('allows export after successful reconciliation', async () => {
    const reconcile = jest.fn().mockResolvedValue({
      ok: true,
      counts: {
        acceptedSubmissions: 2,
        storedBallots: 4,
        hashEntries: 4
      },
      ballots: [
        {
          id: 'internal-ballot',
          ballotData: {
            preferences: [1, 2]
          }
        }
      ]
    });

    const exported = await prepareResultsForExport(
      electionId,
      signedResults,
      trustedPublicKey,
      { reconcile }
    );

    expect(reconcile).toHaveBeenCalledTimes(1);
    expect(reconcile).toHaveBeenCalledWith(electionId);

    expect(exported).toEqual(signedResults);

    // Sensitive internal ballot data must not appear in exports.
    expect(exported).not.toHaveProperty('ballots');
    expect(JSON.stringify(exported)).not.toContain('internal-ballot');
  });

  test('blocks export when reconciliation reports failure', async () => {
    const reconcile = jest.fn().mockResolvedValue({
      ok: false,
      reason: 'Ballot count mismatch'
    });

    await expect(
      prepareResultsForExport(
        electionId,
        signedResults,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'RECONCILIATION_FAILED'
    });
  });

  test('blocks export when reconciliation throws an error', async () => {
    const reconcile = jest.fn().mockRejectedValue(
      new Error('Ballot integrity verification failed')
    );

    await expect(
      prepareResultsForExport(
        electionId,
        signedResults,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toThrow('Ballot integrity verification failed');
  });

  test('rejects results belonging to a different election', async () => {
    const reconcile = jest.fn();

    await expect(
      prepareResultsForExport(
        202,
        signedResults,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'ELECTION_MISMATCH'
    });

    expect(reconcile).not.toHaveBeenCalled();
  });

  test('rejects invalid election IDs', async () => {
    const reconcile = jest.fn();

    await expect(
      prepareResultsForExport(
        -1,
        signedResults,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'INVALID_ELECTION'
    });

    expect(reconcile).not.toHaveBeenCalled();
  });

  test('rejects missing signed result packages', async () => {
    const reconcile = jest.fn();

    await expect(
      prepareResultsForExport(
        electionId,
        null,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'INVALID_RESULT_PACKAGE'
    });

    expect(reconcile).not.toHaveBeenCalled();
  });

  test('blocks reconciliation when the signature is invalid', async () => {
    const reconcile = jest.fn();

    const altered = {
      ...signedResults,
      results: [
        { candidateId: 1, votes: 999 },
        { candidateId: 2, votes: 100 }
      ]
    };

    await expect(
      prepareResultsForExport(
        electionId,
        altered,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'INVALID_RESULT_SIGNATURE'
    });

    // An invalid signature must not proceed to reconciliation.
    expect(reconcile).not.toHaveBeenCalled();
  });

  test('rejects unsigned additional result fields', async () => {
    const reconcile = jest.fn();

    const altered = {
      ...signedResults,
      winner: 'Unauthorised candidate'
    };

    await expect(
      prepareResultsForExport(
        electionId,
        altered,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'INVALID_RESULT_SIGNATURE'
    });

    expect(reconcile).not.toHaveBeenCalled();
  });

  test('rejects duplicate candidate IDs', async () => {
    const reconcile = jest.fn();

    const altered = {
      ...signedResults,
      results: [
        { candidateId: 1, votes: 150 },
        { candidateId: 1, votes: 100 }
      ]
    };

    await expect(
      prepareResultsForExport(
        electionId,
        altered,
        trustedPublicKey,
        { reconcile }
      )
    ).rejects.toMatchObject({
      code: 'INVALID_RESULT_SIGNATURE'
    });

    expect(reconcile).not.toHaveBeenCalled();
  });
});