// SR-17: Automated privacy checks for backend logging paths.

const fs = require('fs');
const path = require('path');

const srcRoot = path.resolve(__dirname, '../../src');

function readSource(relativePath) {
  return fs.readFileSync(path.join(srcRoot, relativePath), 'utf8');
}

describe('SR-17: Automated logging source checks', () => {
  test('voter access-denied events use the privacy log', () => {
    const source = readSource('middleware/requireRole.js');

    expect(source).toContain('INSERT INTO voter_privacy_log');
    expect(source).toContain('pseudonymiseVoter(req.user.id)');
  });

  test('eligibility-denied events use the privacy log', () => {
    const source = readSource('middleware/requireEligibleVoter.js');

    expect(source).toContain('INSERT INTO voter_privacy_log');
    expect(source).toContain('pseudonymiseVoter(userId)');
  });

  test('eligibility middleware does not write voter details to console logs', () => {
    const source = readSource('middleware/requireEligibleVoter.js');

    expect(source).not.toMatch(/console\.(log|warn|info|debug)\s*\(/);
  });

  test('privacy-log inserts exclude direct identifiers and correlation fields', () => {
    const files = [
      'middleware/requireRole.js',
      'middleware/requireEligibleVoter.js',
    ];

    for (const file of files) {
      const source = readSource(file);

      const inserts = [
        ...source.matchAll(
          /INSERT INTO voter_privacy_log\s*\(([^)]*)\)/gi
        ),
      ];

      expect(inserts.length).toBeGreaterThan(0);

      for (const insert of inserts) {
        const columns = insert[1]
          .split(',')
          .map((column) => column.trim().toLowerCase());

        expect(columns).toEqual([
          'voter_pseudonym',
          'event_type',
          'reason',
        ]);

        expect(columns).not.toContain('voter_id');
        expect(columns).not.toContain('ip_address');
        expect(columns).not.toContain('ballot_id');
        expect(columns).not.toContain('election_id');
        expect(columns).not.toContain('created_at');
      }
    }
  });

  test('candidate audit actions use candidate-specific targets', () => {
    const source = readSource('services/adminActions.js');

    expect(source).toContain('target: `candidate:${candidateId}`');
  });

  test('application error handler does not print raw exception objects', () => {
    const source = readSource('app.js');

    expect(source).not.toMatch(/console\.error\s*\(\s*(err|error)\s*\)/);
    expect(source).toContain("console.error('Internal application error')");
  });
});