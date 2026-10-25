// SR-20: the CVSS >= 7.0 build gate, including the 6.9 / 7.0 boundary.
const { spawnSync } = require('child_process');
const path = require('path');
const { evaluateAudit } = require('../../scripts/check-audit');

const script = path.resolve(__dirname, '../../scripts/check-audit.js');
const advisory = (score, severity = 'moderate') => ({
  source: 1, name: 'pkg', title: 'Example', url: 'https://github.com/advisories/GHSA-test',
  severity, cvss: { score, vectorString: 'CVSS:3.1/AV:N' }
});
const reportWith = (...vias) => ({ auditReportVersion: 2, vulnerabilities: { pkg: { name: 'pkg', via: vias } } });

test('a clean report passes', () => {
  expect(evaluateAudit({ auditReportVersion: 2, vulnerabilities: {} })).toEqual({ ok: true, blocking: [] });
});

test('CVSS 6.9 passes and CVSS 7.0 fails (boundary)', () => {
  expect(evaluateAudit(reportWith(advisory(6.9))).ok).toBe(true);
  const failed = evaluateAudit(reportWith(advisory(7.0, 'high')));
  expect(failed.ok).toBe(false);
  expect(failed.blocking[0]).toMatchObject({ package: 'pkg', cvss: 7 });
});

test('critical scores fail', () => {
  expect(evaluateAudit(reportWith(advisory(9.8, 'critical'))).ok).toBe(false);
});

test('one severe advisory among mild ones fails', () => {
  expect(evaluateAudit(reportWith(advisory(3.1, 'low'), advisory(8.1, 'high'), 'other-package')).ok).toBe(false);
});

test('transitive string references alone do not fail', () => {
  expect(evaluateAudit(reportWith('other-package')).ok).toBe(true);
});

test('an unscored high or critical advisory fails closed; unscored moderate passes', () => {
  expect(evaluateAudit(reportWith({ ...advisory(0, 'high'), cvss: undefined })).ok).toBe(false);
  expect(evaluateAudit(reportWith({ ...advisory(0, 'critical'), cvss: { score: 0 } })).ok).toBe(false);
  expect(evaluateAudit(reportWith({ ...advisory(0, 'moderate'), cvss: undefined })).ok).toBe(true);
});

test.each([null, 'text', {}, { vulnerabilities: 3 }, { vulnerabilities: {}, error: { summary: 'offline' } }])(
  'an unreadable report %j throws instead of passing', bad => {
    expect(() => evaluateAudit(bad)).toThrow();
  });

function runCli(input) {
  return spawnSync(process.execPath, [script], { input, encoding: 'utf8' });
}

test('CLI exit codes: 0 clean, 1 blocked, 2 unreadable', () => {
  expect(runCli(JSON.stringify(reportWith(advisory(6.9)))).status).toBe(0);
  const blocked = runCli(JSON.stringify(reportWith(advisory(7.0, 'high'))));
  expect(blocked.status).toBe(1);
  expect(blocked.stderr).toContain('CVSS 7');
  expect(runCli('not json').status).toBe(2);
  expect(runCli('').status).toBe(2);
});

test('CLI reads a file argument', () => {
  const file = path.join(require('os').tmpdir(), `audit-${process.pid}.json`);
  require('fs').writeFileSync(file, JSON.stringify(reportWith(advisory(9.1, 'critical'))));
  try {
    const result = spawnSync(process.execPath, [script, file], { encoding: 'utf8' });
    expect(result.status).toBe(1);
  } finally {
    require('fs').unlinkSync(file);
  }
});
