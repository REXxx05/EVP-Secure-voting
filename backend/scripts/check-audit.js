// SR-20: fails the build on any dependency vulnerability with CVSS >= 7.0.
//
// Usage (from the backend folder):
//   npm audit --json | node scripts/check-audit.js
//   node scripts/check-audit.js path/to/audit.json
//
// Exit code 0 = no dependency at or above the threshold, 1 = blocked,
// 2 = the report could not be read (fail closed: an unreadable scan is not a pass).

const fs = require('fs');

const THRESHOLD = 7.0;

// npm audit (report version 2) lists each advisory as an object inside
// vulnerabilities[name].via[]; strings in via[] only point at another package.
function evaluateAudit(report, threshold = THRESHOLD) {
  if (!report || typeof report !== 'object' || !report.vulnerabilities ||
      typeof report.vulnerabilities !== 'object') {
    throw new Error('Not an npm audit JSON report');
  }
  if (report.error) {
    throw new Error('npm audit reported an error: ' + (report.error.summary || report.error.code || 'unknown'));
  }
  const blocking = [];
  for (const [pkg, vuln] of Object.entries(report.vulnerabilities)) {
    for (const via of vuln.via || []) {
      if (typeof via !== 'object' || via === null) continue;
      const score = via.cvss && typeof via.cvss.score === 'number' ? via.cvss.score : null;
      // No score published: fall back to severity so an unscored high/critical still blocks.
      const unscoredButSevere = score === null || score === 0
        ? (via.severity === 'high' || via.severity === 'critical') : false;
      if ((score !== null && score >= threshold) || unscoredButSevere) {
        blocking.push({ package: pkg, advisory: via.url || via.title || 'unknown', cvss: score, severity: via.severity });
      }
    }
  }
  return { ok: blocking.length === 0, blocking };
}

function main() {
  let raw;
  try {
    raw = fs.readFileSync(process.argv[2] || 0, 'utf8');
    const result = evaluateAudit(JSON.parse(raw));
    if (result.ok) {
      console.log(`Dependency scan passed: no advisory with CVSS >= ${THRESHOLD}.`);
      return 0;
    }
    console.error(`Dependency scan FAILED: ${result.blocking.length} advisory(ies) with CVSS >= ${THRESHOLD}:`);
    for (const b of result.blocking) {
      console.error(` - ${b.package}: CVSS ${b.cvss === null ? 'unscored' : b.cvss} (${b.severity}) ${b.advisory}`);
    }
    return 1;
  } catch (err) {
    console.error('Dependency scan could not be evaluated: ' + err.message);
    return 2;
  }
}

if (require.main === module) {
  process.exitCode = main();
}

module.exports = { evaluateAudit, THRESHOLD };
