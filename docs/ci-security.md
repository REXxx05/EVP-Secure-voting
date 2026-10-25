# SR-20 — CI security pipeline

Requirement: every code change passes a CI security pipeline (dependency vulnerability scan, static analysis, signed SBOM per release) before merge; builds fail on any dependency with CVSS ≥ 7.0.

## What runs

| Workflow / job | File | What it does | Fails the build when |
|---|---|---|---|
| Tests | `.github/workflows/security-ci.yml` | Fresh PostgreSQL 16, applies `database/0*.sql` and `database/setup/roles.sql`, writes a throwaway random `.env`, runs the full Jest suite | any test fails |
| Dependency scan (CVSS >= 7.0 fails) | same | `npm audit --json` over the whole tree, evaluated by `backend/scripts/check-audit.js` | any advisory has CVSS ≥ 7.0 (an unscored high/critical advisory also fails; an unreadable report exits 2 and fails) |
| Static analysis (ESLint security) | same | `eslint . --max-warnings 0` with `eslint-plugin-security`; every rule of the plugin is an error | any finding |
| CodeQL | same | GitHub CodeQL, `security-extended` queries, JavaScript | needs the ruleset `code_scanning` rule below to block merging on alerts |
| SBOM builds | same | `npm sbom --package-lock-only` CycloneDX, sanity-checked | lockfile cannot produce a valid SBOM |
| Signed SBOM | `.github/workflows/release-sbom.yml` | On a published release: repeats the CVSS gate, generates the SBOM, signs it with Sigstore cosign keyless (GitHub OIDC; **no signing key or secret in the repo**), verifies the signature, proves a modified SBOM fails verification, attaches SBOM + `.sigstore.json` bundle + SHA-256 to the release | CVSS gate, signing, verification, or the tamper check fails |

Actions are pinned to full commit SHAs. Workflow permissions default to `contents: read`; only the release job gets `contents: write` and `id-token: write`.

## Verifying a release SBOM

```bash
scripts/verify-sbom.sh REXxx05/EVP-Secure-voting sbom.cdx.json sbom.cdx.json.sigstore.json
```

Succeeds only if the file is exactly what this repository's `release-sbom.yml` signed.

## Merge enforcement (needs the repository owner)

A workflow cannot stop a merge by itself; GitHub must be told the checks are required. `.github/rulesets/main-protection.json` is an importable ruleset for the default branch that requires a pull request, the five checks above (names must match the job names exactly), a strict up-to-date branch, and CodeQL alerts of high severity or above to be resolved. Importing it needs repository **admin** rights: Settings → Rules → Rulesets → New ruleset → Import a ruleset. Until the owner does this, SR-20's "before merge" enforcement is **not active** — only the checks exist.

## Tested locally

- `check-audit.js` unit tests including the 6.9 / 7.0 boundary (`tests/unit/checkAudit.test.js`), and run against the real `npm audit --json` (0 vulnerabilities).
- ESLint passes on the repo and fails (exit 1) on a probe file containing `eval` and a non-literal `fs` path.
- `actionlint` (Docker `rhysd/actionlint`) reports no problems in both workflows.
- The Tests job's steps were reproduced locally: fresh `postgres:16` container, `database/0*.sql` + `roles.sql`, full Jest suite.
- Not testable locally: GitHub-hosted execution, CodeQL, and cosign keyless signing (needs GitHub OIDC). These run for the first time on GitHub.
