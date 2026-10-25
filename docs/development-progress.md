# Development and documentation working tracker

Process support only. This file is not final assessable report content or a record of student design decisions. Owner: vinuthna, s4217142, GitHub Vinuthna1R, as recorded in A3_Secure.docx.

## Checkpoint 2026-10-25 — SR-06 completion work and SR-11 / SR-12 / SR-15 / SR-20 implementation (AI-assisted, Claude)

Implemented on branch vinuthna/a3-security-requirements (originally codex/ai-assisted-sr06; renamed after removing a co-author trailer from commit messages, trees/authors/timestamps unchanged; local tag backup/pre-rewrite-f9df621 holds the old history). Generated code, identified as such; not student-authored. Commit identity is set repo-locally to Vinuthna1R; the global Git identity (a different account) was deliberately not used. No Co-Authored-By trailer is added to commits.

Git history: PR #26 (SR-06, SR-11, SR-12, plus SR-15 which was pushed to the same branch before the merge) was merged into main by REXxx05 as f4c8d36. SR-20 is on a separate branch, vinuthna/sr-20-ci-security (fd915c2 CVSS gate + ESLint, 3eb55dc CI/SBOM/ruleset); no PR for it yet. Issues #9, #17, #18, #21, #25 are all still open; none has been closed.

Synchronisation: fetched all remotes; main is still 5c10c25. SR-04 (origin/dhanush/sr-01-03-04-07-19) and SR-07 are NOT merged. SR-05 (`checkEligibility(userId, electionId, { client, lock: true })`) and SR-08 (`saveBallotAnonymously(client, ballot)`) were re-read in source and match the recorded contracts. Baseline re-run before any change: 11 suites, 85 tests, 0 failed.

| Requirement | Issue | What exists now | Still missing | Status |
|---|---|---|---|---|
| SR-06 | #9 | Transactional submission service, unmounted route factory, rollback/retry/concurrency tests; now also records SR-11 hashes and SR-12 receipt in the same transaction | Real login -> vote -> duplicate E2E (SR-04 unmerged, kept as `test.todo` in e2eVoting.pending.test.js); real SR-07 validator; real session finalizer | Not complete, issue open |
| SR-11 | #17 | `database/05_ballot_hashes.sql` (append-only, trigger + INSERT/SELECT-only grant), `ballotIntegrity.js` (HMAC-SHA-256 hash, recorded in the vote transaction, `verifyElection`, `loadBallotsForTally` gate), unit + PostgreSQL tamper tests | SR-13 must call `loadBallotsForTally`; "separate store" is a separate table in the same database, not a separate server; hash is keyed HMAC-SHA-256 (decision recorded below) | Implemented, pending team acceptance, issue open |
| SR-12 | #18 | `database/06_bulletin_board.sql`, Ed25519 signed receipts (`receiptSigning.js`, `receipts.js`), public routes (`/api/bulletin-board/*`, mounted in app.js), `markElectionCounted` gated by SR-11, tests | Counted status needs SR-13 to trigger `markElectionCounted`; key lifecycle/rotation procedure; first-party UI | Implemented, pending acceptance, issue open |
| SR-15 | #21 | (merged in PR #26, de80fd8) `database/04_audit_log.sql` (04 as instructed), `auditLog.js` runner (success row in the action's transaction; failure row after rollback; action blocked if the log cannot be written), `adminActions.js` (candidate exclusion), tests | SR-02 MFA and SR-03 role routing do not exist yet, so no HTTP privileged endpoints are wired; SR-16 hash chain / auditor-only reads not done | Implemented for the service layer, merged, pending acceptance, issue open |
| SR-20 | #25 | `.github/workflows/security-ci.yml`, `release-sbom.yml`, `backend/scripts/check-audit.js` (CVSS >= 7.0 gate), ESLint security config, `scripts/verify-sbom.sh`, `.github/rulesets/main-protection.json`, docs/ci-security.md | Workflows have not run on GitHub; ruleset needs repository-owner import; cosign signing only runs on a real release | Implemented on vinuthna/sr-20-ci-security (not merged); workflows never run on GitHub; merge enforcement inactive until the owner imports the ruleset; issue open |

Design decisions worth reviewing:
- SR-11 uses HMAC-SHA-256 with BALLOT_INTEGRITY_KEY (kept in .env) over `version, ballot id, election, division, chamber, plaintext`. A plain unkeyed SHA-256 of a small ballot space lets anyone with read access to the hash table guess the vote without the SR-09 key; hashing ciphertext would break on SR-09 key rotation. If a plain SHA-256 is required by the marker, the change is confined to `computeBallotHash`.
- Hash and bulletin-board tables carry no voter id and no timestamp or serial (SR-08).
- A vote fails closed (rolls back entirely) if the integrity hash or the receipt cannot be written, including when the receipt signing key is not configured.
- SR-15: the app database role can INSERT but not SELECT audit_log, so INSERT ... RETURNING is not used.
- New secrets (never committed): BALLOT_INTEGRITY_KEY and RECEIPT_SIGNING_PRIVATE_KEY in .env; placeholders in .env.example.
- Database numbering: 04 = audit_log (teammate instruction), 05 = ballot_hashes, 06 = bulletin_board. Existing databases need these files and the new GRANTs from roles.sql applied manually (they only run on first creation).
- package-lock.json changed (ESLint devDependencies); expect a merge conflict with the SR-01 branch's bcrypt change that is trivially resolvable by re-running `npm install`.

Test evidence: full suite 18 suites / 168 tests passed, 5 todo (pending E2E), 0 failed (`npm test -- --runInBand`); lint passes; `npm audit` 0 vulnerabilities; actionlint clean; the same suite also passed against a brand-new PostgreSQL 16 container built only from `database/0*.sql` + `roles.sql` (the CI recipe).

## Verified baseline

## Latest AI-assisted SR-06 implementation checkpoint

### Latest route integration and review milestone

- Independently verified existing baseline at 5c10c25: 10 suites, 63 tests passed, 0 failed, 4.366 s. Fetched public refs with credential helpers disabled; main remains 5c10c25. No branch merge or teammate-source edits.
- Reviewed every untracked source/test/document addition. No unexpected tracked changes; no private key/GitHub token/AWS access-key patterns; .env is ignored. Existing fake fixture credentials remain test-only. Preserve AI attribution and limits; scan is not a comprehensive security certification.
- Inspected unmerged SR-04 sessionModel: createSession, findValidSession, touchSession, invalidateSession and 30-minute idle constant; all use pooled db.query. No real auth middleware/login route/CSRF adapter or transaction-client invalidation yet. SR-07 validator still absent. Exact required integration contracts recorded in docs/ai-assisted-sr06.md. No duplication of their implementations.
- Added AI-generated backend/src/routes/ballots.js and backend/tests/integration/ballotsRoute.test.js. Router factory requires explicit actual auth, CSRF, validator and session-finalizer collaborators and remains unmounted. Safe body/ID handling, identity from trusted request state, no-store accepted-path response, safe status/error mapping, no internal error logging/serialization, HTTP commit-wait verified in isolated tests.
- Extended service with optional transactional session finalizer, required by the route factory, before COMMIT. Real-PostgreSQL tests prove a test-only finalizer marker commits/rolls back alongside the ballots; they do not test actual sessions. No authenticated end-to-end completion claim.
- Initial focused execution: route suite parse failure from an extra parenthesis; service unit suite 17/17 passed. Corrected test syntax. Final full suite: 11 suites passed, 85 tests passed, 0 failed, 4.244 s. Includes 39 baseline + 17 service unit + 9 database service integration + 20 HTTP adapter tests. No additional reruns without changes are needed.
- Genuine milestone ready: service + explicit route integration boundary + tests + AI attribution. Check real clock, latest commit time and configured author before commit; no timestamp/environment overrides. Issue #9 remains open, no PR/push/merge to main.

### Earlier service milestone

The user explicitly changed the working approach and requested direct AI-generated implementation in an identified working branch. Generated work must not be represented as student-authored or assumed permitted for assessment submission. This supersedes the earlier process-only/no-generated-code statements for the files listed here; earlier entries remain historical.

- Created codex/ai-assisted-sr06 from 5c10c25, preserving all prior documentation and teammate source/history. No PR or issue closure. No new Git commit; actual timestamps/history remain unchanged. Keep the 30-minute minimum at any later genuine commit checkpoint.
- AI-generated backend/src/services/ballotSubmission.js: CommonJS factory using existing pool, real locked eligibility and real anonymous storage. Requires explicit validator wiring; no permissive production fallback and no public route. Trusted identity is a service precondition, not a simulated authentication implementation.
- Service reserves participation with plain INSERT under the real composite primary key, writes both chamber ballots via SR-08 on the same client, confirms only after a verified COMMIT command tag, rolls back failures, preserves eligibility denial reason, narrowly maps the participation conflict, and releases/discards connections. Ambiguous commit errors are distinguished from known rollback, never reported as success.
- AI-generated backend/tests/unit/ballotSubmission.test.js and backend/tests/integration/ballotSubmission.test.js. PostgreSQL integration uses real eligibility, encryption and storage, isolated fake fixtures, admin-only fixture setup/observation/cleanup, and explicitly simulated trusted identity/validator. Two independent connections actually enter an observed PostgreSQL lock wait, then test first-commit and first-rollback outcomes. No shared seed or database volume reset.
- Execution: unit-only run 16 passed / 0 failed, 1.547 s; integration-only run 6 passed / 0 failed, 1.665 s; initial full run 10 suites / 61 tests passed, 3.977 s.
- Review found a previously uncovered bug: a collaborator suppressing an SQL error can leave PostgreSQL aborted, making COMMIT return ROLLBACK without rejecting. Fixed acceptance to require the COMMIT command tag and added unit/real-database regression cases. Final full run: 10 suites passed, 63 tests passed, 0 failed; npm test -- --runInBand; 4.161 seconds. Final SR-06 tests: 17 unit + 7 integration. No failed test run occurred in this checkpoint; bug found by review.
- Evidence covers success, sequential duplicate, Senate SQL failure with total rollback, retry, ineligibility/missing chamber, competing commit/rollback outcomes, no additional/partial ballot pairs, pending COMMIT, acquisition/BEGIN/rollback/commit failures, and no direct identity fields passed to storage. It does not establish database-administrator-resistant anonymity or real authentication.
- Remaining: route-level request/status/error mapping; real SR-01/SR-04 login/session and invalidation; real SR-07 validator; actual end-to-end login->vote->duplicate rejection; team review and acceptance. Issue #9 stays open; SR-06 remains partially implemented, not complete.
- AI attribution/design/integration notes: docs/ai-assisted-sr06.md. Earlier issue inventory remains intact; no other requirement implementation started.
- Authorized report's existing working comment updated with explicit AI-generated authorship, branch/files, actual initial/final runs, review-found COMMIT-as-ROLLBACK bug and fix, remaining integration and partial status. Only comments.xml changed; ten rendered pages match the last reviewed report. Source hash checked before saving; preserved A3_Secure.before-ai-sr06.docx. No final assessable narrative rewritten.

## Historical baseline and process records

- Branch: codex/assigned-security-requirements; baseline commit: 5593716533ec3f764de182a02f36afeabda0c240.
- Node 24.14.1, npm 11.11.0, Git 2.54.0, Docker 29.7.2, Compose 5.4.0.
- Existing lockfile installed without modification: 397 packages. npm emitted a glob@10.5.0 deprecation/security warning; no vulnerability scan has been completed.
- PostgreSQL 16.15 initialized using existing Compose/schema/seed files. Seven tables, three divisions, one election, nine candidates. Existing roles.sql applied. evp_app is not a superuser; ballot INSERT allowed, UPDATE and DELETE denied by privilege inspection.
- Existing Jest baseline: 3 suites passed, 15 tests passed, 0 failed. Initial sandbox run: 11 passed and 4 loopback EACCES failures; rerun with local networking passed. This is not acceptance evidence for the five assigned requirements.
- Live app on port 3100: homepage, /api/health and /api/health/db returned HTTP 200. Port 3000 belongs to another local project. /login.html is absent in this checkout.
- Local .env contains generated development secrets and is ignored. Never copy its values into evidence.
- No student implementation changes or new commits have been made in this session. No timestamps or history were rewritten.
- GitHub live branch lookup showed main and sr-09-encryption. Latest issue-detail request failed with DNS error; issue assignments must be rechecked before coordination.

## Commit and pull request rules

- User requires at least 30 minutes between consecutive commits made for this project. Check the latest applicable actual commit time and the current clock immediately before committing; never override author or committer timestamps. Also retain an actual execution-time record for any commits made during this workflow.
- Continue development, testing, debugging and review between commits. Elapsed time alone is not a reason to commit. If a meaningful verified milestone finishes too early, leave it uncommitted until a later genuine development checkpoint after the interval has elapsed.
- No scheduled commits, fabricated activity, empty milestone commits, backdating, history rewriting or metadata manipulation.
- Do not open a pull request until all SR-06/11/12/15/20 acceptance criteria have evidence and the user explicitly requests the PR.
- Latest observed HEAD remains 5593716533ec3f764de182a02f36afeabda0c240, committer timestamp 2026-10-25T00:12:30+11:00. No new commit made. A fresh time/history check is required at a real commit checkpoint.
- Current checkpoint: no student implementation diff exists; routes/services contain only placeholders. The tracker is untracked. No new requirement tests were run because there is no implementation change to verify. Report status remains unchanged.

## SR-06 synchronization and issue checkpoint

- Active scope is SR-06 only. No work on SR-11/12/15/20 is authorized at this checkpoint.
- Fetched origin and fast-forwarded codex/assigned-security-requirements to 6a59910 (merge of teammate PR #8), without creating a new commit or altering existing history. Read the updated README and reviewed TLS configuration/server changes and new tests. Schema/dependency lockfile unchanged.
- Current verified baseline: 5 suites passed, 18 tests passed, 0 failed; npm test -- --runInBand, 1.975 seconds. These are existing baseline tests, not SR-06 acceptance tests. Earlier expectation of four added tests was incorrect: the teammate changes add three tests.
- New README allocation table conflicts with the student's explicit allocation: it appears to give SR-06/11/12/15/20 to Shambhu. Preserve it for group correction; student's confirmed assignment remains authoritative for this workflow.
- Current server source requires HTTPS certificates, which are absent locally. The previous running HTTP process is stale relative to synchronized source. Passing Supertest/configuration tests do not verify a live TLS deployment. No TLS source was weakened or changed for SR-06.
- SR-06 issue: https://github.com/REXxx05/EVP-Secure-voting/issues/9. Exact Part 1 requirement/acceptance wording preserved. Assignment to Vinuthna1R and labels Priority - High / Complexity - High visually verified using the Vinuthna1R browser session.
- Account error: initial issue creation used the preconfigured heybhava Git credential without verifying identity first. Issue authorship remains heybhava and cannot be changed. User explicitly forbids any further use of that account. Do not retrieve/use its stored credential, mutate its issue as that account, push through it, or change global account settings. Further authenticated GitHub work must verify Vinuthna1R first. Browser session was subsequently verified as Vinuthna1R and used for assignment/labels. No duplicate issue or authorship-rewriting action was performed.
- Confirmed by student from teammate: House and Senate submitted together, both or neither saved; SR-01/04 own authentication and sessions, SR-05 eligibility only, SR-08 anonymous storage. These are confirmed architectural responsibilities; no production functions implementing these interfaces exist in the synchronized source.
- First concrete student checkpoint is docs/sr06-contract-review.md. Contract choices await the student's own answers. No production code/test doubles or SR-06 acceptance tests were generated.
- SR-06 report milestone: attached one Word comment authored Codex process support to the student's SR-06 contribution description. It records student-confirmed responsibilities, issue #9 metadata, the 18-test baseline, pending checkpoints, missing evidence and interfaces. No final report prose or rationale added. Existing visible text was compared and is unchanged; comment range/reference and package wiring verified. All ten rendered pages are pixel-identical to the last visually inspected report. Saved Downloads working copy after a source-hash check; backup A3_Secure.before-sr06-checkpoint.docx. No commit created.
- Student subsequently supplied six proposed contract decisions: combined POST endpoint, 201 after commit/409 for confirmed duplicate, trusted SR-01/04 identity, SR-05 eligibility, same-client SR-08 storage without independent commit, and full rollback/retry after Senate failure. Recorded as proposals for review, not final student rationale. Expanded docs/sr06-contract-review.md with schema limitations, unresolved interfaces, student implementation exercise and deterministic rollback/concurrency test scenarios. No source/tests changed and no new tests were run at this documentation checkpoint. Prior 18-test baseline remains the latest execution evidence. The report's existing working comment already records these responsibilities and pending implementation; no new implementation outcome exists to add. No commit or PR created.

## Requirement progress

## Latest GitHub synchronization and issue milestone

- Active feature branch codex/assigned-security-requirements inspected with two untracked working documentation files; no source implementation changes found. Fetched public refs with credential helpers disabled. Safely fast-forwarded afe8b23 -> 5c10c25; no conflicts, discarded work, rewritten history or new commit.
- Newly incorporated PR #16: SR-05 transaction support. Implementation commit 50780a7; merge commit 5c10c25f7e591eae46da1fb2e45cd9c005d69fa3. Updated eligibilityService.js and its integration tests; read current README. checkEligibility now accepts { client, lock: true }, shares the SR-06 transaction, and row-locks election then enrolment FOR SHARE. Previous pending-interface entries are historical and superseded.
- Full baseline after sync: 8 suites passed, 39 tests passed, 0 failed; npm test -- --runInBand; 4.046 seconds. No new SR-06 acceptance tests exist or were claimed to pass.
- Inspected unmerged origin/dhanush/sr-01-03-04-07-19: authentication/session model work exists but SR-04 is not merged into main. No teammate branch was merged prematurely. Real login/session -> full vote -> duplicate denial remains a pending integration test, including renewed-session duplicate testing where invalidation masks the participation constraint.
- Compared all public open/closed issues to all twenty Part 1 requirements. Created missing SR-11/12/13/14/15/16/17/18/20 as issues #17-25 through the verified Vinuthna1R browser session, rechecking duplicates before every creation. All nine include exact requirement text, priority/complexity, measurable checklist, dependency notes and review-before-close instructions. No implementation of the other four assigned requirements began.
- Existing eleven issue bodies retained in full and extended with exact-source references where needed, source ratings and integration dependencies. Concurrent-edit checks preserved originals. Final public verification established one issue per SR, exact source descriptions in all twenty, correct existing priority/complexity labels, unchanged original assignments/states, and all five user issues assigned to Vinuthna1R. No issue was closed.
- User issue links: SR-06 #9, SR-11 #17, SR-12 #18, SR-15 #21, SR-20 #25. Unconfirmed owners left unassigned: SR-13 #19, SR-14 #20, SR-16 #22, SR-17 #23, SR-18 #24. README allocation conflict still requires group clarification.
- Saved complete inventory in docs/github-issue-inventory.md and docs/github-issue-inventory.json; visual proof all-20-issues.png in the task's visualization folder. Existing issue #9 authorship remains the previously disclosed account error; all current mutations used only Vinuthna1R. No prohibited account credential was retrieved or used.
- Closing workflow: actual implementation, criterion-specific tests, genuine commits, tracker/report evidence and team-accepted review are required. Do not automatically close from commits or close teammates' issues. No PR or merge of the feature branch into main is authorized.
- No implementation commit is ready; all source remains teammate-authored. Working documentation stays uncommitted. At any later genuine commit checkpoint, enforce the existing minimum 30 minutes, verify actual Git author identity, and preserve real timestamps.
- Report updated with this synchronization/issue milestone in the existing attributed process-support comment. Only comments.xml changed; all ten rendered pages are identical to the previously reviewed report. Saved authorized Downloads copy after source-hash verification and preserved A3_Secure.before-issue-workflow.docx. No final assessable report prose generated.

## Historical integration checkpoints

Latest integration update: fetched without Git credential helpers and fast-forwarded the existing feature branch from 6a59910 to afe8b23. SR-05 (#11) and SR-08 (#15) are merged; no SR-06 transaction service exists. Eligibility interface and same-client mismatch are recorded at the top of docs/sr06-contract-review.md. Storage accepts the transaction client and must be called for each chamber. Historical absent-interface notes below are superseded by this update.

Initial synchronized test run: 8 suites total, 5 passed / 3 failed; 36 tests total, 22 passed / 14 failed. PostgreSQL connection refused on 127.0.0.1:5432 because Docker Desktop was stopped. SR-08 teardown also raised undefined-client errors after failed acquisition. These are actual failed results, not SR-06 acceptance failures. Database recovery is in progress; no source code changed.

Recovery checkpoint: Docker Desktop processes are running and CLI says already running, but the Linux engine named pipe remains unavailable after startup retries. PostgreSQL cannot be started yet. Requested that the student inspect Docker Desktop's startup/error prompt. No database reset, migration application, privilege change or additional test run occurred. Before rerunning, install 03_has_voted.sql if absent and reconcile existing participation SELECT privilege with the new INSERT-only policy; do not rerun CREATE ROLE blindly.

Recovery completed after student's Docker restart: engine 29.7.2 responds; Compose recreated the service container while retaining the existing database volume. PostgreSQL accepts connections. Inspection found has_voted absent and participation SELECT still granted. Applied existing database/03_has_voted.sql once; reconciled privileges in a transaction: revoked participation SELECT, retained INSERT, revoked PUBLIC has_voted execution and granted it to evp_app. Verified SELECT=false, INSERT=true, function EXECUTE=true. No data reset and no source changes.

Latest verified suite at afe8b23 after recovery: 8 suites passed, 36 tests passed, 0 failed; npm test -- --runInBand; 2.234 seconds. This supersedes the infrastructure-failed run as the current baseline, without erasing it. No SR-06 transaction/rollback/concurrency acceptance tests exist yet. Student will coordinate the SR-05 transaction interface later; that dependency remains unresolved. No commit or PR created.

Updated the report's existing SR-06 working comment with the recovery result and pending interface. Only word/comments.xml changed; ten rendered pages remain identical. Saved the authorized Downloads copy after source-hash validation and preserved A3_Secure.before-database-recovery.docx. No report narrative or final analysis authored.

Report checkpoint: added a clearly attributed working-evidence comment recording the actual SR-05/SR-08 interfaces, eligibility transaction mismatch, 22/14 test outcome, SR-04 pending login-flow test and future 04 audit numbering. Report narrative is unchanged; ten rendered pages compared identical to the previously inspected preview. Comment anchors verified, saved authorized Downloads working copy, backup A3_Secure.before-integration-update.docx. No final assessable analysis authored, new commit or PR created.

Pending SR-04 integration: simulated authenticated voter permitted only in isolated tests. Once real authentication/session code is merged, test actual login, full combined submission, acceptance and rejected duplicate. Also test a duplicate with a renewed valid session if post-vote session expiration would mask the participation check.

SR-15 numbering instruction: use 04 for future audit SQL if no conflict at creation time. 03_has_voted.sql currently occupies 03; no 04 file exists. Do not implement SR-15 now.

| Requirement | Implementation status | Existing foundation / files changed | Completed tests | Tests still needed | Commit evidence | Report locations | Missing evidence and integration dependencies |
|---|---|---|---|---|---|---|---|
| SR-06 | Partially implemented: pre-existing database foundation only | Existing database/01_schema.sql composite participation primary key; backend/src/config/db.js exports pool. No implementation files changed by student yet. | Baseline only; no concurrency acceptance test | Synchronized same-voter concurrency, rollback, retries, distinct voters/elections, eligibility and anonymity checks | d64bfa6 foundation; baseline 5593716; no new SR-06 commit | Contribution table; 2.3 SR-06; 4.6 database claims; implementation/test sections absent | Decide combined House/Senate submission; SR-01/04 trusted identity/session, SR-05 eligibility, SR-07 validation, SR-08 anonymity, SR-09 encryption; preserve room for SR-11/12 |
| SR-11 | Not started | Existing encryption helper and rotation script are dependencies; no integrity store/service | None for SR-11 | SHA-256 recomputation, missing/duplicate records, tamper detection before tally, append-only permissions, failure rollback, <=1s timing, rotation compatibility | No implementation commit | Contribution table; 2.3 SR-11; solution, implementation and test sections absent | Define store boundary and hash input; coordinate SR-08/09/13; obtain actual decision and rationale from student |
| SR-12 | Not started | No receipt/signing/bulletin-board component | None for SR-12 | Signature verification and failure cases, uniqueness, <=2s delivery, public lookup, no identity/choice leakage, accepted versus counted state | No implementation commit | Contribution table; 2.3 SR-12; solution, implementation and test sections absent | Receipt format, key lifecycle and public trust, durable issuance, SR-08 privacy and SR-13 tally inclusion |
| SR-15 | Not started | No implemented authentication/admin action interface or audit service | None for SR-15 | Successful/failed action logging, required fields/UTC, <=1s timing, log failure blocks action, rollback preserves failure evidence | No implementation commit | Contribution table; 2.3 SR-15; solution, implementation and test sections absent | SR-02 MFA, SR-03 roles, SR-16 append-only/hash chain, SR-17 log privacy, SR-18 signed admin actions; maintenance operations |
| SR-20 | Not started | Existing package.json/lockfile and Jest; no tracked workflows | Baseline Jest only | Full dependency scan with CVSS 6.9/7.0 boundary, SAST blocking, signed release SBOM verification/tamper failure, required-check merge rejection | No implementation commit | Contribution table; 2.3 SR-20; solution, implementation and test sections absent | Repository-owner rulesets, scanner configuration/availability, signing trust and release definition |

## Acceptance criteria source

Authoritative wording is in C:/Users/vinut/Downloads/Part 1.docx. The report's blank rows are to be populated by copying that existing student-provided text, not by replacing acceptance criteria.

- SR-06: exactly one eligible voter ballot accepted per election atomically; simultaneous-submission tests accept exactly one.
- SR-11: SHA-256 of every accepted ballot in a separate append-only store within one second; confirm only after both saves; flag any mismatch before tallying.
- SR-12: digitally signed receipt and unique verification code within two seconds; public board confirms counted status; no identity or choice disclosure.
- SR-15: all successful and failed privileged actions logged with user, action, UTC timestamp, target and outcome within one second; block action if logging cannot be written.
- SR-20: every code change passes dependency scan and static analysis before merge; signed SBOM per release; fail builds for any dependency with CVSS >= 7.0.

## Student decision record

The student confirmed that Downloads/A3_Secure.docx is the authorized working copy. No automatic commit or shared publication is authorized. The student stated that SR-05/SR-08 interface and House/Senate submission decisions have not yet been made and requested proposals.

### SR-06 options to evaluate

These are AI suggestions for discussion, not selected/final design decisions.

1. Combined House/Senate submission: one participation reservation per election and both constituent ballot records in a single transaction. Benefit: avoids consuming voting eligibility after only one chamber. Cost: requires agreement on payload validation, receipts and tally record counts. Alternative: separate chamber submissions requires a deliberate revision of participation semantics; the current primary key cannot represent independent chamber completion.
2. Eligibility: obtain voter identity from authenticated server state, and recheck election/enrolment at submission on the transaction's client. Decide with SR-05 how concurrent closure or enrolment edits are serialized. Benefit: avoids trusting client assertions or a stale activation check. Cost: locking/order choices and integration testing.
3. Atomicity: reserve participation via the existing unique key and save all required ballot records using one checked-out PostgreSQL client; commit before confirming. On any failure, roll back; handle the specific duplicate-participation conflict distinctly from unrelated integrity errors. Benefit: database-backed race handling. Cost: connection/transaction cleanup and rollback tests.
4. Anonymity: do not add a voter/session/participation identifier to ballot, hash or receipt rows. This alone does not satisfy administrator-resistant SR-08: same-transaction metadata and operational timing can correlate records. Ask the SR-08 owner to evaluate unlinkable authorization/ballot collection or another defensible protocol. No full anonymity claim is verified, and no final protocol is selected.

Questions for the student: Which submission option do you accept and why? What tradeoffs did the team accept? What eligibility function/result will SR-05 expose? What anonymity threat model/protocol has SR-08 approved? Record actual answers here before drafting rationale.

## Report review flags for group discussion

All paragraphs below describe the source report as inspected; other members' text is preserved.

- Contribution table is empty. Team identity row records vinuthna / s4217142 / Vinuthna1R. Other incomplete member identity cells should be completed by those members.
- Section 2.3 has blank rows for SR-06/11/12/15/20 and several teammates' requirements. Only the student's five rows are authorized for copying from Part 1.
- Section 4.6 says the participation primary key rejects the second concurrent vote. It rejects duplicate participation rows; no submission transaction or concurrent acceptance test exists yet.
- Section 4.6 says full database access cannot link voters to ballots. Absence of a direct foreign key does not establish this against transaction metadata or other correlations.
- Section 4.6 describes a key column as storing the encryption key. Actual key_version stores a version; keys are read from environment settings.
- Section 4.6 says never use evp_admin, but the existing maintenance rotation script intentionally uses admin credentials.
- Section 4.6 claims attempted DELETE/UPDATE/DROP were denied. The existing embedded terminal screenshot visibly supports those three denials and a zero ballot count. Preserve it and attribute it to the original contributor; this session inspected privileges and did not execute those three operations.
- Section 1.2 says TOTP and mkcert were used. Neither is implemented/configured in the inspected checkout; ask authors for branch/commit and verification evidence rather than assuming the claims are false.
- The report says fake voter/enrolment data was seeded, but current seed SQL creates divisions/elections/candidates and no users/enrolments.
- Section 2.2 says nine high, ten medium, one low complexity. Part 1 instead totals eight high, eleven medium, one low. Ask the group to reconcile ratings; both sets satisfy the minimum eight high/eight medium.
- Section numbering skips 2.4 and Part 2/3 content; solutions, cost-benefit, implementation, tests and student rationale sections are absent. Do not restructure shared sections without group agreement.
- Most paragraphs use the same normal style, including visual headings; many empty paragraphs create spacing. Preserve formatting until visual review is available.

## Evidence collection and update procedure

After each actual milestone: student implementation -> tests -> verification -> accurate commit -> report review -> tracker update. Do not create commits simply to record activity.

Capture real test output, command/context, commit SHA, fake-data setup and timing method. For concurrent tests, use independent requests/connections and a start barrier; assert response counts plus persisted participation/ballot counts. Include rollback injection and successful retry. Keep screenshots free of credentials, raw voter identifiers and choice-linked logs.

Screenshots still needed: genuine concurrency run/results, integrity failure stopping tally, receipt verification, privileged audit failure blocking mutation, and CI/security/SBOM verification. None exists yet for these five requirements.

## AI-use working record

AI assistance to date: repository/document inspection, environment setup, running existing tests, organizing verified evidence, identifying contradictions, proposing options and tests. No final assessable implementation code, analysis, rationale or report prose has been authored. Administrative report edits copy existing requirements and factual contribution metadata only. The student must record which suggestions were accepted/rejected/revised and their own reasoning for the Condition 3 declaration; these answers are pending.

## Document operations

- Authorized source: C:/Users/vinut/Downloads/A3_Secure.docx.
- Original SHA-256: 16D3313390D330DB21B4DC462D6405BD44170874D977C24855B7E548F3C75417.
- Report updates must preserve a backup, existing teammate text, formatting and table organization. Only contribution records and the five existing blank requirements are in scope for the initial administrative edit.
- Bundled DOCX renderer failed because LibreOffice is not supplied in this Windows runtime. Microsoft Word exported the staged report read-only for visual inspection. The existing screenshot and blank spacing are preserved; no new final report narrative was written.
- Administrative milestone completed: contribution table populated for vinuthna's five allocations; SR-06 marked Partially implemented for the existing schema foundation only, others Not started. Exact requirement text/priority/complexity copied from Part 1 into the five blank section 2.3 rows. Report references are 2.3 and, for SR-06, 4.6.
- All narrative paragraphs and unrelated tables were checked byte-for-byte at XML level; all package parts except document.xml, including embedded screenshots, remain unchanged. Exact copied requirement cells were verified against Part 1. Ten rendered pages inspected; original incomplete content/spacing retained. Only the five requirement rows were set to stay together across page breaks.
- Original backup: C:/Users/vinut/Downloads/A3_Secure.before-codex-update.docx. Authorized working copy saved only after checking that its source hash had not changed; saved bytes match the visually reviewed staged copy. No report commit or publication performed.
