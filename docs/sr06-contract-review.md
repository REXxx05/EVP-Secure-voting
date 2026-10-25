# SR-06 submission contract review worksheet

Working prompts for the student, not final assessable API design or report content. Issue: https://github.com/REXxx05/EVP-Secure-voting/issues/9. Baseline: 6a59910; 5 suites / 18 tests passed. SR-06 acceptance remains unverified.

## Current integration checkpoint at 5c10c25

AI-assisted implementation now exists on codex/ai-assisted-sr06 at the student's explicit request. Earlier student-exercise/no-service wording below is historical. Service + unmounted route factory + 46 AI-generated tests are available; full current suite is 85 passing tests. See docs/ai-assisted-sr06.md for exact route, authentication, CSRF, validator and transactional invalidation contracts. Real SR-04/SR-07 production collaborators remain unavailable; isolated doubles are not production integration. Issue stays open.

This section supersedes earlier interface-gap notes below. Teammate PR #16 merged commit 50780a7 through merge 5c10c25f7e591eae46da1fb2e45cd9c005d69fa3. The existing feature branch was fast-forwarded without a new commit; documentation work was preserved. Current complete baseline: 8 suites and 39 tests passed, 0 failed, 4.046 seconds.

- checkEligibility(userId, electionId, options = {}) now accepts options.client and options.lock. For SR-06, pass the acquired transaction client and lock: true after BEGIN. It executes all reads using that client and uses FOR SHARE on election and enrolment rows, in that order. Existing middleware calls without options remain supported. Do not duplicate eligibility queries or use the prior pool-only workaround.
- The new tests verify eligibility with a transaction client, an administrator's election closure timing out while the vote holds the lock, and rejection of lock:true without a supplied client. They do not establish SR-06 atomic acceptance or concurrent-duplicate behavior.
- The function expects the caller to have begun a real transaction; receiving a client alone does not establish that. Time-of-eligibility versus eventual commit semantics and concurrent changes to users.role still need agreement if those are in the threat model. The user-role query is not row-locked. Keep transactions short, use a consistent lock order, and do not claim the comments prove deadlocks impossible across the whole application.
- saveBallotAnonymously(client, ballot) remains the actual SR-08 write interface; call once for each chamber through the same client with no voter identifier. Use plain participation INSERT without RETURNING or direct SELECT under the current limited app privileges.
- SR-04 is not merged into main. Remote branch origin/dhanush/sr-01-03-04-07-19 contains session migration/model and authentication-related work, but no public login route was identified. It was inspected as unmerged work and was not merged into this branch. Real-login-to-vote end-to-end test remains pending; isolated simulated identity is not production authentication.
- No ballotSubmission.js or SR-06 tests exist yet. Next student action: implement the transaction-owning service using the real eligibility options and real anonymous storage function, then bring the diff for review and execute the rollback/concurrency scenarios below. Existing 39 passing tests are baseline only.

Issue workflow: docs/github-issue-inventory.md and .json verify exactly one issue for each of twenty SRs. Issues must remain open until acceptance tests, genuine commit evidence, documentation and team review establish completion; no automatic closure from commits.

## Latest teammate interfaces at afe8b23

This section supersedes earlier statements below that all collaborator services are absent. Earlier baseline results remain historical evidence, not the current run.

- SR-05 is merged through PR #11. backend/src/services/eligibilityService.js exports checkEligibility(userId, electionId). Success is { eligible: true, electionId, divisionId }; denial is { eligible: false, reason }, with invalid_input, not_found, not_a_voter, election_not_open or not_enrolled. It checks stored user role, election status/dates, and enrolment; do not duplicate these checks in a separate production eligibility implementation.
- backend/src/middleware/requireEligiblevoter.js (preserve its exact filename casing) exports requireEligibleVoter. It expects req.user.id, reads req.params.electionId, responds 401 without req.user and 403 on eligibility denial, and attaches req.eligibility = { electionId, divisionId }. It is not login/session middleware and is not yet wired into a ballot route.
- Critical remaining mismatch: checkEligibility uses db.query/pool.query internally and accepts no transaction client. Calling it after BEGIN does not bring its reads into the SR-06 transaction. Ask the SR-05 owner to support a transaction query executor while preserving existing callers and agreeing locking/consistency behavior. Do not silently pass an ignored third argument, duplicate the logic, or declare full same-client integration complete.
- SR-08 is merged through PR #15. backend/src/services/ballotStorage.js exports saveBallotAnonymously(client, { electionId, divisionId, ballotType, ballotData }). Call once for house and once for senate using exactly the same SR-06 client. It encrypts with the existing SR-09 helper, inserts one row, and returns a UUID. It does not commit. Do not pass voter identity or return an identity-linked pair of UUIDs in the public response.
- SR-08 storage performs basic shape checks only; it does not implement SR-07 voting-rule validation. Keep that dependency explicit.
- database/03_has_voted.sql adds has_voted(userId, electionId). The latest role script intends INSERT-only access on voter_participation; use plain INSERT without RETURNING or a participation-table pre-read. Existing installations retain old SELECT grants until explicitly revoked: removing a GRANT from the script does not revoke an existing privilege. Test count assertions should use the test-only admin connection, not broaden app privileges.
- SR-04 is explicitly incomplete. Simulated req.user belongs only in isolated tests and must be labelled simulated. Pending end-to-end requirement: real login/session -> complete House/Senate submission -> accepted response -> duplicate attempt denied. If post-vote session invalidation denies the immediate duplicate, also exercise a renewed valid session to distinguish authentication rejection from the SR-06 participation conflict.
- A future SR-15 audit schema/migration must use the 04 prefix if still free. Current top-level SQL files are 01_schema.sql, 02_seed.sql and 03_has_voted.sql. Recheck before creating any file; SR-15 implementation is out of scope.

## Confirmed responsibilities

- One submission includes House and Senate. Both save or neither saves.
- SR-01/04 supply authenticated voter identity and session handling. SR-05 supplies eligibility, not login.
- SR-08 owns anonymous storage. SR-06 owns participation uniqueness and atomic acceptance.
- Existing participation primary key is (user_id, election_id). Ballot rows have no voter ID.
- Middleware, routes, models and services currently contain only placeholders. No teammate function name or response shape below should be treated as implemented.

## First exercise: write your contract decisions

The student supplied the six proposals below for review. These are proposed decisions, not final rationale. Complete the remaining Student answer cells in your own words; do not treat suggested interface names or response formats as teammate implementations.

## Student-supplied proposals and schema review

1. POST /api/elections/:electionId/ballots accepts House and Senate together. The current ballots table represents this as two rows distinguished by ballot_type, not one combined row. One participation reservation covers the complete submission. No submission-group identifier exists; do not add an identity-linked join to manufacture one.
2. Return 201 only after successful commit; 409 only for confirmed duplicate participation. The composite participation primary key supports that distinction, but unrelated unique violations must retain their own meaning. Exact public error fields remain open.
3. Identity comes exclusively from trusted SR-01/04 state. users has role and identity columns but the schema is not an authentication/session implementation. The actual request identity property is not available yet.
4. SR-05 verifies election/division eligibility. enrolments has one row per user/election, but participation references users/elections separately; it has no foreign key to enrolments. Ballots also reference election/division independently. None of these constraints substitutes for SR-05. Agree consistency rules when enrolments or election state change during a submission.
5. SR-08 writes through the same checked-out PostgreSQL client and does not commit. backend/src/config/db.js exports pool as well as a query helper; the query helper uses pool.query and is unsuitable for maintaining the whole transaction across separate calls. The storage interface does not yet exist.
6. Senate failure after participation/House writes rolls everything back; no new submission records remain and retry is possible after a confirmed rollback. This requires every write to use that client, errors to propagate, and response success to wait for commit. Do not claim rollback is certain after an ambiguous connection failure during COMMIT.

The schema does not enforce exactly one House and one Senate row for a submission. Their presence is an orchestration/storage contract invariant that must be tested. The ballot_type check only restricts allowed values. The app role can SELECT/INSERT ballots and participation, so ordinary rollback needs no DELETE privilege. Use isolated fixtures rather than identifying ballots through voter identity to count test results.

Anonymity limitation: absence of user_id on ballots meets a structural boundary but does not prove SR-08 against database transaction metadata/timing correlation. Record this dependency explicitly and ask the SR-08 owner to approve the same-transaction integration. SR-06 must not silently claim full SR-08 compliance.

| Contract point | Candidate to evaluate / review question | Student answer and reason |
|---|---|---|
| Endpoint | POST /api/elections/:electionId/ballots | Student-proposed; rationale pending |
| Request | Election ID in the route; one House selection payload and one Senate selection payload. Exact selection formats must match the SR-07 owner's validator. What are those formats? | Pending |
| Trusted identity | Exclusively trusted SR-01/04 state; actual identity property/interface still needed | Student-proposed; integration pending |
| Division | SR-05 verifies requested election/correct division; output and concurrent-change policy still needed | Student-proposed; integration pending |
| Success | HTTP 201 only after commit; minimal response fields still needed, without choice echo or voter/ballot association | Student-proposed; body pending |
| Duplicate | HTTP 409 for confirmed participation conflict only; public error code/body still needed | Student-proposed; body pending |
| Authentication / role | Consider HTTP 401 for no valid session and 403 for a disallowed role. What does the existing team's session convention require? | Pending |
| Eligibility / closed election | Agree response semantics with SR-05. Neither outcome may write participation or ballots. | Pending |
| Malformed / incomplete selections | Missing either chamber or invalid SR-07 selections must not be accepted. Agree 400 versus 422 and stable error fields with frontend owner. | Pending |
| Dependencies unavailable | Fail closed in production; inject doubles only in isolated tests. What unavailable-dependency response will be used during integration? | Pending |
| Transaction | One client/transaction including SR-08 storage; storage must not commit independently. How will every dependency accept the same transaction context? | Student-proposed; interface pending |
| Retry and commit uncertainty | A lost response after a committed submission must not permit another vote. Distinguish definite rollback from uncertain commit; do not report a guaranteed rollback when commit outcome is unknown. How should clients recover? | Pending |
| Session invalidation | SR-04 owns post-submission expiration. How will expiration failure after a committed ballot be reported without pretending the vote rolled back? | Pending |

## Teammate interface questions to resolve

1. SR-01/04: authenticated identity shape, voter-role check, session validity and post-commit invalidation behavior.
2. SR-05: eligibility input/output, election/division checks, transaction-client participation, and locking rules for concurrent election closure/enrolment changes. A check at ballot activation alone can be stale at submission.
3. SR-07: exact House/Senate payload structures and server validation contract. Do not implement substitute production rules or accept arbitrary selections.
4. SR-08: a storage operation that writes both anonymous encrypted ballot records using the caller's transaction client and never commits independently. It must not receive/store voter or session identity as ballot metadata. Agree rollback and serialization behavior. Transaction metadata/timing correlation remains an SR-08 integration concern; no full anonymity claim is established by absence of user_id.
5. SR-09 existing helper: use the team's encryption/key-version convention through the agreed storage boundary; do not add plaintext ballot storage as a fallback.

## Explain the race before writing implementation

Write what the losing concurrent request observes when the winning transaction commits, and what it observes when the first transaction rolls back. Explain why SELECT-then-INSERT without database uniqueness is insufficient. Explain why individual pool.query calls do not guarantee one shared transaction client.

Student explanation: Pending.

## First implementation checkpoint for the student

Scope: write the transaction-owning service unit yourself, before wiring a public route to absent dependencies. Candidate location is backend/src/services/ballotSubmission.js; this file is not created by the worksheet. Export/interface shape is your decision after checking teammate contracts. Do not edit the schema or db.js simply to add a transaction service.

Define the service inputs and collaborator contracts in your own words first: trusted identity/election, validated selections, eligibility check, and anonymous-storage operation. Keep identity out of the anonymous-storage inputs. Transaction client is infrastructure context, not ballot metadata. Production wiring must use actual collaborators or fail closed; doubles belong only in isolated tests.

Review your implementation for these properties:

- The service owns one checked-out client and its lifecycle. It never builds a multi-statement transaction from independent pool.query calls.
- Acquisition failure does not attempt rollback/release on an unacquired client. After acquisition, release occurs on every path. A broken connection is discarded rather than returned as healthy; review the node-postgres release contract before implementing this case.
- Eligibility is checked consistently with the team-agreed election/enrolment locking policy. Ballot validation is not replaced by a truthy/nonempty payload check.
- Participation insertion is the authoritative concurrency gate. A preliminary read can improve messaging, but cannot establish exclusivity.
- Both chamber writes belong to the same transaction. The SR-08 function propagates failures, never opens its own independent transaction and never swallows a failed chamber write.
- Only the specific participation uniqueness conflict maps to duplicate. Agree whether to inspect the actual constraint name after a plain insert or use a targeted ON CONFLICT result; do not blanket-map SQLSTATE 23505 from any table.
- No success is returned before COMMIT resolves. A failure before commit rolls back; a rollback error does not hide the original failure or cause a success response.
- Keep database details, ballot choices and raw identity out of public error bodies and diagnostics produced by your unit.

Do not wire a public unauthenticated endpoint as a shortcut to exercise the service. Review the service and isolated tests first, then integrate real SR-01/04/05/07/08 functions when available.

## Rollback and concurrency test exercise

Write the tests yourself. Suggested new test locations are backend/tests/unit/ballotSubmission.test.js and backend/tests/integration/ballotSubmission.test.js; neither exists yet.

1. Unit sequencing: use isolated collaborators to record transaction/storage call order. Hold COMMIT unresolved and verify the submission has not resolved successfully. Reject COMMIT and check that 201 cannot be produced. This tests orchestration, not PostgreSQL atomicity.
2. Rollback with PostgreSQL: create a dedicated fake election/enrolment/user fixture. Use the real transaction service/client and real participation/House writes. Inject a test-only Senate failure after the House insert completes. Inspect state through a separate connection after failure: zero participation for the fixture voter/election, zero House and zero Senate rows for the isolated election. Remove the injected failure and retry; expect one participation and one row per chamber. A fake storage adapter proves the SR-06 transaction contract, not the absent production SR-08 implementation.
3. Concurrent winner commits: use two independent submissions/connections for the same fixture voter/election. Hold the first transaction open after participation insert. Start the second while the first is open, then release the first to commit. Expect one acceptance and one duplicate outcome, with one complete persisted ballot pair. Use bounded synchronization and confirm the second insert was actually in flight/blocked; do not rely on an arbitrary sleep or Promise.all alone as race evidence.
4. Concurrent first attempt rolls back: hold the first after participation, start the competing submission, then cause the first's Senate write to fail. The competing insert should be able to proceed after rollback and create one complete pair. An uncommitted reservation must not be reported as a permanent duplicate.
5. Broaden only after the above: independent voters/elections; missing chamber; ineligible/missing identity; unrelated uniqueness failure; database acquisition/rollback failure; no identity fields in storage inputs. Route tests for agreed HTTP statuses come after real middleware integration.

Do not use the app user's unavailable DELETE permission for fixture cleanup. Use a dedicated disposable database or an explicitly test-only setup/cleanup connection, preserve shared local seed data, and never run a volume reset as automatic cleanup. Test writes inside an outer transaction do not exercise real independent-connection commits unless the fixture visibility and transaction design explicitly support that.

Checkpoint evidence to bring for review: your new service diff, your collaborator contracts, unit output, and the real-database rollback/concurrency output with before/after fixture counts. Do not put voter-to-ballot IDs in production logs as test evidence.

## Test cases to implement yourself after contract review

| Scenario | Required observation |
|---|---|
| One eligible complete submission | One participation row and exactly one House plus one Senate record in isolated fake-data fixtures; success only after commit |
| Same voter/election concurrent requests | Independent connections and synchronized start; exactly one successful acceptance and one complete persisted ballot set; pool size is ten, so use a concurrency barrier that does not deadlock waiting for more than ten checked-out clients |
| House write succeeds, Senate write fails | No participation, House or Senate record remains for the isolated submission; a later valid retry succeeds |
| Participation reservation fails | No new ballot records are stored |
| Invalid/ineligible/unauthenticated | No writes; expected agreed response |
| Different voters / different elections | Legitimate independent submissions succeed without false duplicates |
| Missing chamber | No partial acceptance or participation consumption |
| Storage fails / unavailable dependency | No success response or production bypass |
| Identity and anonymous storage boundary | Ballot persistence parameters/columns contain no voter identity; inspect integration separately for SR-08 metadata correlations |

Mocked service tests establish behavior of your unit only. Real PostgreSQL tests are required to establish uniqueness races, rollback, and database state. No tests in this worksheet have been executed.

## Evidence for your own report notes

Record the chosen contract and your reasoning after you decide. Then record actual changed files, commands, test output, fixture counts, issue reference and real commit hash. Current verified evidence is baseline only. Screenshots of SR-06 concurrency/rollback tests are still needed. No SR-06 implementation commit exists.


## Status update 2026-10-26

The service and an unmounted route factory are merged (PR #26). The submission transaction now also records SR-11 integrity hashes and an SR-12 receipt before COMMIT; a successful submission returns { accepted: true, receipt }. SR-04 and SR-07 are still unmerged, so the real login -> vote -> duplicate E2E tests remain test.todo in backend/tests/integration/e2eVoting.pending.test.js. Contract choices above are unchanged.
