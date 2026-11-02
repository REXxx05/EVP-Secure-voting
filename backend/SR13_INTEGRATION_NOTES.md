# SR-13 — Ballot Reconciliation Integration Notes

## Purpose

SR-13 verifies that accepted voting submissions, stored ballots,
ballot integrity hashes, receipts, and verified tally inputs agree
before election results can be released.

## Main Service

File: `src/services/ballotReconciliation.js`

Function:

`reconcileElection(electionId)`

## Preconditions

- The election must exist.
- The election must be closed.
- PostgreSQL must be available.
- The SR-13 database migration must have been applied.

## Expected Counts

Each accepted voting submission produces:

- 1 House ballot
- 1 Senate ballot
- 2 ballot integrity hashes
- 1 bulletin-board receipt

The service verifies these relationships.

## Successful Reconciliation

The function returns an object containing:

- `electionId`
- `ok: true`
- `counts`
- `reason: null`
- `ballots`

The `ballots` property contains verified, decrypted ballot data
for internal processing only.

It must never be returned through a public API.

## Failed Reconciliation

The service throws a `ReconciliationError`.

For detected count or integrity discrepancies, it records an
entry in `election_security_alerts`.

The publication workflow must reject the operation whenever
reconciliation throws an error.

## Required SR-14 Integration

Before publishing election results:

1. Confirm the election is closed.
2. Perform SR-13 reconciliation.
3. Calculate the actual House and Senate tallies from the verified ballots.
4. Confirm the tally includes every verified ballot exactly once.
5. Prevent publication if any reconciliation or tally check fails.
6. Ensure the verified data cannot change between reconciliation
   and publication.

The current SR-13 service does not itself publish results.

## Security Requirements

- Never expose voter identities.
- Never include decrypted ballot selections in auditor alerts.
- Never expose `result.ballots` through public endpoints.
- Do not bypass reconciliation when publishing results.
- Do not reuse an outdated reconciliation result.
- Restrict auditor alert access to authorised personnel.

## Testing

Unit tests:

`npm test -- --runInBand ballotReconciliation`

PostgreSQL integration tests:

`npm test -- --runInBand tests/integration/ballotReconciliation.test.js`

Last verified results:

- 13 SR-13 unit tests passed.
- 4 SR-13 PostgreSQL integration tests passed.
- 38 backend test suites passed.
- 314 tests passed overall.

## Outstanding Work

- Actual tally-output reconciliation.
- Integration with SR-14 publication.
- Authorised auditor notification or alert retrieval.
- End-to-end publication blocking tests.