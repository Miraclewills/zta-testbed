# Design decisions

## Data
- Table `zta-testbed-records`, partition key `record_id` (string).
- Fields: `record_id`, `tenant_id`, `content`.
- Two tenants: `tenant-a`, `tenant-b`. Five records each (A-001..A-005, B-001..B-005).

## Endpoints
- GET  /health         status and active mode (no key)
- GET  /records/{id}   read one record
- GET  /records        list the calling tenant's records
- POST /records        write a record
- POST /batch          read several records by id (max 25)

## Method 1: baseline (implemented)
- One shared API key (header `x-api-key`), checked inside the Lambda function.
- The tenant is whatever the client sends in `x-tenant-id`.
- Reading a single record or a batch does not check who owns the record.
- There are no tokens, roles or expiry.

## Method 2: ABAC (implemented)
- Token (`Authorization: Bearer`) is a JWT signed HS256 with PyJWT, carrying
  `tenant_id`, `role` (reader or writer) and `exp`. Cognito is not on the lab list,
  so the test harness mints tokens itself.
- The tenant comes from the token only. A client-sent `x-tenant-id` or body
  `tenant_id` is ignored.
- Policy (in `abac.py`, deny by default): a request is allowed only if the token's
  tenant equals the record's tenant AND a rule grants the action to the role.
  Readers: read, list, batch read. Writers: those plus write.
- Checked inside the API, one policy check per request. No separate authoriser and
  no decision log (those are Method 3).
- Batch requests are checked per record, not once per request.
- Writes use a conditional put so a tenant cannot overwrite another tenant's record.
- Accepted algorithm is fixed to HS256 (rejects `alg: none`); `exp` is required.
- Cross-tenant reads return 403 while missing records return 404, which reveals
  that an ID exists. Compare with Method 3.
- PyJWT is bundled in `app/jwt/` because Lambda does not provide it.

## Method 3 (planned)
- Adds a Lambda authoriser on every request with caching off, tenant and role
  checks, per-tenant keys and a decision log.

## Changes from the Week 1 design document
- API Gateway HTTP API instead of REST API (one-call setup). The shared-key
  check therefore lives in the Lambda code rather than at the gateway.
  Confirm this is acceptable for the baseline.
- All Lambda functions run as LabRole (IAM roles cannot be created in the lab),
  so tenant isolation cannot rely on separate IAM roles. State this as a limitation.

## Known gaps and extra cases to consider
- The baseline lets a tenant overwrite another tenant's record by ID. The 11-case
  suite does not test this. Candidate extra case C6 (write across tenants); ask
  the supervisor before changing the suite, because it must be run on all methods.
- The test suite is the author's own. Methods were also attacked with extra checks
  (unsigned token, wrong secret, role header, overwrite, body tenant) during build.
