# ZTA Testbed (thesis project)

One multi-tenant API on AWS with a switchable security mode, used to compare
security approaches on confidentiality, access control, complexity and cost.

| Mode | Status |
|---|---|
| baseline (Method 1) | Implemented |
| abac (Method 2) | Implemented |
| zta (Method 3) | Week 5 |

Modes that are not built yet return HTTP 501.

## Run it in AWS CloudShell (no local setup)

1. Start the Learner Lab, open the AWS console, check the region is us-east-1.
2. Open CloudShell (terminal icon in the top bar).
3. Actions > Upload file > choose `zta-testbed.zip`.
4. Unpack and enter the folder:
   python3 -m zipfile -e zta-testbed.zip .
   cd zta-testbed
5. Deploy (creates DynamoDB table, Lambda function, HTTP API):
   python3 deploy.py
6. Run the tests:
   python3 tests/run_tests.py
7. Switch to Method 2 (same resources, new code and mode):
   python3 deploy.py --mode abac
   python3 tests/run_tests.py
   Switch back any time with: python3 deploy.py --mode baseline
8. When finished for the day (optional, keeps the account clean):
   python3 teardown.py

Results are saved as CSV files in `results/`. Download them with
Actions > Download file before the session ends.

## Files

- `app/handler.py`     entry point, picks the mode from SECURITY_MODE
- `app/baseline.py`    Method 1 (shared API key, trusts the client)
- `app/abac.py`        Method 2 (signed token + attribute policy)
- `app/common.py`      code shared by all modes
- `app/jwt/`           PyJWT 2.10.1, bundled so Lambda needs no install
- `deploy.py`          creates and updates the AWS resources (safe to re-run)
- `teardown.py`        deletes them
- `tests/run_tests.py` cases C1-C5 and A1-A6, plus a latency run
- `docs/design-decisions.md`

## Notes

- Leak rate counts the four cross-tenant cases C2-C5. C1 is the control.
- Latency from CloudShell includes network time. Use the same place for every
  mode so the comparison stays fair.
- `config.json` (written by deploy.py) holds the API key and the token-signing
  secret. It is git-ignored. Never share it or screenshot it.
- Run the tests for each mode from the same place (CloudShell) so latency is comparable.
- Each run uses its own credentials per mode; the cases and pass criteria are identical.
