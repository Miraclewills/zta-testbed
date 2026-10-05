"""Multi-tenant testbed API: one codebase, switchable security mode.

SECURITY_MODE selects how requests are secured:
  baseline  - Method 1: shared API key, trusts the client (baseline.py)
  abac      - Method 2: signed tokens + attribute-based policy (abac.py)
  zta       - Method 3: Zero Trust model (Week 5)

Routes:
  GET  /health            -> status and active mode (no credentials needed)
  GET  /records/{id}      -> read one record
  GET  /records           -> list the calling tenant's records
  POST /records           -> write a record
  POST /batch             -> read several records by id
"""
import abac
import baseline
from common import MODE, parse_request, respond

MODES = {"baseline": baseline.handle, "abac": abac.handle}


def lambda_handler(event, context):
    try:
        method, parts, headers, data = parse_request(event)
    except (ValueError, KeyError):
        return respond(400, {"error": "malformed request"})

    if method == "GET" and parts == ["health"]:
        return respond(200, {"status": "ok", "mode": MODE})

    mode_handler = MODES.get(MODE)
    if mode_handler is None:
        return respond(501, {"error": "mode '%s' is not implemented yet" % MODE})
    return mode_handler(method, parts, headers, data)
