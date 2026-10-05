"""Run the testbed test cases against the deployed API and save results to CSV.

    python3 tests/run_tests.py             # test cases + 50-request latency run
    python3 tests/run_tests.py --latency 0 # test cases only

The same cases (C1-C5 confidentiality, A1-A6 access control) run against every
mode. Only the way credentials are built differs per mode:
  baseline : shared API key + a tenant header the client chooses
  abac     : signed token carrying tenant_id and role
Cases a mode has no mechanism for are recorded as N/A or as a false allow.
"""
import argparse
import csv
import json
import os
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "app"))  # bundled PyJWT, used only to mint test tokens


def load_config():
    with open(os.path.join(ROOT, "config.json")) as f:
        return json.load(f)


def call(cfg, method, path, headers=None, body=None):
    url = cfg["api_url"].rstrip("/") + path
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            status, raw = r.status, r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read().decode("utf-8")
    elapsed_ms = (time.perf_counter() - start) * 1000
    try:
        payload = json.loads(raw)
    except ValueError:
        payload = raw
    return status, payload, elapsed_ms


def foreign_records(payload, own_tenant):
    """Return ids of any record in the response that belongs to another tenant."""
    found = []

    def walk(x):
        if isinstance(x, dict):
            if "tenant_id" in x and x["tenant_id"] != own_tenant:
                found.append(x.get("record_id"))
            for v in x.values():
                walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)

    walk(payload)
    return found


# ---------------------------------------------------------------------------
# Credential builders
# ---------------------------------------------------------------------------
def make_token(cfg, tenant, role="reader", expires_in=300, secret=None):
    import jwt
    claims = {"role": role, "exp": int(time.time()) + expires_in}
    if tenant:
        claims["tenant_id"] = tenant
    return jwt.encode(claims, secret or cfg["jwt_secret"], algorithm="HS256")


def tamper(token):
    """Change the tenant inside a valid token without re-signing it."""
    import base64
    head, payload, sig = token.split(".")
    pad = "=" * (-len(payload) % 4)
    claims = json.loads(base64.urlsafe_b64decode(payload + pad))
    claims["tenant_id"] = "tenant-b"
    new = base64.urlsafe_b64encode(json.dumps(claims).encode()).decode().rstrip("=")
    return ".".join([head, new, sig])


def creds(mode, cfg, tenant, role="reader", claimed_tenant=None):
    """Headers for a caller who really is `tenant`; claimed_tenant simulates a lying client."""
    if mode == "baseline":
        return {"x-api-key": cfg["api_key"], "x-tenant-id": claimed_tenant or tenant,
                "x-role": role}
    if mode == "abac":
        h = {"authorization": "Bearer " + make_token(cfg, tenant, role)}
        if claimed_tenant:
            h["x-tenant-id"] = claimed_tenant
        return h
    raise SystemExit("No test credentials defined for mode '%s' yet." % mode)


def bad_credentials(mode, cfg, kind):
    """Credentials that should be refused: 'expired', 'tampered', 'none', 'no_tenant'."""
    if mode == "baseline":
        if kind == "expired":
            return None  # baseline has no tokens
        if kind == "tampered":
            return {"x-api-key": "wrong-key", "x-tenant-id": "tenant-a"}
        if kind == "none":
            return {"x-tenant-id": "tenant-a"}
        if kind == "no_tenant":
            return {"x-api-key": cfg["api_key"]}
    if mode == "abac":
        if kind == "expired":
            return {"authorization": "Bearer " + make_token(cfg, "tenant-a", expires_in=-60)}
        if kind == "tampered":
            return {"authorization": "Bearer " + tamper(make_token(cfg, "tenant-a"))}
        if kind == "none":
            return {}
        if kind == "no_tenant":
            return {"authorization": "Bearer " + make_token(cfg, None)}
    raise SystemExit("Unknown credential kind '%s' for mode '%s'" % (kind, mode))


# ---------------------------------------------------------------------------
# Test cases
# ---------------------------------------------------------------------------
def run_cases(mode, cfg):
    a = creds(mode, cfg, "tenant-a", "reader")
    results = []

    def add(case_id, desc, status, leak, correct, note):
        results.append({"case": case_id, "description": desc, "status": status,
                        "leak": leak, "correct": correct, "note": note})

    # C1: own record (control)
    s, p, _ = call(cfg, "GET", "/records/A-001", a)
    ok = s == 200 and isinstance(p, dict) and p.get("tenant_id") == "tenant-a"
    add("C1", "Tenant A reads its own record (control)", s, False, ok, "allowed" if ok else "unexpected result")

    # C2: tenant A reads tenant B's record by id
    s, p, _ = call(cfg, "GET", "/records/B-001", a)
    leaked = s == 200 and bool(foreign_records(p, "tenant-a"))
    add("C2", "Tenant A reads Tenant B's record by ID", s, leaked, not leaked,
        "LEAKED tenant-b data" if leaked else "denied")

    # C3: list as tenant A
    s, p, _ = call(cfg, "GET", "/records", a)
    ids = foreign_records(p, "tenant-a")
    add("C3", "Tenant A lists records with no filter", s, bool(ids), s == 200 and not ids,
        "LEAKED %s" % ids if ids else "only tenant-a records")

    # C4: tenant A changes the tenant ID in the request
    s, p, _ = call(cfg, "GET", "/records", creds(mode, cfg, "tenant-a", "reader", claimed_tenant="tenant-b"))
    ids = foreign_records(p, "tenant-a")
    add("C4", "Tenant A changes the tenant ID in the request", s, bool(ids), not ids,
        "LEAKED %d tenant-b records" % len(ids) if ids else "denied or ignored")

    # C5: batch mixing tenants
    s, p, _ = call(cfg, "POST", "/batch", a, {"ids": ["A-001", "B-001", "B-002"]})
    ids = foreign_records(p, "tenant-a")
    add("C5", "Batch request mixing Tenant A and Tenant B IDs", s, bool(ids), not ids,
        "LEAKED %s" % ids if ids else "tenant-b items denied")

    # A1: valid credentials, permitted action
    s, _, _ = call(cfg, "GET", "/records/A-001", a)
    add("A1", "Valid credentials, permitted action", s, False, s == 200, "allowed" if s == 200 else "wrongly denied")

    # A2: expired token
    h = bad_credentials(mode, cfg, "expired")
    if h is None:
        add("A2", "Expired token", "n/a", False, None, "N/A: this mode has no tokens")
    else:
        s, _, _ = call(cfg, "GET", "/records/A-001", h)
        add("A2", "Expired token", s, False, s in (401, 403), "denied" if s in (401, 403) else "FALSE ALLOW")

    # A3: tampered credential
    s, _, _ = call(cfg, "GET", "/records/A-001", bad_credentials(mode, cfg, "tampered"))
    add("A3", "Tampered credential", s, False, s in (401, 403), "denied" if s in (401, 403) else "FALSE ALLOW")

    # A4: no credential
    s, _, _ = call(cfg, "GET", "/records/A-001", bad_credentials(mode, cfg, "none"))
    add("A4", "No credential", s, False, s in (401, 403), "denied" if s in (401, 403) else "FALSE ALLOW")

    # A5: read-only role attempts a write
    s, _, _ = call(cfg, "POST", "/records", creds(mode, cfg, "tenant-a", "reader"),
                   {"record_id": "A-WRITE-TEST", "content": "write by read-only role"})
    allowed = s in (200, 201)
    add("A5", "Read-only role attempts a write", s, False, not allowed,
        "FALSE ALLOW (write went through)" if allowed else "denied")

    # A6: credential missing the tenant attribute
    s, _, _ = call(cfg, "GET", "/records", bad_credentials(mode, cfg, "no_tenant"))
    add("A6", "Credential missing the tenant attribute", s, False, s in (400, 401, 403),
        "denied" if s in (400, 401, 403) else "FALSE ALLOW")

    return results


def run_sanity(mode, cfg):
    """Not scored: guards against a mode that passes by denying everything."""
    s, _, _ = call(cfg, "POST", "/records", creds(mode, cfg, "tenant-a", "writer"),
                   {"record_id": "A-SANITY-WRITE", "content": "write by writer role"})
    return [("S1", "Writer role writes its own record (should be allowed)", s, s in (200, 201))]


def run_latency(mode, cfg, n):
    headers = creds(mode, cfg, "tenant-a", "reader")
    call(cfg, "GET", "/records/A-001", headers)  # warm-up, not counted
    times = []
    for _ in range(n):
        # fresh token each time so the cost of signing is not hidden in a reused header
        _, _, ms = call(cfg, "GET", "/records/A-001", creds(mode, cfg, "tenant-a", "reader"))
        times.append(ms)
    times.sort()
    return {"n": n, "median_ms": statistics.median(times),
            "p95_ms": times[min(n - 1, int(round(0.95 * n)) - 1)]}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--latency", type=int, default=50, help="sequential requests for the latency run (0 to skip)")
    args = parser.parse_args()

    cfg = load_config()
    _, health, _ = call(cfg, "GET", "/health")
    mode = health.get("mode", "unknown") if isinstance(health, dict) else "unknown"
    print("Testing mode: %s   API: %s\n" % (mode, cfg["api_url"]))

    results = run_cases(mode, cfg)
    print("%-4s %-52s %-6s %s" % ("ID", "Case", "HTTP", "Result"))
    print("-" * 100)
    for r in results:
        print("%-4s %-52s %-6s %s" % (r["case"], r["description"], r["status"], r["note"]))

    attacks = [r for r in results if r["case"] in ("C2", "C3", "C4", "C5")]
    leaks = sum(1 for r in attacks if r["leak"])
    decided = [r for r in results if r["case"].startswith("A") and r["correct"] is not None]
    right = sum(1 for r in decided if r["correct"])
    na = len([r for r in results if r["case"].startswith("A") and r["correct"] is None])
    print()
    print("Leak rate (C2-C5):            %d/%d = %.0f%%" % (leaks, len(attacks), 100.0 * leaks / len(attacks)))
    print("Correct access decisions:     %d/%d = %.0f%%  (%d not applicable)" % (right, len(decided), 100.0 * right / len(decided), na))

    sanity = run_sanity(mode, cfg)
    print("\nSanity check (not scored):")
    for sid, desc, status, ok in sanity:
        print("  %s %s -> HTTP %s %s" % (sid, desc, status, "OK" if ok else "PROBLEM"))

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    out_dir = os.path.join(ROOT, "results")
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, "%s_cases_%s.csv" % (mode, stamp))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mode", "case", "description", "http_status", "leak", "correct", "note"])
        for r in results:
            w.writerow([mode, r["case"], r["description"], r["status"], r["leak"], r["correct"], r["note"]])
    print("Saved:", path)

    if args.latency > 0:
        lat = run_latency(mode, cfg, args.latency)
        print("\nLatency over %d sequential requests (includes network from where you run this):" % lat["n"])
        print("  median %.0f ms, p95 %.0f ms" % (lat["median_ms"], lat["p95_ms"]))
        lpath = os.path.join(out_dir, "%s_latency_%s.csv" % (mode, stamp))
        with open(lpath, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["mode", "n", "median_ms", "p95_ms"])
            w.writerow([mode, lat["n"], round(lat["median_ms"], 1), round(lat["p95_ms"], 1)])
        print("Saved:", lpath)


if __name__ == "__main__":
    main()
