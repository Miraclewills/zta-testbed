"""Deploy the testbed to AWS: DynamoDB table + Lambda + HTTP API.

Run in AWS CloudShell (or anywhere with Learner Lab credentials):
    python3 deploy.py                 # deploys the baseline
    python3 deploy.py --mode abac     # switches the same deployment to Method 2

Safe to re-run: existing resources are updated, not duplicated.
"""
import argparse
import io
import json
import os
import secrets
import time
import urllib.error
import urllib.request
import zipfile

import boto3
from botocore.exceptions import ClientError

ROOT = os.path.dirname(os.path.abspath(__file__))
TABLE_NAME = "zta-testbed-records"
FUNCTION_NAME = "zta-testbed-api"
API_NAME = "zta-testbed-http-api"
CONFIG_PATH = os.path.join(ROOT, "config.json")


def seed_items():
    """Two tenants, five records each."""
    items = []
    for letter in ("A", "B"):
        for i in range(1, 6):
            items.append({
                "record_id": "%s-%03d" % (letter, i),
                "tenant_id": "tenant-%s" % letter.lower(),
                "content": "Tenant %s confidential record %d" % (letter, i),
            })
    return items


def seed_table(table):
    with table.batch_writer() as batch:
        for item in seed_items():
            batch.put_item(Item=item)


def build_zip():
    """Zip everything in app/ (handler, modes, bundled PyJWT) with files at the zip root."""
    app_dir = os.path.join(ROOT, "app")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for folder, dirs, files in os.walk(app_dir):
            dirs[:] = [d for d in dirs if d != "__pycache__"]
            for name in files:
                if name.endswith(".pyc"):
                    continue
                full = os.path.join(folder, name)
                z.write(full, os.path.relpath(full, app_dir))
    return buf.getvalue()


def ensure_table(ddb):
    try:
        ddb.create_table(
            TableName=TABLE_NAME,
            KeySchema=[{"AttributeName": "record_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "record_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        print("Created DynamoDB table:", TABLE_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceInUseException":
            raise
        print("DynamoDB table already exists:", TABLE_NAME)
    ddb.get_waiter("table_exists").wait(TableName=TABLE_NAME)


def ensure_function(lam, role_arn, env):
    code = build_zip()
    try:
        fn = lam.create_function(
            FunctionName=FUNCTION_NAME,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.lambda_handler",
            Code={"ZipFile": code},
            Timeout=10,
            MemorySize=256,
            Environment={"Variables": env},
        )
        print("Created Lambda function:", FUNCTION_NAME)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            raise
        lam.update_function_code(FunctionName=FUNCTION_NAME, ZipFile=code)
        lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)
        fn = lam.update_function_configuration(
            FunctionName=FUNCTION_NAME, Environment={"Variables": env}
        )
        print("Updated Lambda function:", FUNCTION_NAME)
    lam.get_waiter("function_active_v2").wait(FunctionName=FUNCTION_NAME)
    lam.get_waiter("function_updated_v2").wait(FunctionName=FUNCTION_NAME)
    return fn["FunctionArn"]


def ensure_api(apigw, lam, fn_arn, region, account):
    existing = None
    for api in apigw.get_apis().get("Items", []):
        if api["Name"] == API_NAME:
            existing = api
            break
    if existing is None:
        existing = apigw.create_api(Name=API_NAME, ProtocolType="HTTP", Target=fn_arn)
        print("Created HTTP API:", API_NAME)
    else:
        print("HTTP API already exists:", API_NAME)

    api_id = existing["ApiId"]
    try:
        lam.add_permission(
            FunctionName=FUNCTION_NAME,
            StatementId="apigw-invoke",
            Action="lambda:InvokeFunction",
            Principal="apigateway.amazonaws.com",
            SourceArn="arn:aws:execute-api:%s:%s:%s/*/*" % (region, account, api_id),
        )
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceConflictException":
            raise
    return existing["ApiEndpoint"]


def smoke_test(api_url):
    for attempt in range(1, 7):
        try:
            with urllib.request.urlopen(api_url + "/health", timeout=10) as r:
                return json.loads(r.read().decode())
        except (urllib.error.URLError, urllib.error.HTTPError, OSError):
            print("  waiting for the API to become reachable (try %d/6)..." % attempt)
            time.sleep(4)
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="baseline", choices=["baseline", "abac", "zta"])
    args = parser.parse_args()

    session = boto3.session.Session()
    region = session.region_name or "us-east-1"
    sts = session.client("sts")
    account = sts.get_caller_identity()["Account"]
    role_arn = "arn:aws:iam::%s:role/LabRole" % account
    print("Account %s, region %s" % (account, region))

    old = {}
    if os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH) as f:
            old = json.load(f)
    api_key = old.get("api_key") or secrets.token_urlsafe(24)
    jwt_secret = old.get("jwt_secret") or secrets.token_urlsafe(32)

    ddb = session.client("dynamodb", region_name=region)
    lam = session.client("lambda", region_name=region)
    apigw = session.client("apigatewayv2", region_name=region)

    ensure_table(ddb)
    seed_table(session.resource("dynamodb", region_name=region).Table(TABLE_NAME))
    print("Seeded 2 tenants x 5 records")

    env = {"TABLE_NAME": TABLE_NAME, "SECURITY_MODE": args.mode,
           "SHARED_API_KEY": api_key, "JWT_SECRET": jwt_secret}
    fn_arn = ensure_function(lam, role_arn, env)
    api_url = ensure_api(apigw, lam, fn_arn, region, account)

    with open(CONFIG_PATH, "w") as f:
        json.dump({"api_url": api_url, "api_key": api_key, "jwt_secret": jwt_secret,
                   "region": region, "mode": args.mode}, f, indent=2)

    health = smoke_test(api_url)
    print()
    if health:
        print("DEPLOYED. API URL:", api_url)
        print("Health check:", health)
        print("Next: python3 tests/run_tests.py")
    else:
        print("Deployed, but the health check did not respond yet. Wait a minute and try:")
        print("  curl %s/health" % api_url)


if __name__ == "__main__":
    main()
