"""Code shared by every security mode: config, DynamoDB access, request parsing, responses."""
import base64
import json
import os

import boto3
from boto3.dynamodb.conditions import Attr

TABLE_NAME = os.environ.get("TABLE_NAME", "zta-testbed-records")
MODE = os.environ.get("SECURITY_MODE", "baseline")
SHARED_API_KEY = os.environ.get("SHARED_API_KEY", "")
JWT_SECRET = os.environ.get("JWT_SECRET", "")
MAX_BATCH = 25

_resource = None


def table():
    """Create the DynamoDB table handle on first use and reuse it afterwards."""
    global _resource
    if _resource is None:
        _resource = boto3.resource("dynamodb")
    return _resource.Table(TABLE_NAME)


def respond(status, body):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(body),
    }


def parse_request(event):
    http = event["requestContext"]["http"]
    method = http["method"]
    path = event.get("rawPath", "/")
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    raw = event.get("body")
    if raw and event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode("utf-8")
    data = json.loads(raw) if raw else {}
    if not isinstance(data, dict):
        raise ValueError("body must be a JSON object")
    parts = [p for p in path.split("/") if p]
    return method, parts, headers, data


def get_record(record_id):
    return table().get_item(Key={"record_id": str(record_id)}).get("Item")


def list_tenant_records(tenant_id):
    items = []
    kwargs = {"FilterExpression": Attr("tenant_id").eq(tenant_id)}
    while True:
        out = table().scan(**kwargs)
        items.extend(out.get("Items", []))
        if "LastEvaluatedKey" not in out:
            return items
        kwargs["ExclusiveStartKey"] = out["LastEvaluatedKey"]
