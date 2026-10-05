"""Method 2: attribute-based access control (ABAC).

Based on the ABAC model in Sanders and Yue (2019). A signed token carries the
caller's attributes (tenant_id, role). Each request is checked against a small
policy before any data is returned. The tenant comes from the token, never from
a header the client controls. Deny by default.

This mode uses one policy check per request, inside the API. It has no separate
authoriser and no decision log (those belong to Method 3).
"""
import uuid

import jwt
from botocore.exceptions import ClientError

from common import (JWT_SECRET, MAX_BATCH, get_record, list_tenant_records,
                    respond, table)

ROLES = {"reader", "writer"}

# ---------------------------------------------------------------------------
# POLICY: the rules below are the "policy code" counted for the complexity
# measurement. A request is allowed only if the caller's tenant equals the
# resource's tenant AND a rule grants the action to the caller's role.
# ---------------------------------------------------------------------------
POLICY = [
    {"actions": {"read", "list", "batch_read"}, "roles": {"reader", "writer"}},
    {"actions": {"write"}, "roles": {"writer"}},
]


def permitted(subject, action, resource_tenant):
    if subject["tenant_id"] != resource_tenant:
        return False
    return any(action in rule["actions"] and subject["role"] in rule["roles"]
               for rule in POLICY)
# ---------------------------------------------------------------------------


def authenticate(headers):
    """Validate the bearer token. Returns (subject, None) or (None, error response)."""
    auth = headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return None, respond(401, {"error": "missing bearer token"})
    if not JWT_SECRET:
        return None, respond(500, {"error": "server is missing its signing secret"})
    token = auth[7:].strip()
    try:
        # Algorithm is fixed to HS256 so a token cannot pick its own (e.g. "none").
        claims = jwt.decode(token, JWT_SECRET, algorithms=["HS256"],
                            options={"require": ["exp"]})
    except jwt.ExpiredSignatureError:
        return None, respond(401, {"error": "token expired"})
    except jwt.InvalidTokenError:
        return None, respond(401, {"error": "invalid token"})

    tenant = claims.get("tenant_id")
    role = claims.get("role")
    if not isinstance(tenant, str) or not tenant or role not in ROLES:
        return None, respond(403, {"error": "token is missing required attributes"})
    return {"tenant_id": tenant, "role": role}, None


def handle(method, parts, headers, data):
    subject, error = authenticate(headers)
    if error:
        return error

    if method == "GET" and len(parts) == 2 and parts[0] == "records":
        item = get_record(parts[1])
        if item is None:
            return respond(404, {"error": "record not found"})
        if not permitted(subject, "read", item["tenant_id"]):
            return respond(403, {"error": "forbidden"})
        return respond(200, item)

    if method == "GET" and parts == ["records"]:
        if not permitted(subject, "list", subject["tenant_id"]):
            return respond(403, {"error": "forbidden"})
        return respond(200, {"records": list_tenant_records(subject["tenant_id"])})

    if method == "POST" and parts == ["records"]:
        if not permitted(subject, "write", subject["tenant_id"]):
            return respond(403, {"error": "forbidden"})
        item = {
            "record_id": str(data.get("record_id") or uuid.uuid4()),
            "tenant_id": subject["tenant_id"],
            "content": data.get("content", ""),
        }
        try:
            # Refuse to overwrite a record that belongs to another tenant.
            table().put_item(
                Item=item,
                ConditionExpression="attribute_not_exists(record_id) OR tenant_id = :t",
                ExpressionAttributeValues={":t": subject["tenant_id"]},
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
                return respond(403, {"error": "forbidden"})
            raise
        return respond(201, item)

    if method == "POST" and parts == ["batch"]:
        ids = data.get("ids", [])
        if not isinstance(ids, list) or len(ids) > MAX_BATCH:
            return respond(400, {"error": "ids must be a list of at most %d" % MAX_BATCH})
        records, denied = [], 0
        for record_id in ids:
            item = get_record(record_id)
            if item is None:
                continue
            # Every record is checked on its own, not once for the whole request.
            if permitted(subject, "batch_read", item["tenant_id"]):
                records.append(item)
            else:
                denied += 1
        return respond(200, {"records": records, "denied": denied})

    return respond(404, {"error": "route not found"})
