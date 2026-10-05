"""Method 1: baseline (conventional perimeter-style security).

A shared API key is the only gate. Once past it, the API trusts whatever
tenant ID the client sends and does not check who owns a record.
"""
import hmac
import uuid

from common import (MAX_BATCH, SHARED_API_KEY, get_record, list_tenant_records,
                    respond, table)


def handle(method, parts, headers, data):
    supplied = headers.get("x-api-key", "")
    if not SHARED_API_KEY or not hmac.compare_digest(supplied, SHARED_API_KEY):
        return respond(401, {"error": "invalid or missing api key"})

    tenant = headers.get("x-tenant-id")

    if method == "GET" and len(parts) == 2 and parts[0] == "records":
        item = get_record(parts[1])
        if item is None:
            return respond(404, {"error": "record not found"})
        return respond(200, item)

    if method == "GET" and parts == ["records"]:
        if not tenant:
            return respond(400, {"error": "missing tenant id"})
        return respond(200, {"records": list_tenant_records(tenant)})

    if method == "POST" and parts == ["records"]:
        if not tenant:
            return respond(400, {"error": "missing tenant id"})
        record_id = data.get("record_id") or str(uuid.uuid4())
        item = {
            "record_id": str(record_id),
            "tenant_id": tenant,
            "content": data.get("content", ""),
        }
        table().put_item(Item=item)
        return respond(201, item)

    if method == "POST" and parts == ["batch"]:
        ids = data.get("ids", [])
        if not isinstance(ids, list) or len(ids) > MAX_BATCH:
            return respond(400, {"error": "ids must be a list of at most %d" % MAX_BATCH})
        records = [item for item in (get_record(i) for i in ids) if item]
        return respond(200, {"records": records})

    return respond(404, {"error": "route not found"})
