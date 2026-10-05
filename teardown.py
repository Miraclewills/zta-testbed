"""Delete everything deploy.py created (use this when you finish for the day if you want a clean account)."""
import boto3
from botocore.exceptions import ClientError

TABLE_NAME = "zta-testbed-records"
FUNCTION_NAME = "zta-testbed-api"
API_NAME = "zta-testbed-http-api"

session = boto3.session.Session()
region = session.region_name or "us-east-1"

apigw = session.client("apigatewayv2", region_name=region)
for api in apigw.get_apis().get("Items", []):
    if api["Name"] == API_NAME:
        apigw.delete_api(ApiId=api["ApiId"])
        print("Deleted API", api["ApiId"])

try:
    session.client("lambda", region_name=region).delete_function(FunctionName=FUNCTION_NAME)
    print("Deleted Lambda", FUNCTION_NAME)
except ClientError as e:
    print("Lambda:", e.response["Error"]["Code"])

try:
    session.client("dynamodb", region_name=region).delete_table(TableName=TABLE_NAME)
    print("Deleted table", TABLE_NAME)
except ClientError as e:
    print("Table:", e.response["Error"]["Code"])
