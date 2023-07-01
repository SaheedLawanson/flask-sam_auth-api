import boto3

cognito_client = boto3.client("cognito-idp", 
    endpoint_url="http://0.0.0.0:9229")
dynamodb_client = boto3.client('dynamodb', 
    endpoint_url="http://localhost:8000")

tables = dynamodb_client.list_tables(
    Limit=50
)
print(tables)