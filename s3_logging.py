import boto3
import json
import time
from datetime import datetime
from botocore.exceptions import ClientError

# AWS S3 Client
s3 = boto3.resource('s3')

def upload_to_s3(log_message, bucket, key):
    try:
        response = s3.Object(bucket, key).put(Body=log_message)
        return response
    except Exception as error:
        raise

def log_to_s3(log_message, s3_bucket_name, prefix='logs'):
    timestamp = datetime.now().isoformat()
    key = f'{prefix}/{timestamp}.json'
    upload_to_s3(log_message, s3_bucket_name, key)
