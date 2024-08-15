import boto3
import json
import logging
import time
from datetime import datetime
from botocore.exceptions import ClientError
from collections import Counter, defaultdict
from plot_logs import visualize_summary  # Import the plotting function
from s3_logging import log_to_s3  # Import the S3 logging function

cloudtrail = boto3.client('cloudtrail')
guardduty = boto3.client('guardduty')
config = boto3.client('config')
logs = boto3.client('logs')

log_group_name = 'group'
log_stream_name = 'example'
sequence_token = None
s3_bucket_name = 'compliance-checker-jshim123'

logger = logging.getLogger()
logger.setLevel(logging.ERROR)

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return json.JSONEncoder.default(self, obj)

def fetch_cloudtrail_logs():
    events = cloudtrail.lookup_events(MaxResults=10)
    for event in events['Events']:
        process_event(event)

def fetch_guardduty_findings():
    detectors = guardduty.list_detectors()
    for detector_id in detectors['DetectorIds']:
        findings = guardduty.list_findings(DetectorId=detector_id)
        for finding_id in findings['FindingIds']:
            finding = guardduty.get_findings(DetectorId=detector_id, FindingIds=[finding_id])
            process_finding(finding)

def fetch_config_rules():
    rules = config.describe_config_rules()
    for rule in rules['ConfigRules']:
        process_rule(rule)

def process_event(event):
    log_message = json.dumps(event, cls=DateTimeEncoder)
    log_to_cloudwatch(log_message)
    log_to_s3(log_message, s3_bucket_name, prefix='cloudtrail')

def process_finding(finding):
    log_message = json.dumps(finding, cls=DateTimeEncoder)
    log_to_cloudwatch(log_message)
    log_to_s3(log_message, s3_bucket_name, prefix='guardduty')

def process_rule(rule):
    log_message = json.dumps(rule, cls=DateTimeEncoder)
    log_to_cloudwatch(log_message)
    log_to_s3(log_message, s3_bucket_name, prefix='config')

def log_to_cloudwatch(log_message):
    global sequence_token
    try:
        if sequence_token:
            response = logs.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(round(time.time() * 1000)),
                        'message': log_message
                    },
                ],
                sequenceToken=sequence_token
            )
        else:
            response = logs.put_log_events(
                logGroupName=log_group_name,
                logStreamName=log_stream_name,
                logEvents=[
                    {
                        'timestamp': int(round(time.time() * 1000)),
                        'message': log_message
                    },
                ],
            )
        sequence_token = response['nextSequenceToken']
    except ClientError as e:
        raise

def fetch_cloudwatch_logs(log_group_name, log_stream_name):
    logs_client = boto3.client('logs')
    response = logs_client.get_log_events(
        logGroupName=log_group_name,
        logStreamName=log_stream_name,
        startFromHead=True
    )
    events = response['events']
    logs = [json.loads(event['message']) for event in events]
    return logs

def extract_compliance_info(logs):
    user_access_logs = []
    data_access_logs = []
    admin_action_logs = []
    security_event_logs = []

    for log in logs:
        cloudtrail_event_str = log.get('CloudTrailEvent', '{}')
        try:
            cloudtrail_event = json.loads(cloudtrail_event_str)
        except json.JSONDecodeError:
            continue

        event_name = cloudtrail_event.get('eventName')
        user_identity = cloudtrail_event.get('userIdentity', {})
        user = user_identity.get('userName', 'N/A')
        if user == 'N/A' and user_identity.get('type') == 'Root':
            user = 'root'
        timestamp = cloudtrail_event.get('eventTime')
        source_ip = cloudtrail_event.get('sourceIPAddress', 'N/A')

        if event_name in ['DescribeMetricFilters', 'GetLogEvents']:
            user_access_logs.append({
                'Timestamp': timestamp,
                'User': user,
                'Event': event_name,
                'Source IP': source_ip
            })

        if event_name in ['PutBucketPublicAccessBlock']:
            data_access_logs.append({
                'Timestamp': timestamp,
                'User': user,
                'Event': event_name,
                'Source IP': source_ip,
                'Details': log
            })

        if user == 'root':
            admin_action_logs.append({
                'Timestamp': timestamp,
                'User': user,
                'Event': event_name,
                'Source IP': source_ip
            })

        if 'guardduty.amazonaws.com' in log.get('EventSource', ''):
            security_event_logs.append({
                'Timestamp': timestamp,
                'User': user,
                'Event': event_name,
                'Source IP': source_ip,
                'Severity': log.get('severity', 'N/A'),
                'Description': log.get('detail', {}).get('description', 'N/A')
            })

    return user_access_logs, data_access_logs, admin_action_logs, security_event_logs

def summarize_logs(user_access_logs, data_access_logs, admin_action_logs, security_event_logs):
    summary = {
        'User Access Logs': user_access_logs,
        'Data Access Logs': data_access_logs,
        'Admin Action Logs': admin_action_logs,
        'Security Event Logs': security_event_logs
    }
    
    return summary

def main():
    fetch_cloudtrail_logs()
    fetch_guardduty_findings()
    fetch_config_rules()

    cloudwatch_logs = fetch_cloudwatch_logs(log_group_name, log_stream_name)
    user_access_logs, data_access_logs, admin_action_logs, security_event_logs = extract_compliance_info(cloudwatch_logs)
    
    summary = summarize_logs(user_access_logs, data_access_logs, admin_action_logs, security_event_logs)

    print("User Access Logs from CloudWatch:")
    for log in user_access_logs:
        print(log)

    print("\nData Access Logs from CloudWatch:")
    for log in data_access_logs:
        print(log)

    print("\nAdministrative Action Logs from CloudWatch:")
    for log in admin_action_logs:
        print(log)

    print("\nSecurity Event Logs from CloudWatch:")
    for log in security_event_logs:
        print(log)

    print("\nSummary:")
    for key, value in summary.items():
        print(f"{key}: {value}")

    visualize_summary(summary)

if __name__ == "__main__":
    main()
