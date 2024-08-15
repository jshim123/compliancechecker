import boto3
import json

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
    from collections import Counter

    summary = {
        'Total User Access Events': len(user_access_logs),
        'Total Data Access Events': len(data_access_logs),
        'Total Admin Actions': len(admin_action_logs),
        'Total Security Events': len(security_event_logs)
    }

    user_access_summary = Counter(log['User'] for log in user_access_logs)
    data_access_summary = Counter(log['Event'] for log in data_access_logs)
    admin_action_summary = Counter(log['Event'] for log in admin_action_logs)
    security_event_summary = Counter(log['Event'] for log in security_event_logs)

    summary['User Access Summary'] = dict(user_access_summary)
    summary['Data Access Summary'] = dict(data_access_summary)
    summary['Admin Action Summary'] = dict(admin_action_summary)
    summary['Security Event Summary'] = dict(security_event_summary)

    return summary

log_group_name = 'group'
log_stream_name = 'example'

cloudwatch_logs = fetch_cloudwatch_logs(log_group_name, log_stream_name)

user_access_logs, data_access_logs, admin_action_logs, security_event_logs = extract_compliance_info(cloudwatch_logs)

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

summary = summarize_logs(user_access_logs, data_access_logs, admin_action_logs, security_event_logs)

print("\nSummary:")
for key, value in summary.items():
    print(f"{key}: {value}")
