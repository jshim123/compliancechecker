import requests
import json

# Splunk HEC configuration
SPLUNK_HEC_URL = 'https://splunk-server:8088/services/collector/event'
SPLUNK_HEC_TOKEN = '3073e1c4-b733-4c18-8a36-0c18bef4b222'

def send_to_splunk(data, sourcetype):
    headers = {'Authorization': f'Splunk {SPLUNK_HEC_TOKEN}'}
    payload = {
        'event': data,
        'sourcetype': sourcetype
    }
    response = requests.post(SPLUNK_HEC_URL, headers=headers, json=payload)
    if response.status_code != 200:
        print(f"Error sending data to Splunk: {response.text}")
    else:
        print("Data successfully sent to Splunk")
