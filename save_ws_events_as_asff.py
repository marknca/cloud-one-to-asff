#! /usr/bin/env python3

"""
Select and convert important Workload Security events to Amazon Finding Format
* Function runs as an AWS Lambda function triggers by an Amazon SNS topic
* Topic receives messages from Workload Security's Event Forwarding to Amazon SNS (ref: https://help.deepsecurity.trendmicro.com/sns.html?Highlight=sns)
* Each message should have one Workload Security event to evaluate but the code is robust enough to handle multiple events per message
* All logs are sent to Amazon CloudWatch Logs
"""
# Standard library
import datetime
import json
import os

# 3rd party libraries
import boto3

def generate_finding_title(title):
	"""
	Generate a consistent title for a finding in AWS Security Hub
	* Setup as a function for consistency
	"""
	return "Trend Micro: {}".format(title)

def verify_required_properties(deep_security_event):
	"""
	Verify if the specified Deep Security event contains the required properties to 
	be convert to an Amazon Finding Format finding
	"""
	result = True

	required_properties = [
		'HostOwnerID',
		'HostInstanceID',
		'TenantID',
		'EventID',
		'EventType',
		'LogDate',
		'HostAssetValue',
		'HostGroupID',
		'HostGroupName',
		'HostID',
		'Hostname',
		'HostSecurityPolicyID',
		'HostSecurityPolicyName',
		]

	for prop in required_properties:
		if not prop in deep_security_event:
			result = False

	return result

def convert_deep_security_event_to_aff(deep_security_event):
	"""
	Convert a Deep Security to the Amazon Finding Format with all required and 
	any applicable option properties
	"""
	event_types = {
		'SystemEvent': 'system',
		'PacketLog': 'firewall',
		'PayloadLog': 'ips',
		'AntiMalwareEvent': 'antimalware',
		'WebReputationEvent': 'webreputation',
		'IntegrityEvent': 'integrity',
		'LogInspectionEvent': 'log',
		'AppControlEvent': 'applicationcontrol',
		}

	deep_security_product_arns = {
		"us-east-2": "arn:aws:securityhub:us-east-2:679593333241:product/trend-micro/deep-security",
		"us-east-1": "arn:aws:securityhub:us-east-1:679593333241:product/trend-micro/deep-security",
		"us-west-1": "arn:aws:securityhub:us-west-1:679593333241:product/trend-micro/deep-security",
		"us-west-2": "arn:aws:securityhub:us-west-2:679593333241:product/trend-micro/deep-security",
		"ap-south-1": "arn:aws:securityhub:ap-south-1:679593333241:product/trend-micro/deep-security",
		"ap-northeast-2": "arn:aws:securityhub:ap-northeast-2:679593333241:product/trend-micro/deep-security",
		"ap-southeast-1": "arn:aws:securityhub:ap-southeast-1:679593333241:product/trend-micro/deep-security",
		"ap-southeast-2": "arn:aws:securityhub:ap-southeast-2:679593333241:product/trend-micro/deep-security",
		"ap-northeast-1": "arn:aws:securityhub:ap-northeast-1:679593333241:product/trend-micro/deep-security",
		"ca-central-1": "arn:aws:securityhub:ca-central-1:679593333241:product/trend-micro/deep-security",
		"eu-central-1": "arn:aws:securityhub:eu-central-1:679593333241:product/trend-micro/deep-security",
		"eu-west-1": "arn:aws:securityhub:eu-west-1:679593333241:product/trend-micro/deep-security",
		"eu-west-2": "arn:aws:securityhub:eu-west-2:679593333241:product/trend-micro/deep-security",
		"eu-west-3": "arn:aws:securityhub:eu-west-3:679593333241:product/trend-micro/deep-security",
		"sa-east-1": "arn:aws:securityhub:sa-east-1:679593333241:product/trend-micro/deep-security",
		}

	id_key = deep_security_event['LogDate'][0:-1].replace(':', '-').replace('.', '-').replace('T', '-') # 2019-11-15T19:35:00.359Z
	if 'ManagerNodeID' in deep_security_event:
		id_key += "-{}".format(deep_security_event['ManagerNodeID']) # Manager node that generated the event
	if 'HostOwnerID' in deep_security_event:
		id_key += "-{}".format(deep_security_event['HostOwnerID']) # AWS account
	if 'HostInstanceID' in deep_security_event:
		id_key += "-{}".format(deep_security_event['HostInstanceID']) # EC2 instance ID
	id_key = id_key.strip('-')

	aff_format = {
		"SchemaVersion": "2018-10-08",
		# Id == AWS region / ManagerNodeID-(AWS account && EC2 instance ID) ||  / Deep Security Tenant ID / Deep Security Event ID
		"Id": "{}-{}-{}-{}".format(id_key, os.environ['AWS_REGION'], deep_security_event['TenantID'], deep_security_event['EventID']),
		"ProductArn": deep_security_product_arns[os.environ['AWS_REGION']] if 'AWS_REGION' in os.environ else deep_security_product_arns[boto3.session.Session().region_name],
		"GeneratorId": "trend-micro-deep-security-{}".format(event_types[deep_security_event['EventType']]),
		"AwsAccountId": deep_security_event['HostOwnerID'] if 'HostOwnerID' in deep_security_event else '', # AWS account for the event source pulled from Deep Security AWS cloud connector
		"Types": [ # Specific types are added to align with event type
			],
		"FirstObservedAt": deep_security_event['LogDate'], # ISO8601 formatted
		"UpdatedAt": "{}Z".format(datetime.datetime.utcnow().isoformat()), # Z suffix required by API
		"CreatedAt": "{}Z".format(datetime.datetime.utcnow().isoformat()), # Z suffix required by API
		"Severity": {
			"Product": 0,
			"Normalized": 0,
			},
		"Title": "", # optional
		#"SourceUrl": "", # optional
		"ProductFields": {
			'trend-micro:TenantName': deep_security_event['TenantName'] if 'TenantName' in deep_security_event else '',
			'trend-micro:TenantID': str(deep_security_event['TenantID']) if 'TenantID' in deep_security_event else '',
			'trend-micro:EventID': str(deep_security_event['EventID']) if 'EventID' in deep_security_event else '',
			'trend-micro:HostAssetValue': str(deep_security_event['HostAssetValue']) if 'HostAssetValue' in deep_security_event else '',
			'trend-micro:HostGroupID': str(deep_security_event['HostGroupID']) if 'HostGroupID' in deep_security_event else '',
			'trend-micro:HostGroupName': deep_security_event['HostGroupName'] if 'HostGroupName' in deep_security_event else '',
			'trend-micro:HostID': str(deep_security_event['HostID']) if 'HostID' in deep_security_event else '',
			'trend-micro:HostInstanceID': str(deep_security_event['HostInstanceID']) if 'HostInstanceID' in deep_security_event else '',
			'trend-micro:Hostname': deep_security_event['Hostname'] if 'Hostname' in deep_security_event else '',
			'trend-micro:HostSecurityPolicyID': str(deep_security_event['HostSecurityPolicyID']) if 'HostSecurityPolicyID' in deep_security_event else '',
			'trend-micro:HostSecurityPolicyName': deep_security_event['HostSecurityPolicyName'] if 'HostSecurityPolicyName' in deep_security_event else '',			
			}, # optional, added to 
		#"Malware": {}, # added when a malware event is detected
		"Network": {}, # optional
		"RecordState": "ACTIVE",
		#"ThreatIntelIndicators": {}, # optional
		"Resources": [
			{
				"Type": "AwsEc2Instance",
				"Id": deep_security_event['HostInstanceID'] if 'HostInstanceID' in deep_security_event else '',
				}
			],
		}

	if 'Tags' in deep_security_event:
		aff_format['ProductFields']['trend-micro:Tags'] = deep_security_event['Tags']
	if 'OriginString' in deep_security_event:
		aff_format['ProductFields']['trend-micro:Origin'] = deep_security_event['OriginString']

	# Apply custom properties based on Deep Security event type
	if deep_security_event['EventType'] == "SystemEvent": 
		# Ignore, generated by Deep Security as a platform. Includes events like agent updates, communication issues, etc.
		pass
	elif deep_security_event['EventType'] == "PacketLog": 
		# Firewall events
		aff_format['Severity']['Product'] = 0
		aff_format['Severity']['Normalized'] = int(20) # An "could result in future compromises" finding in the AFF format
		aff_format['Types'].append("Unusual Behaviors/Network Flow")
		aff_format['Title'] = generate_finding_title("Repeated attempted network connection on instance {}".format(deep_security_event['HostInstanceID']))
	elif deep_security_event['EventType'] == "PayloadLog":
		# Intrusion prevention events
		if 'Severity' in deep_security_event:
			aff_format['Severity']['Product'] = int(deep_security_event['Severity'])
			aff_format['Severity']['Normalized'] = int(int(deep_security_event['Severity']) * 17.5) # to match the 31-70 range in the AFF format

		# Add the finding type
		aff_format['Types'].append("Software and Configuration Checks Vulnerabilities/Vulnerabilities/CVE")
		aff_format['Title'] = generate_finding_title("Rule [{}] triggered".format(deep_security_event['Reason']))
	elif deep_security_event['EventType'] == "AntiMalwareEvent":
		# Anti-malware events
		aff_format['Malware'] = [
				{
					"Name": deep_security_event['MalwareName'],
					"Path": deep_security_event['InfectedFilePath'],
					}
			]
		aff_format['Types'].append("TPPs/Execution")
		aff_format['Title'] = generate_finding_title("Malware [{}] detected".format(deep_security_event['MalwareName']))
	elif deep_security_event['EventType'] == "WebReputationEvent":	
		# Web reputation events
		if 'Risk' in deep_security_event:
			aff_format['Severity']['Product'] = int(deep_security_event['Risk'])
			aff_format['Severity']['Normalized'] = int(int(deep_security_event['Risk']) * 17.5) # to match the 31-70 range in the AFF format
		aff_format['Types'].append("TPPs/Execution")
		aff_format['Title'] = generate_finding_title("High risk web request to IP [{}]".format(deep_security_event['TargetIP']))
	elif deep_security_event['EventType'] == "IntegrityEvent":	
		# Integrity monitoring events
		if 'Severity' in deep_security_event:
			aff_format['Severity']['Product'] = int(deep_security_event['Severity'])
			aff_format['Severity']['Normalized'] = int(int(deep_security_event['Severity']) * 17.5) # to match the 31-70 range in the AFF format
		aff_format['Types'].append("Unusual Behaviors/VM")
		aff_format['Title'] = generate_finding_title("Unexpected change to object [{}]".format(deep_security_event['Key']))
	elif deep_security_event['EventType'] == "LogInspectionEvent":	
		# Log inspection events
		if 'OSSEC_Level' in deep_security_event:
			aff_format['Severity']['Product'] = int(deep_security_event['OSSEC_Level'])
			if int(deep_security_event['OSSEC_Level']) >= 13:
				aff_format['Severity']['Normalized'] = int(int(deep_security_event['OSSEC_Level']) * 6.5) # to match the 71-100 range in the AFF format
			else:
				aff_format['Severity']['Normalized'] = int(int(deep_security_event['OSSEC_Level']) * 5) # to match the 31-70 range in the AFF format
		aff_format['Types'].append("Unusual Behaviors/VM")
		aff_format['Types'].append("Unusual Behaviors/Application")
		aff_format['Title'] = generate_finding_title(deep_security_event['OSSEC_Description'])	
	elif deep_security_event['EventType'] == "AppControlEvent":	
		# Application control events
		aff_format['Types'].append("Unusual Behaviors/Application")
		pass # TODO: Add severity normalization for this type of event

	converted_event = aff_format
	print(converted_event['ProductArn'])
	return converted_event

def lambda_handler(event, context):
	# Workflow:
	# 1. Verify that this is an event from an Amazon SNS topic
	# 2. Extract the Deep Security event data
	# 3. Evaluate the event for security importance
	# 4. Convert selected events to the Amazon Finding Format (AFF)
	# 5. Send select events (in AFF) to the AWS Security Hub
	total_events = 0
	saved_events = 0
	if not 'S3_BUCKET_NAME' in os.environ:
		print("S3_BUCKET_NAME is a required environment variable")
		return None
	s3_bucket_name = os.environ['S3_BUCKET_NAME']
	print('Using S3 bucket: {}'.format(s3_bucket_name))
	region = os.environ['REGION'] if 'REGION' in os.environ else None
	s3 = boto3.resource('s3', region_name=region)
	s3_bucket = b = s3.Bucket(s3_bucket_name)
	
	if 'Records' in event:
		# 1. Verify that this is an event from an Amazon SNS topic
		for e in event['Records']:
			if 'EventSource' in e and e['EventSource'] == 'aws:sns':
				print("Amazon SNS message received")
				# This is an Amazon SNS message
				# 2. Extract the Deep Security event data
				if 'Sns' in e:
					deep_security_events = None
					try:
						deep_security_events = json.loads(e['Sns']['Message'])
						print("Extracted Deep Security event(s) from the SNS message")
					except Exception as err:
						print("Could not extract the Deep Security event(s) from the SNS message. Threw exception:\n{}".format(err))

					aff_events = []
					if deep_security_events:
						print("Found {} Deep Security events...processing".format(len(deep_security_events)))
						for deep_security_event in deep_security_events:
							total_events += 1
							if not deep_security_event['EventType'] == 'SystemEvent' or verify_required_properties(deep_security_event):
								print("Security event detected, queuing to save to Amazon S3")
								print(deep_security_event)
								aff_event = convert_deep_security_event_to_aff(deep_security_event)
								aff_events.append(aff_event)
							else:
								print("Specified event does not have the required properties to properly process it")

					if len(aff_events) > 0:
						# Save the events in the specified Amazon S3 bucket
						for aff_event in aff_events:
							# Create a unique key
							kyear = aff_event['FirstObservedAt'][0:4] # 2019-11-15
							kmonth = aff_event['FirstObservedAt'][5:7]
							kday = aff_event['FirstObservedAt'][8:10]
							key = "{}/{}/{}/{}.asff.log".format(kyear, kmonth, kday, aff_event['Id'])
							try:
								s3_bucket.put_object(ACL='private', Body=json.dumps(aff_event, ensure_ascii=False).encode('gbk'), Key=key)
								saved_events += 1
								print("Wrote [{}] to S3 bucket [{}]".format(key, s3_bucket_name))
								print(aff_event)
							except Exception as err:
								print("Could not write finding to S3. Threw exception::\n{}".format(err))
							
	return {
		'total_events': total_events,
		'saved_events': saved_events,
		'issues': (total_events - saved_events),
	}								