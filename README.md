# Cloud One To ASFF

By default, Trend Micro's Cloud One Workload Security sends events to Amazon SNS using a custom JSON format. This simple script converts that JSON document into one compatible with the [Amazon Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) for **security** events only.

System events from Workload Security don't fit into the format as it was designed for security events and not maintenance or operational events.

## Architecture

![Normalizing security events](docs/normalizing-aws-security-events.jpg)

AWS Lambda function #1 [save_ws_events_as_asff.py](save_ws_events_as_asff.py) is triggered whenever Cloud One Workload Security sends and event to the specific Amazon SNS Topic.

This function then reads the event in Cloud One's format and—for security events only—converts it to Amazon's Security Finding Format.