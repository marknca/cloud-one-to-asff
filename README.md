# Cloud One To ASFF

By default, Trend Micro's Cloud One Workload Security sends events to Amazon SNS using a custom JSON format. This simple script converts that JSON document into one compatible with the [Amazon Security Finding Format](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-findings-format.html) for **security** events only.

System events from Workload Security don't fit into the format as it was designed for security events and not maintenance or operational events.

## Architecture

![Normalizing security events](docs/normalizing-aws-security-events.jpg)
