"""
CloudTrail Security Checks
--------------------------
- No trails configured
- Trail not logging
- Log file validation disabled
- Multi-region trail missing
- CloudWatch integration not configured
"""

import boto3


def _client(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("cloudtrail", region_name=region)


def run(profile=None, region="us-east-1"):
    ct = _client(profile, region)
    findings = []

    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
    except Exception as e:
        return [{
            "check": "cloudtrail",
            "severity": "INFO",
            "title": "Could not describe CloudTrail trails",
            "detail": str(e),
            "resource": "N/A",
            "region": region,
            "remediation": "Ensure secaudit has cloudtrail:DescribeTrails permission."
        }]

    if not trails:
        return [{
            "check": "cloudtrail",
            "severity": "CRITICAL",
            "title": "No CloudTrail trails configured in this region",
            "detail": f"No trails found in region {region}. API activity is not being logged.",
            "resource": f"arn:aws:cloudtrail:{region}",
            "region": region,
            "remediation": "Create a multi-region CloudTrail trail with log file validation and CloudWatch integration."
        }]

    for trail in trails:
        name = trail.get("Name", "unknown")
        arn = trail.get("TrailARN", "N/A")

        # Is it currently logging?
        try:
            status = ct.get_trail_status(Name=arn)
            if not status.get("IsLogging"):
                findings.append({
                    "check": "cloudtrail",
                    "severity": "HIGH",
                    "title": f"CloudTrail trail is not actively logging: {name}",
                    "detail": f"Trail {name} exists but logging is disabled.",
                    "resource": arn,
                    "region": region,
                    "remediation": "Enable logging on the trail via the console or aws cloudtrail start-logging."
                })
        except Exception:
            pass

        # Log file validation
        if not trail.get("LogFileValidationEnabled"):
            findings.append({
                "check": "cloudtrail",
                "severity": "MEDIUM",
                "title": f"Log file validation not enabled: {name}",
                "detail": f"Trail {name} does not have log file integrity validation enabled.",
                "resource": arn,
                "region": region,
                "remediation": "Enable log file validation to detect log tampering."
            })

        # Multi-region coverage
        if not trail.get("IsMultiRegionTrail"):
            findings.append({
                "check": "cloudtrail",
                "severity": "MEDIUM",
                "title": f"Trail is not multi-region: {name}",
                "detail": f"Trail {name} only captures events in a single region.",
                "resource": arn,
                "region": region,
                "remediation": "Configure the trail to cover all regions."
            })

        # CloudWatch Logs integration
        if not trail.get("CloudWatchLogsLogGroupArn"):
            findings.append({
                "check": "cloudtrail",
                "severity": "LOW",
                "title": f"Trail not integrated with CloudWatch Logs: {name}",
                "detail": f"Trail {name} is not sending events to CloudWatch Logs for real-time alerting.",
                "resource": arn,
                "region": region,
                "remediation": "Configure CloudWatch Logs integration for real-time monitoring and alerting."
            })

    return findings
