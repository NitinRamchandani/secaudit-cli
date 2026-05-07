"""
IAM Security Checks
-------------------
- Root account MFA
- Users with console access but no MFA
- Access keys older than 90 days
- Users with both console access and active access keys
- Inline policies attached directly to users
"""

import boto3
from datetime import datetime, timezone


def _client(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("iam")


def run(profile=None, region="us-east-1"):
    iam = _client(profile, region)
    findings = []

    # --- Root MFA check
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if not summary.get("AccountMFAEnabled", 0):
            findings.append({
                "check": "iam",
                "severity": "CRITICAL",
                "title": "Root account does not have MFA enabled",
                "detail": "The AWS root account has no MFA device associated. Root access without MFA is a critical risk.",
                "resource": "arn:aws:iam::root",
                "region": "global",
                "remediation": "Enable MFA on the root account via IAM > Security credentials."
            })
    except Exception as e:
        findings.append(_error("iam-root-mfa", str(e), region))

    # --- Users without MFA / old keys / dual access
    try:
        paginator = iam.get_paginator("get_account_authorization_details")
        for page in paginator.paginate(Filter=["User"]):
            for user in page.get("UserDetailList", []):
                username = user["UserName"]
                arn = user["Arn"]

                # Console access?
                try:
                    iam.get_login_profile(UserName=username)
                    has_console = True
                except iam.exceptions.NoSuchEntityException:
                    has_console = False

                # MFA devices
                mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
                if has_console and not mfa_devices:
                    findings.append({
                        "check": "iam",
                        "severity": "HIGH",
                        "title": f"IAM user has console access without MFA: {username}",
                        "detail": f"User {username} can log into the AWS console but has no MFA device.",
                        "resource": arn,
                        "region": "global",
                        "remediation": "Enforce MFA via an IAM policy or AWS Organizations SCP."
                    })

                # Access keys older than 90 days
                keys = iam.list_access_keys(UserName=username)["AccessKeyMetadata"]
                for key in keys:
                    if key["Status"] == "Active":
                        age = (datetime.now(timezone.utc) - key["CreateDate"]).days
                        if age > 90:
                            findings.append({
                                "check": "iam",
                                "severity": "MEDIUM",
                                "title": f"Active access key older than 90 days: {username}",
                                "detail": f"Key {key['AccessKeyId']} for user {username} is {age} days old.",
                                "resource": arn,
                                "region": "global",
                                "remediation": "Rotate or deactivate access keys older than 90 days."
                            })

                # Inline policies on users (bad practice)
                inline = iam.list_user_policies(UserName=username)["PolicyNames"]
                if inline:
                    findings.append({
                        "check": "iam",
                        "severity": "LOW",
                        "title": f"Inline policy attached directly to user: {username}",
                        "detail": f"User {username} has inline policies: {', '.join(inline)}. Prefer managed policies.",
                        "resource": arn,
                        "region": "global",
                        "remediation": "Replace inline policies with AWS managed or customer managed policies."
                    })

    except Exception as e:
        findings.append(_error("iam-users", str(e), region))

    return findings


def _error(check_name, detail, region):
    return {
        "check": "iam",
        "severity": "INFO",
        "title": f"Could not complete check: {check_name}",
        "detail": detail,
        "resource": "N/A",
        "region": region,
        "remediation": "Verify IAM permissions for secaudit."
    }
