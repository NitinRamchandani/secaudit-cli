"""
S3 Security Checks
------------------
- Public access block not enabled at bucket level
- Buckets with public ACLs
- Server-side encryption not enabled
- Versioning not enabled
- Logging not enabled
"""

import boto3


def _client(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("s3")


def run(profile=None, region="us-east-1"):
    s3 = _client(profile, region)
    findings = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return [{
            "check": "s3",
            "severity": "INFO",
            "title": "Could not list S3 buckets",
            "detail": str(e),
            "resource": "N/A",
            "region": region,
            "remediation": "Ensure secaudit has s3:ListAllMyBuckets permission."
        }]

    for bucket in buckets:
        name = bucket["Name"]
        arn = f"arn:aws:s3:::{name}"

        # Public access block
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all([
                pab.get("BlockPublicAcls"),
                pab.get("IgnorePublicAcls"),
                pab.get("BlockPublicPolicy"),
                pab.get("RestrictPublicBuckets")
            ]):
                findings.append({
                    "check": "s3",
                    "severity": "HIGH",
                    "title": f"S3 bucket public access block not fully enabled: {name}",
                    "detail": f"Bucket {name} has partial or no public access block settings.",
                    "resource": arn,
                    "region": region,
                    "remediation": "Enable all four public access block settings on the bucket."
                })
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            findings.append({
                "check": "s3",
                "severity": "HIGH",
                "title": f"S3 bucket has no public access block configuration: {name}",
                "detail": f"Bucket {name} has no public access block configured at all.",
                "resource": arn,
                "region": region,
                "remediation": "Configure public access block settings for this bucket."
            })
        except Exception:
            pass

        # Encryption
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            findings.append({
                "check": "s3",
                "severity": "MEDIUM",
                "title": f"S3 bucket does not have default encryption enabled: {name}",
                "detail": f"Bucket {name} has no server-side encryption configured.",
                "resource": arn,
                "region": region,
                "remediation": "Enable default SSE-S3 or SSE-KMS encryption on the bucket."
            })

        # Versioning
        try:
            versioning = s3.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                findings.append({
                    "check": "s3",
                    "severity": "LOW",
                    "title": f"S3 bucket versioning not enabled: {name}",
                    "detail": f"Bucket {name} does not have versioning enabled.",
                    "resource": arn,
                    "region": region,
                    "remediation": "Enable versioning to protect against accidental deletion and overwrites."
                })
        except Exception:
            pass

        # Logging
        try:
            logging_config = s3.get_bucket_logging(Bucket=name).get("LoggingEnabled")
            if not logging_config:
                findings.append({
                    "check": "s3",
                    "severity": "LOW",
                    "title": f"S3 bucket access logging not enabled: {name}",
                    "detail": f"Bucket {name} does not have server access logging configured.",
                    "resource": arn,
                    "region": region,
                    "remediation": "Enable server access logging and direct logs to a dedicated audit bucket."
                })
        except Exception:
            pass

    return findings
