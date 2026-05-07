"""
Security Group Checks
---------------------
- Unrestricted inbound on port 22 (SSH)
- Unrestricted inbound on port 3389 (RDP)
- Unrestricted inbound on all ports (0.0.0.0/0 or ::/0)
- Default VPC security group with inbound rules
"""

import boto3


def _client(profile, region):
    session = boto3.Session(profile_name=profile, region_name=region)
    return session.client("ec2", region_name=region)


DANGEROUS_PORTS = {
    22:   ("SSH", "HIGH"),
    3389: ("RDP", "HIGH"),
    5432: ("PostgreSQL", "MEDIUM"),
    3306: ("MySQL", "MEDIUM"),
    1433: ("MSSQL", "MEDIUM"),
    27017:("MongoDB", "MEDIUM"),
}

OPEN_CIDRS = {"0.0.0.0/0", "::/0"}


def run(profile=None, region="us-east-1"):
    ec2 = _client(profile, region)
    findings = []

    try:
        paginator = ec2.get_paginator("describe_security_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page.get("SecurityGroups", []))
    except Exception as e:
        return [{
            "check": "security-groups",
            "severity": "INFO",
            "title": "Could not describe security groups",
            "detail": str(e),
            "resource": "N/A",
            "region": region,
            "remediation": "Ensure secaudit has ec2:DescribeSecurityGroups permission."
        }]

    for sg in groups:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", "unknown")
        vpc_id = sg.get("VpcId", "N/A")
        arn = f"arn:aws:ec2:{region}:sg/{sg_id}"

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", 0)
            to_port = rule.get("ToPort", 65535)
            ip_ranges = [r["CidrIp"] for r in rule.get("IpRanges", [])]
            ipv6_ranges = [r["CidrIpv6"] for r in rule.get("Ipv6Ranges", [])]
            all_ranges = set(ip_ranges + ipv6_ranges)
            open_to_world = all_ranges & OPEN_CIDRS

            if not open_to_world:
                continue

            # All ports open
            if from_port == 0 and to_port == 65535:
                findings.append({
                    "check": "security-groups",
                    "severity": "CRITICAL",
                    "title": f"Security group allows unrestricted inbound on all ports: {sg_name} ({sg_id})",
                    "detail": f"SG {sg_id} in VPC {vpc_id} allows inbound on 0-65535 from {open_to_world}.",
                    "resource": arn,
                    "region": region,
                    "remediation": "Restrict inbound rules to specific ports and trusted CIDR ranges."
                })
                continue

            # Specific dangerous ports
            for port, (service, severity) in DANGEROUS_PORTS.items():
                if from_port <= port <= to_port:
                    findings.append({
                        "check": "security-groups",
                        "severity": severity,
                        "title": f"Security group allows unrestricted {service} ({port}) access: {sg_name} ({sg_id})",
                        "detail": f"SG {sg_id} in VPC {vpc_id} allows inbound on port {port} from {open_to_world}.",
                        "resource": arn,
                        "region": region,
                        "remediation": f"Restrict port {port} to known IP ranges. Use a bastion host or VPN for {service} access."
                    })

        # Default security group with rules
        if sg_name == "default" and sg.get("IpPermissions"):
            findings.append({
                "check": "security-groups",
                "severity": "MEDIUM",
                "title": f"Default security group has inbound rules: {sg_id}",
                "detail": f"The default security group in VPC {vpc_id} should have no inbound or outbound rules.",
                "resource": arn,
                "region": region,
                "remediation": "Remove all rules from the default security group and use purpose-built security groups."
            })

    return findings
