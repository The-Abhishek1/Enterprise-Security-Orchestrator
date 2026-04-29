# src/workers/aws_auditor.py
"""
AWS Security Auditor — checks cloud resources against CIS AWS Foundations Benchmark.
Uses boto3 with assume-role pattern (never stores long-term credentials).
"""
import asyncio
from datetime import datetime, timezone, timedelta
from typing   import Any, Dict, List, Optional
from src.utils.logging import logger

PROVIDER = "aws"


async def run_aws_audit(
    credentials:   Dict[str, Any],
    region:        str,
    cloud_account: str,
) -> List[Dict]:
    """Run all AWS security checks in parallel. Returns normalized findings."""
    try:
        import boto3
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        logger.error("[aws-auditor] boto3 not installed — pip install boto3")
        return [_finding("aws-boto3-missing", "iam", cloud_account, "critical",
                         "boto3 not installed", "Install boto3: pip install boto3", [])]

    # Build boto3 session from credentials
    session = _build_session(credentials, region)
    if not session:
        return [_finding("aws-auth-failed", "iam", cloud_account, "critical",
                         "Failed to authenticate with AWS", "Check credentials and permissions", [])]

    logger.info(f"[aws-auditor] Starting audit: account={cloud_account} region={region}")

    # Run all checks in parallel
    checks = await asyncio.gather(
        _check_s3(session, cloud_account),
        _check_ec2(session, region, cloud_account),
        _check_rds(session, region, cloud_account),
        _check_iam(session, cloud_account),
        _check_cloudtrail(session, region, cloud_account),
        _check_vpc(session, region, cloud_account),
        return_exceptions=True,
    )

    findings = []
    for result in checks:
        if isinstance(result, Exception):
            logger.warning(f"[aws-auditor] check error: {result}")
        elif isinstance(result, list):
            findings.extend(result)

    logger.info(f"[aws-auditor] Done: {cloud_account} — {len(findings)} findings")
    return findings


def _build_session(credentials: Dict, region: str):
    """Build boto3 session. Supports role ARN (preferred) or access keys."""
    try:
        import boto3
        cred_type = credentials.get("type", "access_key")

        if cred_type == "role_arn":
            # Assume role — preferred for production (no long-term keys)
            sts = boto3.client(
                "sts",
                aws_access_key_id=credentials.get("access_key_id"),
                aws_secret_access_key=credentials.get("secret_access_key"),
                region_name=region,
            )
            assumed = sts.assume_role(
                RoleArn=credentials["role_arn"],
                RoleSessionName="XCloakAudit",
                DurationSeconds=3600,
            )
            creds = assumed["Credentials"]
            return boto3.Session(
                aws_access_key_id=creds["AccessKeyId"],
                aws_secret_access_key=creds["SecretAccessKey"],
                aws_session_token=creds["SessionToken"],
                region_name=region,
            )
        else:
            # Direct access keys
            return boto3.Session(
                aws_access_key_id=credentials.get("access_key_id"),
                aws_secret_access_key=credentials.get("secret_access_key"),
                region_name=region,
            )
    except Exception as e:
        logger.error(f"[aws-auditor] Auth failed: {e}")
        return None


# ── S3 Checks ─────────────────────────────────────────────────────────────────

async def _check_s3(session, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_s3_sync, session, account)


def _check_s3_sync(session, account: str) -> List[Dict]:
    findings = []
    try:
        s3 = session.client("s3")
        buckets = s3.list_buckets().get("Buckets", [])

        for bucket in buckets:
            name = bucket["Name"]
            resource = f"arn:aws:s3:::{name}"

            # Public access block
            try:
                pub = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
                if not all([
                    pub.get("BlockPublicAcls"), pub.get("IgnorePublicAcls"),
                    pub.get("BlockPublicPolicy"), pub.get("RestrictPublicBuckets"),
                ]):
                    findings.append(_finding(
                        "aws-s3-public-access", "s3", resource, "critical",
                        f"S3 bucket '{name}' has public access enabled",
                        "Enable 'Block all public access' in S3 bucket settings. Go to S3 → bucket → Permissions → Block public access → Edit → enable all checkboxes.",
                        ["CIS-2.1.1", "SOC2-CC6.1", "PCI-DSS-1.3"],
                    ))
            except Exception:
                # If the call fails, assume no block (misconfigured)
                findings.append(_finding(
                    "aws-s3-public-access", "s3", resource, "high",
                    f"S3 bucket '{name}' public access block could not be verified",
                    "Verify and enable public access block settings manually.",
                    ["CIS-2.1.1"],
                ))

            # Encryption
            try:
                s3.get_bucket_encryption(Bucket=name)
            except Exception:
                findings.append(_finding(
                    "aws-s3-no-encryption", "s3", resource, "high",
                    f"S3 bucket '{name}' has no server-side encryption",
                    "Enable SSE-S3 or SSE-KMS: S3 → bucket → Properties → Default encryption → Enable.",
                    ["CIS-2.1.2", "SOC2-CC6.7", "PCI-DSS-3.5"],
                ))

            # Versioning
            try:
                ver = s3.get_bucket_versioning(Bucket=name)
                if ver.get("Status") != "Enabled":
                    findings.append(_finding(
                        "aws-s3-no-versioning", "s3", resource, "medium",
                        f"S3 bucket '{name}' has versioning disabled",
                        "Enable versioning: S3 → bucket → Properties → Bucket Versioning → Enable.",
                        ["CIS-2.1.3"],
                    ))
            except Exception:
                pass

            # Logging
            try:
                log = s3.get_bucket_logging(Bucket=name)
                if "LoggingEnabled" not in log:
                    findings.append(_finding(
                        "aws-s3-no-logging", "s3", resource, "low",
                        f"S3 bucket '{name}' access logging not enabled",
                        "Enable access logging: S3 → bucket → Properties → Server access logging → Enable.",
                        ["CIS-2.1.4", "SOC2-CC7.2"],
                    ))
            except Exception:
                pass

    except Exception as e:
        logger.warning(f"[aws-auditor] S3 check failed: {e}")
    return findings


# ── EC2 / Security Groups ─────────────────────────────────────────────────────

async def _check_ec2(session, region: str, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_ec2_sync, session, region, account)


def _check_ec2_sync(session, region: str, account: str) -> List[Dict]:
    findings = []
    try:
        ec2 = session.client("ec2", region_name=region)

        # Security groups
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            resource = f"arn:aws:ec2:{region}:{account}:security-group/{sg_id}"

            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort", 65535)
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        if from_port <= 22 <= to_port:
                            findings.append(_finding(
                                "aws-ec2-open-sg-ssh", "ec2", resource, "critical",
                                f"Security group '{sg_name}' allows SSH (22) from 0.0.0.0/0",
                                f"Restrict SSH access: EC2 → Security Groups → {sg_id} → Edit inbound rules → restrict source to your IP.",
                                ["CIS-4.1", "SOC2-CC6.6", "PCI-DSS-1.3.1"],
                            ))
                        if from_port <= 3389 <= to_port:
                            findings.append(_finding(
                                "aws-ec2-open-sg-rdp", "ec2", resource, "critical",
                                f"Security group '{sg_name}' allows RDP (3389) from 0.0.0.0/0",
                                f"Restrict RDP access: EC2 → Security Groups → {sg_id} → Edit inbound rules → restrict source to your IP.",
                                ["CIS-4.2", "SOC2-CC6.6"],
                            ))
                        if rule.get("IpProtocol") == "-1":
                            findings.append(_finding(
                                "aws-ec2-open-sg-all", "ec2", resource, "critical",
                                f"Security group '{sg_name}' allows ALL traffic from 0.0.0.0/0",
                                f"Remove the 'All traffic' rule: EC2 → Security Groups → {sg_id} → Edit inbound rules.",
                                ["CIS-4.3", "SOC2-CC6.6", "PCI-DSS-1.3"],
                            ))

        # EBS volume encryption
        volumes = ec2.describe_volumes()["Volumes"]
        for vol in volumes:
            if not vol.get("Encrypted"):
                vol_id   = vol["VolumeId"]
                resource = f"arn:aws:ec2:{region}:{account}:volume/{vol_id}"
                findings.append(_finding(
                    "aws-ec2-unencrypted-volume", "ec2", resource, "high",
                    f"EBS volume '{vol_id}' is not encrypted",
                    "Create encrypted snapshot and restore: EC2 → Volumes → Actions → Create snapshot → copy with encryption enabled.",
                    ["CIS-2.2.1", "SOC2-CC6.7", "PCI-DSS-3.4"],
                ))

    except Exception as e:
        logger.warning(f"[aws-auditor] EC2 check failed: {e}")
    return findings


# ── RDS ───────────────────────────────────────────────────────────────────────

async def _check_rds(session, region: str, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_rds_sync, session, region, account)


def _check_rds_sync(session, region: str, account: str) -> List[Dict]:
    findings = []
    try:
        rds       = session.client("rds", region_name=region)
        instances = rds.describe_db_instances()["DBInstances"]

        for db in instances:
            db_id    = db["DBInstanceIdentifier"]
            resource = f"arn:aws:rds:{region}:{account}:db:{db_id}"

            if db.get("PubliclyAccessible"):
                findings.append(_finding(
                    "aws-rds-public", "rds", resource, "critical",
                    f"RDS instance '{db_id}' is publicly accessible",
                    f"Disable public accessibility: RDS → {db_id} → Modify → Connectivity → Publicly accessible → No.",
                    ["CIS-2.3.1", "SOC2-CC6.6", "PCI-DSS-1.3.2"],
                ))

            if not db.get("StorageEncrypted"):
                findings.append(_finding(
                    "aws-rds-no-encryption", "rds", resource, "high",
                    f"RDS instance '{db_id}' storage is not encrypted",
                    "Encryption can only be enabled on new instances. Create encrypted snapshot and restore to new encrypted instance.",
                    ["CIS-2.3.1", "SOC2-CC6.7", "PCI-DSS-3.4"],
                ))

            if db.get("BackupRetentionPeriod", 0) == 0:
                findings.append(_finding(
                    "aws-rds-no-backup", "rds", resource, "medium",
                    f"RDS instance '{db_id}' has automated backups disabled",
                    f"Enable backups: RDS → {db_id} → Modify → Backup → Backup retention period → set to 7+ days.",
                    ["CIS-2.3.2", "SOC2-A1.2"],
                ))

    except Exception as e:
        logger.warning(f"[aws-auditor] RDS check failed: {e}")
    return findings


# ── IAM ───────────────────────────────────────────────────────────────────────

async def _check_iam(session, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_iam_sync, session, account)


def _check_iam_sync(session, account: str) -> List[Dict]:
    findings = []
    try:
        iam = session.client("iam")

        # Root account usage
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountAccessKeysPresent", 0) > 0:
                findings.append(_finding(
                    "aws-iam-root-access-keys", "iam", f"arn:aws:iam::{account}:root", "critical",
                    "Root account has active access keys",
                    "Delete root access keys immediately: IAM → Security credentials (as root) → Access keys → Delete.",
                    ["CIS-1.4", "SOC2-CC6.3", "PCI-DSS-7.1"],
                ))
        except Exception:
            pass

        # Users: MFA and unused credentials
        users = iam.list_users()["Users"]
        for user in users:
            username = user["UserName"]
            resource = f"arn:aws:iam::{account}:user/{username}"

            # MFA check
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                # Only flag if user has console access
                try:
                    iam.get_login_profile(UserName=username)
                    findings.append(_finding(
                        "aws-iam-no-mfa", "iam", resource, "high",
                        f"IAM user '{username}' has console access but no MFA",
                        f"Enable MFA: IAM → Users → {username} → Security credentials → Assign MFA device.",
                        ["CIS-1.10", "SOC2-CC6.1", "PCI-DSS-8.3"],
                    ))
                except Exception:
                    pass  # No console access, skip

            # Unused credentials (>90 days)
            try:
                cred_report = iam.get_credential_report()
            except Exception:
                try:
                    iam.generate_credential_report()
                except Exception:
                    pass

            # Admin policy
            attached = iam.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            for policy in attached:
                if policy["PolicyName"] in ("AdministratorAccess", "PowerUserAccess"):
                    findings.append(_finding(
                        "aws-iam-admin-policy", "iam", resource, "high",
                        f"IAM user '{username}' has '{policy['PolicyName']}' attached",
                        f"Follow least-privilege principle: IAM → Users → {username} → Permissions → remove {policy['PolicyName']} and grant only needed permissions.",
                        ["CIS-1.16", "SOC2-CC6.3"],
                    ))

    except Exception as e:
        logger.warning(f"[aws-auditor] IAM check failed: {e}")
    return findings


# ── CloudTrail ────────────────────────────────────────────────────────────────

async def _check_cloudtrail(session, region: str, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_cloudtrail_sync, session, region, account)


def _check_cloudtrail_sync(session, region: str, account: str) -> List[Dict]:
    findings = []
    try:
        ct     = session.client("cloudtrail", region_name=region)
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]

        if not trails:
            findings.append(_finding(
                "aws-cloudtrail-disabled", "cloudtrail",
                f"arn:aws:cloudtrail:{region}:{account}:trail/*", "critical",
                "CloudTrail is not enabled",
                "Enable CloudTrail: CloudTrail → Create trail → enable for all regions → enable log file validation.",
                ["CIS-3.1", "SOC2-CC7.2", "PCI-DSS-10.2"],
            ))
        else:
            for trail in trails:
                status = ct.get_trail_status(Name=trail["TrailARN"])
                if not status.get("IsLogging"):
                    findings.append(_finding(
                        "aws-cloudtrail-disabled", "cloudtrail", trail["TrailARN"], "high",
                        f"CloudTrail '{trail['Name']}' is not currently logging",
                        f"Start logging: CloudTrail → {trail['Name']} → Start logging.",
                        ["CIS-3.1", "SOC2-CC7.2"],
                    ))
    except Exception as e:
        logger.warning(f"[aws-auditor] CloudTrail check failed: {e}")
    return findings


# ── VPC ───────────────────────────────────────────────────────────────────────

async def _check_vpc(session, region: str, account: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_vpc_sync, session, region, account)


def _check_vpc_sync(session, region: str, account: str) -> List[Dict]:
    findings = []
    try:
        ec2  = session.client("ec2", region_name=region)
        vpcs = ec2.describe_vpcs()["Vpcs"]

        for vpc in vpcs:
            vpc_id   = vpc["VpcId"]
            resource = f"arn:aws:ec2:{region}:{account}:vpc/{vpc_id}"

            if vpc.get("IsDefault"):
                # Check if default VPC has any resources
                instances = ec2.describe_instances(
                    Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
                )["Reservations"]
                if instances:
                    findings.append(_finding(
                        "aws-vpc-default-used", "vpc", resource, "medium",
                        f"Default VPC '{vpc_id}' is in use",
                        "Move resources to a custom VPC with proper network segmentation, then delete the default VPC.",
                        ["CIS-5.3", "SOC2-CC6.6"],
                    ))

            # Flow logs
            flow_logs = ec2.describe_flow_logs(
                Filters=[{"Name": "resource-id", "Values": [vpc_id]}]
            )["FlowLogs"]
            if not flow_logs:
                findings.append(_finding(
                    "aws-vpc-flow-logs-off", "vpc", resource, "medium",
                    f"VPC '{vpc_id}' has no flow logs enabled",
                    f"Enable VPC flow logs: VPC → {vpc_id} → Flow logs → Create flow log.",
                    ["CIS-3.9", "SOC2-CC7.2"],
                ))

    except Exception as e:
        logger.warning(f"[aws-auditor] VPC check failed: {e}")
    return findings


# ── Helper ────────────────────────────────────────────────────────────────────

def _finding(
    rule_id:     str,
    service:     str,
    resource:    str,
    severity:    str,
    description: str,
    remediation: str,
    compliance:  list,
) -> Dict:
    return {
        "provider":    PROVIDER,
        "ruleId":      rule_id,
        "service":     service,
        "resource":    resource,
        "severity":    severity,
        "title":       description.split("'")[0].strip() if "'" in description else description[:80],
        "description": description,
        "remediation": remediation,
        "compliance":  compliance,
    }
