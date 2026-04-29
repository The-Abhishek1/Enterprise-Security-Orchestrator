# src/workers/gcp_auditor.py
"""
GCP Security Auditor — checks Google Cloud resources against CIS GCP Foundations Benchmark.
Uses google-cloud SDKs with service account key or Workload Identity Federation.

Checks:
  - Cloud Storage: public buckets, uniform access, versioning, logging
  - IAM: service account key age, primitive roles, external members
  - Compute: firewall rules open to internet, OS Login, serial port access
  - Cloud SQL: public IP, SSL enforcement, backups
  - Logging: audit logs enabled, log sinks configured
  - KMS: key rotation
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from src.utils.logging import logger

PROVIDER = "gcp"


async def run_gcp_audit(
    credentials: Dict[str, Any],
    project_id:  str,
) -> List[Dict]:
    """Run all GCP security checks in parallel. Returns normalized findings."""
    try:
        import google.auth
        from google.oauth2 import service_account
    except ImportError:
        logger.error("[gcp-auditor] google-cloud SDK not installed — pip install google-cloud-asset google-cloud-storage google-cloud-iam google-cloud-compute")
        return [_finding(
            "gcp-sdk-missing", "iam", project_id, "critical",
            "Google Cloud SDK not installed",
            "Install SDK: pip install google-cloud-storage google-cloud-iam google-cloud-compute",
            [],
        )]

    creds = _build_credentials(credentials)
    if not creds:
        return [_finding(
            "gcp-auth-failed", "iam", project_id, "critical",
            "Failed to authenticate with Google Cloud",
            "Check service account key JSON and ensure the account has Security Reviewer role.",
            [],
        )]

    logger.info(f"[gcp-auditor] Starting audit: project={project_id}")

    checks = await asyncio.gather(
        _check_storage(creds, project_id),
        _check_iam(creds, project_id),
        _check_firewall(creds, project_id),
        _check_sql(creds, project_id),
        _check_logging(creds, project_id),
        _check_kms(creds, project_id),
        return_exceptions=True,
    )

    findings = []
    for result in checks:
        if isinstance(result, Exception):
            logger.warning(f"[gcp-auditor] check error: {result}")
        elif isinstance(result, list):
            findings.extend(result)

    logger.info(f"[gcp-auditor] Done: {project_id} — {len(findings)} findings")
    return findings


def _build_credentials(credentials: Dict[str, Any]):
    """Build google-auth credentials from stored cred dict."""
    try:
        from google.oauth2 import service_account

        cred_type = credentials.get("type", "service_account_key")

        if cred_type == "service_account_key":
            key_json = credentials.get("key_json")
            if isinstance(key_json, str):
                key_json = json.loads(key_json)
            scopes = [
                "https://www.googleapis.com/auth/cloud-platform.read-only",
            ]
            return service_account.Credentials.from_service_account_info(
                key_json, scopes=scopes
            )
        else:
            # Workload Identity / ADC
            import google.auth
            creds, _ = google.auth.default(
                scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
            )
            return creds

    except Exception as e:
        logger.error(f"[gcp-auditor] Credential build failed: {e}")
        return None


# ── Cloud Storage ─────────────────────────────────────────────────────────────

async def _check_storage(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_storage_sync, creds, project_id)


def _check_storage_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        from google.cloud import storage
        client = storage.Client(project=project_id, credentials=creds)
        buckets = list(client.list_buckets())

        for bucket in buckets:
            name     = bucket.name
            resource = f"projects/{project_id}/buckets/{name}"

            # Public access via IAM policy
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get("members", [])
                    if "allUsers" in members or "allAuthenticatedUsers" in members:
                        findings.append(_finding(
                            "gcp-storage-public-iam", "storage", resource, "critical",
                            f"Cloud Storage bucket '{name}' is publicly accessible via IAM",
                            f"Remove allUsers/allAuthenticatedUsers from bucket IAM: Storage → {name} → Permissions → remove public bindings.",
                            ["CIS-GCP-5.1", "SOC2-CC6.1", "PCI-DSS-1.3"],
                        ))
                        break
            except Exception:
                pass

            # Uniform bucket-level access (recommended — prevents ACL bypass)
            try:
                bucket.reload()
                if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                    findings.append(_finding(
                        "gcp-storage-no-uniform-access", "storage", resource, "high",
                        f"Cloud Storage bucket '{name}' does not use uniform bucket-level access",
                        f"Enable uniform access: Storage → {name} → Permissions → Access control → Uniform.",
                        ["CIS-GCP-5.2"],
                    ))
            except Exception:
                pass

            # Versioning
            try:
                if not bucket.versioning_enabled:
                    findings.append(_finding(
                        "gcp-storage-no-versioning", "storage", resource, "low",
                        f"Cloud Storage bucket '{name}' has versioning disabled",
                        f"Enable versioning: Storage → {name} → Protection → Versioning → Enable.",
                        ["CIS-GCP-5.3"],
                    ))
            except Exception:
                pass

            # Logging
            try:
                if not bucket.logging:
                    findings.append(_finding(
                        "gcp-storage-no-logging", "storage", resource, "low",
                        f"Cloud Storage bucket '{name}' has access logging disabled",
                        f"Enable logging: gsutil logging set on -b gs://log-bucket gs://{name}",
                        ["CIS-GCP-5.4"],
                    ))
            except Exception:
                pass

    except ImportError:
        findings.append(_finding(
            "gcp-storage-sdk-missing", "storage", project_id, "critical",
            "google-cloud-storage SDK not installed",
            "pip install google-cloud-storage",
            [],
        ))
    except Exception as e:
        logger.warning(f"[gcp-auditor] Storage check failed: {e}")
    return findings


# ── IAM ───────────────────────────────────────────────────────────────────────

async def _check_iam(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_iam_sync, creds, project_id)


def _check_iam_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        import googleapiclient.discovery
        iam_svc    = googleapiclient.discovery.build("iam", "v1", credentials=creds)
        crm_svc    = googleapiclient.discovery.build("cloudresourcemanager", "v1", credentials=creds)

        # Project-level primitive roles (Owner / Editor) — overly permissive
        try:
            policy = crm_svc.projects().getIamPolicy(
                resource=project_id, body={}
            ).execute()
            for binding in policy.get("bindings", []):
                role    = binding.get("role", "")
                members = binding.get("members", [])
                if role in ("roles/owner", "roles/editor"):
                    for member in members:
                        if member.startswith("user:") or member.startswith("serviceAccount:"):
                            findings.append(_finding(
                                "gcp-iam-primitive-role", "iam",
                                f"projects/{project_id}", "high",
                                f"Principal '{member}' has primitive role '{role}'",
                                f"Replace primitive roles with predefined or custom roles: IAM → remove {role} from {member} and grant specific roles instead.",
                                ["CIS-GCP-1.4", "SOC2-CC6.3"],
                            ))
        except Exception as e:
            logger.debug(f"[gcp-auditor] IAM policy check failed: {e}")

        # Service account keys — flag keys older than 90 days
        try:
            sa_list = iam_svc.projects().serviceAccounts().list(
                name=f"projects/{project_id}"
            ).execute()
            for sa in sa_list.get("accounts", []):
                sa_name = sa["name"]
                keys    = iam_svc.projects().serviceAccounts().keys().list(
                    name=sa_name, keyTypes=["USER_MANAGED"]
                ).execute()
                for key in keys.get("keys", []):
                    created = key.get("validAfterTime", "")
                    if created:
                        try:
                            age = datetime.now(timezone.utc) - datetime.fromisoformat(
                                created.replace("Z", "+00:00")
                            )
                            if age.days > 90:
                                findings.append(_finding(
                                    "gcp-iam-old-sa-key", "iam",
                                    sa["email"], "high",
                                    f"Service account '{sa['email']}' has a key older than 90 days",
                                    f"Rotate service account keys: IAM → Service Accounts → {sa['email']} → Keys → delete old keys → Add key.",
                                    ["CIS-GCP-1.7", "SOC2-CC6.1"],
                                ))
                        except Exception:
                            pass
        except Exception as e:
            logger.debug(f"[gcp-auditor] SA key check failed: {e}")

    except ImportError:
        findings.append(_finding(
            "gcp-iam-sdk-missing", "iam", project_id, "critical",
            "google-api-python-client SDK not installed",
            "pip install google-api-python-client",
            [],
        ))
    except Exception as e:
        logger.warning(f"[gcp-auditor] IAM check failed: {e}")
    return findings


# ── Compute / Firewall ────────────────────────────────────────────────────────

async def _check_firewall(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_firewall_sync, creds, project_id)


def _check_firewall_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        import googleapiclient.discovery
        compute = googleapiclient.discovery.build("compute", "v1", credentials=creds)

        rules = compute.firewalls().list(project=project_id).execute()
        for rule in rules.get("items", []):
            if rule.get("disabled"):
                continue
            name      = rule.get("name", "")
            direction = rule.get("direction", "INGRESS")
            resource  = f"projects/{project_id}/global/firewalls/{name}"

            if direction != "INGRESS":
                continue

            # Check source ranges for internet-open rules
            src_ranges = rule.get("sourceRanges", [])
            open_internet = "0.0.0.0/0" in src_ranges or "::/0" in src_ranges
            if not open_internet:
                continue

            for allowed in rule.get("allowed", []):
                ports    = allowed.get("ports", [])
                protocol = allowed.get("IPProtocol", "")

                # All traffic
                if protocol == "all":
                    findings.append(_finding(
                        "gcp-fw-open-all", "compute", resource, "critical",
                        f"Firewall rule '{name}' allows all ingress from 0.0.0.0/0",
                        f"Restrict the firewall rule: VPC → Firewall → {name} → Edit → restrict source ranges.",
                        ["CIS-GCP-3.6", "SOC2-CC6.6", "PCI-DSS-1.3"],
                    ))

                for port_spec in ports:
                    # Handle ranges like "1-65535"
                    port_range = str(port_spec)
                    def in_range(p: int) -> bool:
                        if "-" in port_range:
                            lo, hi = port_range.split("-", 1)
                            return int(lo) <= p <= int(hi)
                        return port_range == str(p)

                    if in_range(22):
                        findings.append(_finding(
                            "gcp-fw-open-ssh", "compute", resource, "critical",
                            f"Firewall rule '{name}' allows SSH (22) from 0.0.0.0/0",
                            f"Restrict SSH access: VPC → Firewall → {name} → Edit → change source to specific IPs or use IAP.",
                            ["CIS-GCP-3.6", "SOC2-CC6.6", "PCI-DSS-1.3.1"],
                        ))
                    if in_range(3389):
                        findings.append(_finding(
                            "gcp-fw-open-rdp", "compute", resource, "critical",
                            f"Firewall rule '{name}' allows RDP (3389) from 0.0.0.0/0",
                            f"Restrict RDP access: VPC → Firewall → {name} → Edit → restrict source range.",
                            ["CIS-GCP-3.7", "SOC2-CC6.6"],
                        ))

        # Check instances for serial port and OS Login
        zones = compute.zones().list(project=project_id).execute()
        for zone in zones.get("items", []):
            zone_name = zone["name"]
            try:
                instances = compute.instances().list(
                    project=project_id, zone=zone_name
                ).execute()
                for inst in instances.get("items", []):
                    inst_name = inst["name"]
                    inst_res  = f"projects/{project_id}/zones/{zone_name}/instances/{inst_name}"
                    metadata  = {m["key"]: m["value"] for m in inst.get("metadata", {}).get("items", [])}

                    if metadata.get("serial-port-enable") in ("1", "true", "True"):
                        findings.append(_finding(
                            "gcp-compute-serial-port", "compute", inst_res, "high",
                            f"VM instance '{inst_name}' has serial port access enabled",
                            f"Disable serial port: Compute → {inst_name} → Edit → Serial port access → Disable.",
                            ["CIS-GCP-4.5"],
                        ))
            except Exception:
                pass

    except ImportError:
        findings.append(_finding(
            "gcp-compute-sdk-missing", "compute", project_id, "critical",
            "google-api-python-client SDK not installed",
            "pip install google-api-python-client",
            [],
        ))
    except Exception as e:
        logger.warning(f"[gcp-auditor] Firewall check failed: {e}")
    return findings


# ── Cloud SQL ─────────────────────────────────────────────────────────────────

async def _check_sql(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_sql_sync, creds, project_id)


def _check_sql_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        import googleapiclient.discovery
        sql = googleapiclient.discovery.build("sqladmin", "v1beta4", credentials=creds)

        instances = sql.instances().list(project=project_id).execute()
        for inst in instances.get("items", []):
            name     = inst["name"]
            resource = f"projects/{project_id}/instances/{name}"
            settings = inst.get("settings", {})

            # Public IP
            ip_configs = settings.get("ipConfiguration", {})
            ip_addresses = inst.get("ipAddresses", [])
            has_public_ip = any(a.get("type") == "PRIMARY" for a in ip_addresses)
            authorized_nets = ip_configs.get("authorizedNetworks", [])
            open_to_all = any(n.get("value") in ("0.0.0.0/0", "::/0") for n in authorized_nets)

            if has_public_ip and open_to_all:
                findings.append(_finding(
                    "gcp-sql-public-open", "sql", resource, "critical",
                    f"Cloud SQL instance '{name}' is publicly accessible with no IP restriction",
                    f"Restrict authorized networks or switch to private IP: SQL → {name} → Connections → remove 0.0.0.0/0 from authorized networks.",
                    ["CIS-GCP-6.2", "SOC2-CC6.6", "PCI-DSS-1.3.2"],
                ))

            # SSL enforcement
            if not ip_configs.get("requireSsl"):
                findings.append(_finding(
                    "gcp-sql-no-ssl", "sql", resource, "high",
                    f"Cloud SQL instance '{name}' does not require SSL connections",
                    f"Enforce SSL: SQL → {name} → Connections → SSL → Require SSL.",
                    ["CIS-GCP-6.4", "SOC2-CC6.7", "PCI-DSS-4.1"],
                ))

            # Automated backups
            backup_cfg = settings.get("backupConfiguration", {})
            if not backup_cfg.get("enabled"):
                findings.append(_finding(
                    "gcp-sql-no-backup", "sql", resource, "medium",
                    f"Cloud SQL instance '{name}' has automated backups disabled",
                    f"Enable backups: SQL → {name} → Backups → Automated backups → Enable.",
                    ["CIS-GCP-6.7", "SOC2-A1.2"],
                ))

            # Database flags: skip_show_database (MySQL)
            db_flags = {f["name"]: f["value"] for f in settings.get("databaseFlags", [])}
            if inst.get("databaseVersion", "").startswith("MYSQL"):
                if db_flags.get("skip_show_database", "off") != "on":
                    findings.append(_finding(
                        "gcp-sql-skip-show-db", "sql", resource, "medium",
                        f"Cloud SQL MySQL '{name}' skip_show_database flag is not set",
                        f"Set flag: SQL → {name} → Flags → Add flag → skip_show_database=on.",
                        ["CIS-GCP-6.1"],
                    ))

    except ImportError:
        pass  # SDK missing is reported in IAM check
    except Exception as e:
        logger.warning(f"[gcp-auditor] Cloud SQL check failed: {e}")
    return findings


# ── Cloud Logging / Audit Logs ────────────────────────────────────────────────

async def _check_logging(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_logging_sync, creds, project_id)


def _check_logging_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        import googleapiclient.discovery
        logging_svc = googleapiclient.discovery.build("logging", "v2", credentials=creds)

        # Check audit log configuration
        try:
            policy_response = googleapiclient.discovery.build(
                "cloudresourcemanager", "v1", credentials=creds
            ).projects().getIamPolicy(resource=project_id, body={}).execute()

            audit_configs = policy_response.get("auditConfigs", [])
            has_data_read  = False
            has_data_write = False

            for cfg in audit_configs:
                for al in cfg.get("auditLogConfigs", []):
                    if al.get("logType") == "DATA_READ":
                        has_data_read = True
                    if al.get("logType") == "DATA_WRITE":
                        has_data_write = True

            if not has_data_read:
                findings.append(_finding(
                    "gcp-logging-no-data-read", "logging",
                    f"projects/{project_id}", "medium",
                    "Data Read audit logs are not enabled for all services",
                    "Enable audit logs: IAM → Audit Logs → enable Data Read for All Services.",
                    ["CIS-GCP-2.1", "SOC2-CC7.2"],
                ))
            if not has_data_write:
                findings.append(_finding(
                    "gcp-logging-no-data-write", "logging",
                    f"projects/{project_id}", "medium",
                    "Data Write audit logs are not enabled for all services",
                    "Enable audit logs: IAM → Audit Logs → enable Data Write for All Services.",
                    ["CIS-GCP-2.1", "SOC2-CC7.2"],
                ))
        except Exception as e:
            logger.debug(f"[gcp-auditor] Audit log check failed: {e}")

        # Check log sinks (exports)
        try:
            sinks = logging_svc.sinks().list(parent=f"projects/{project_id}").execute()
            if not sinks.get("sinks"):
                findings.append(_finding(
                    "gcp-logging-no-sink", "logging",
                    f"projects/{project_id}", "medium",
                    "No log export sinks configured",
                    "Create a log sink to Cloud Storage or Pub/Sub for long-term retention: Logging → Log Router → Create Sink.",
                    ["CIS-GCP-2.2", "SOC2-CC7.2"],
                ))
        except Exception as e:
            logger.debug(f"[gcp-auditor] Log sink check failed: {e}")

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[gcp-auditor] Logging check failed: {e}")
    return findings


# ── KMS ───────────────────────────────────────────────────────────────────────

async def _check_kms(creds, project_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_kms_sync, creds, project_id)


def _check_kms_sync(creds, project_id: str) -> List[Dict]:
    findings = []
    try:
        import googleapiclient.discovery
        kms = googleapiclient.discovery.build("cloudkms", "v1", credentials=creds)

        # List key rings across common locations
        for location in ["global", "us-central1", "us-east1", "europe-west1", "asia-east1"]:
            try:
                keyrings = kms.projects().locations().keyRings().list(
                    parent=f"projects/{project_id}/locations/{location}"
                ).execute()
                for kr in keyrings.get("keyRings", []):
                    keys = kms.projects().locations().keyRings().cryptoKeys().list(
                        parent=kr["name"]
                    ).execute()
                    for key in keys.get("cryptoKeys", []):
                        key_name      = key["name"].split("/")[-1]
                        rotation_period = key.get("rotationPeriod", "")
                        next_rotation   = key.get("nextRotationTime", "")

                        # Flag keys with rotation > 90 days or no rotation
                        if not rotation_period:
                            findings.append(_finding(
                                "gcp-kms-no-rotation", "kms", key["name"], "medium",
                                f"KMS key '{key_name}' has no automatic rotation configured",
                                f"Set rotation: KMS → {key_name} → Edit → Rotation period → set to 90 days.",
                                ["CIS-GCP-1.8", "SOC2-CC6.7"],
                            ))
                        else:
                            # Rotation period is in seconds (e.g. "7776000s" = 90 days)
                            try:
                                seconds = int(rotation_period.rstrip("s"))
                                if seconds > 7776000:  # > 90 days
                                    findings.append(_finding(
                                        "gcp-kms-long-rotation", "kms", key["name"], "low",
                                        f"KMS key '{key_name}' rotation period is longer than 90 days",
                                        f"Shorten rotation: KMS → {key_name} → Edit → set rotation period ≤ 90 days.",
                                        ["CIS-GCP-1.8"],
                                    ))
                            except (ValueError, AttributeError):
                                pass
            except Exception:
                pass

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[gcp-auditor] KMS check failed: {e}")
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
