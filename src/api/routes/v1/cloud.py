# src/api/routes/v1/cloud.py
"""
Cloud Security Posture Management (CSPM) — ESO side.
Receives audit jobs from XCloak, runs cloud auditors, returns findings + scored breakdown.

Supported providers:
  aws   — S3, EC2/SG, RDS, IAM, CloudTrail, VPC (CIS AWS Foundations)
  gcp   — Storage, IAM, Firewall, Cloud SQL, Logging, KMS (CIS GCP Foundations)
  azure — Storage, RBAC, NSG, SQL, Key Vault, Monitor (CIS Azure Foundations)
"""
import asyncio
from fastapi  import APIRouter, HTTPException, Request
from pydantic import BaseModel
from typing   import Optional, Dict, Any

from src.utils.logging import logger
from src.core.config   import get_settings

router = APIRouter(prefix="/cloud", tags=["cloud"])


class AuditRequest(BaseModel):
    account_id:    str             # XCloak DB account ID
    provider:      str             # aws | gcp | azure
    cloud_account: str             # actual cloud account/project/subscription ID
    region:        str = "us-east-1"
    credentials:   Dict[str, Any]  # provider-specific creds (decrypted by XCloak before sending)
    callback_url:  str


def _check_internal(request: Request):
    expected = get_settings().internal_email_secret
    secret   = request.headers.get("X-Internal-Secret", "")
    if not secret or secret != expected:
        raise HTTPException(403, "Forbidden — internal endpoint")


@router.post("/audit")
async def trigger_audit(req: AuditRequest, request: Request):
    """XCloak calls this to start a cloud security audit. Returns immediately; results via callback."""
    _check_internal(request)
    logger.info(f"[cloud] Audit queued: {req.provider}/{req.cloud_account} (id={req.account_id})")
    asyncio.create_task(_run_audit(req))
    return {"ok": True, "account_id": req.account_id}


@router.get("/supported")
async def supported_checks(request: Request):
    """Return list of supported audit checks per provider."""
    _check_internal(request)
    return {
        "aws":   list(_AWS_CHECKS.keys()),
        "gcp":   list(_GCP_CHECKS.keys()),
        "azure": list(_AZURE_CHECKS.keys()),
    }


async def _run_audit(req: AuditRequest):
    """Full audit pipeline — run checks then call back with scored results."""
    try:
        if req.provider == "aws":
            from src.workers.aws_auditor import run_aws_audit
            findings = await run_aws_audit(req.credentials, req.region, req.cloud_account)

        elif req.provider == "gcp":
            from src.workers.gcp_auditor import run_gcp_audit
            findings = await run_gcp_audit(req.credentials, req.cloud_account)

        elif req.provider == "azure":
            from src.workers.azure_auditor import run_azure_audit
            findings = await run_azure_audit(req.credentials, req.cloud_account)

        else:
            logger.warning(f"[cloud] Unknown provider: {req.provider}")
            findings = []

        # Score with full breakdown
        from src.workers.cloud_scorer import score_findings, score_to_dict
        score_result = score_findings(findings, provider=req.provider)
        score_dict   = score_to_dict(score_result)

        await _callback(req.callback_url, req.account_id, findings, score_result.overall, score_dict)
        logger.info(
            f"[cloud] Audit complete: {req.provider}/{req.cloud_account} — "
            f"{len(findings)} findings, score={score_result.overall} ({score_result.grade})"
        )

    except Exception as e:
        logger.error(f"[cloud] Audit failed for {req.account_id}: {e}", exc_info=True)
        await _callback(req.callback_url, req.account_id, [], None, None, error=str(e))


async def _callback(
    callback_url:  str,
    account_id:    str,
    findings:      list,
    posture_score: Optional[int],
    score_detail:  Optional[Dict] = None,
    error:         Optional[str]  = None,
):
    import httpx
    settings = get_settings()
    payload  = {
        "accountId":    account_id,
        "findings":     findings,
        "postureScore": posture_score,
        "scoreDetail":  score_detail,
    }
    if error:
        payload["error"] = error

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            res = await client.patch(
                callback_url,
                json=payload,
                headers={"X-Internal-Secret": settings.internal_email_secret},
            )
            if not res.is_success:
                logger.warning(f"[cloud] callback failed ({res.status_code}): {res.text[:200]}")
    except Exception as e:
        logger.error(f"[cloud] callback error: {e}")


# ── Check registries (used by /supported endpoint) ────────────────────────────

_AWS_CHECKS = {
    "aws-s3-public-access":        "S3 bucket allows public access",
    "aws-s3-no-encryption":        "S3 bucket has no server-side encryption",
    "aws-s3-no-versioning":        "S3 bucket has no versioning enabled",
    "aws-s3-no-logging":           "S3 bucket access logging not enabled",
    "aws-ec2-open-sg-ssh":         "Security group allows SSH from 0.0.0.0/0",
    "aws-ec2-open-sg-rdp":         "Security group allows RDP from 0.0.0.0/0",
    "aws-ec2-open-sg-all":         "Security group allows all traffic from 0.0.0.0/0",
    "aws-ec2-unencrypted-volume":  "EBS volume is not encrypted",
    "aws-rds-public":              "RDS instance is publicly accessible",
    "aws-rds-no-encryption":       "RDS instance storage not encrypted",
    "aws-rds-no-backup":           "RDS automated backups disabled",
    "aws-iam-root-access-keys":    "Root account has active access keys",
    "aws-iam-no-mfa":              "IAM user has no MFA enabled",
    "aws-iam-admin-policy":        "IAM user has AdministratorAccess attached",
    "aws-cloudtrail-disabled":     "CloudTrail is not enabled or logging",
    "aws-vpc-flow-logs-off":       "VPC flow logs not enabled",
    "aws-vpc-default-used":        "Default VPC is in use",
}

_GCP_CHECKS = {
    "gcp-storage-public-iam":      "Cloud Storage bucket is publicly accessible via IAM",
    "gcp-storage-no-uniform-access": "Bucket does not use uniform bucket-level access",
    "gcp-storage-no-versioning":   "Cloud Storage bucket versioning disabled",
    "gcp-storage-no-logging":      "Cloud Storage bucket access logging disabled",
    "gcp-iam-primitive-role":      "Principal has primitive Owner/Editor role",
    "gcp-iam-old-sa-key":          "Service account key is older than 90 days",
    "gcp-fw-open-all":             "Firewall allows all ingress from 0.0.0.0/0",
    "gcp-fw-open-ssh":             "Firewall allows SSH (22) from 0.0.0.0/0",
    "gcp-fw-open-rdp":             "Firewall allows RDP (3389) from 0.0.0.0/0",
    "gcp-compute-serial-port":     "VM instance has serial port access enabled",
    "gcp-sql-public-open":         "Cloud SQL is publicly accessible with no IP restriction",
    "gcp-sql-no-ssl":              "Cloud SQL does not require SSL connections",
    "gcp-sql-no-backup":           "Cloud SQL automated backups disabled",
    "gcp-logging-no-data-read":    "Data Read audit logs not enabled",
    "gcp-logging-no-data-write":   "Data Write audit logs not enabled",
    "gcp-logging-no-sink":         "No log export sinks configured",
    "gcp-kms-no-rotation":         "KMS key has no automatic rotation",
    "gcp-kms-long-rotation":       "KMS key rotation period exceeds 90 days",
}

_AZURE_CHECKS = {
    "azure-storage-public-blob":   "Storage account allows public blob access",
    "azure-storage-no-https":      "Storage account does not enforce HTTPS-only",
    "azure-storage-old-tls":       "Storage account minimum TLS version below 1.2",
    "azure-storage-no-soft-delete": "Storage account blob soft delete not enabled",
    "azure-rbac-owner":            "Principal has Owner role at subscription scope",
    "azure-rbac-contributor":      "User has Contributor role at subscription scope",
    "azure-rbac-too-many-owners":  "Subscription has too many Owner role assignments",
    "azure-nsg-open-ssh":          "NSG allows SSH (22) from Internet",
    "azure-nsg-open-rdp":          "NSG allows RDP (3389) from Internet",
    "azure-nsg-open-all":          "NSG allows all ports from Internet",
    "azure-sql-fw-open-all":       "SQL Server firewall allows all IPs",
    "azure-sql-no-auditing":       "SQL Server has auditing disabled",
    "azure-sql-old-tls":           "SQL Server minimum TLS below 1.2",
    "azure-kv-no-soft-delete":     "Key Vault soft delete not enabled",
    "azure-kv-no-purge-protection": "Key Vault purge protection not enabled",
    "azure-kv-open-network":       "Key Vault accessible from all networks",
    "azure-monitor-no-log-profile": "No Activity Log profile configured",
    "azure-monitor-short-retention": "Activity Log retention below 365 days",
}
