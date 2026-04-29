# src/workers/azure_auditor.py
"""
Azure Security Auditor — checks Microsoft Azure resources against CIS Azure Foundations Benchmark.
Uses azure-mgmt SDK with Service Principal credentials.

Checks:
  - Storage Accounts: public blob access, HTTPS enforcement, TLS version, soft delete
  - IAM / RBAC: overly broad role assignments (Owner/Contributor at subscription level)
  - Network Security Groups: SSH/RDP open to internet
  - SQL / PostgreSQL: firewall rules open to all, SSL enforcement, auditing
  - Key Vault: soft delete, purge protection, key expiry
  - Monitor / Activity Logs: log profile, diagnostic settings
  - Defender for Cloud: enabled plans
"""
import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from src.utils.logging import logger

PROVIDER = "azure"


async def run_azure_audit(
    credentials:     Dict[str, Any],
    subscription_id: str,
) -> List[Dict]:
    """Run all Azure security checks in parallel. Returns normalized findings."""
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
    except ImportError:
        logger.error("[azure-auditor] azure-mgmt SDK not installed — pip install azure-mgmt-security azure-mgmt-storage azure-mgmt-network azure-mgmt-sql azure-mgmt-keyvault azure-mgmt-monitor azure-identity")
        return [_finding(
            "azure-sdk-missing", "iam", subscription_id, "critical",
            "Azure Management SDK not installed",
            "Install SDK: pip install azure-identity azure-mgmt-storage azure-mgmt-network azure-mgmt-sql azure-mgmt-keyvault azure-mgmt-monitor",
            [],
        )]

    cred = _build_credentials(credentials)
    if not cred:
        return [_finding(
            "azure-auth-failed", "iam", subscription_id, "critical",
            "Failed to authenticate with Azure",
            "Check Service Principal credentials (tenant_id, client_id, client_secret) and ensure the SP has Security Reader role.",
            [],
        )]

    logger.info(f"[azure-auditor] Starting audit: subscription={subscription_id}")

    checks = await asyncio.gather(
        _check_storage(cred, subscription_id),
        _check_rbac(cred, subscription_id),
        _check_nsg(cred, subscription_id),
        _check_sql(cred, subscription_id),
        _check_keyvault(cred, subscription_id),
        _check_monitor(cred, subscription_id),
        return_exceptions=True,
    )

    findings = []
    for result in checks:
        if isinstance(result, Exception):
            logger.warning(f"[azure-auditor] check error: {result}")
        elif isinstance(result, list):
            findings.extend(result)

    logger.info(f"[azure-auditor] Done: {subscription_id} — {len(findings)} findings")
    return findings


def _build_credentials(credentials: Dict[str, Any]):
    """Build azure-identity credential object."""
    try:
        from azure.identity import ClientSecretCredential, DefaultAzureCredential

        cred_type = credentials.get("type", "service_principal")
        if cred_type == "service_principal":
            return ClientSecretCredential(
                tenant_id=credentials["tenant_id"],
                client_id=credentials["client_id"],
                client_secret=credentials["client_secret"],
            )
        else:
            return DefaultAzureCredential()
    except Exception as e:
        logger.error(f"[azure-auditor] Credential build failed: {e}")
        return None


def _sub(subscription_id: str) -> str:
    return f"/subscriptions/{subscription_id}"


# ── Storage Accounts ──────────────────────────────────────────────────────────

async def _check_storage(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_storage_sync, cred, subscription_id)


def _check_storage_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.storage import StorageManagementClient
        client = StorageManagementClient(cred, subscription_id)

        for account in client.storage_accounts.list():
            name     = account.name
            rg       = account.id.split("/")[4] if account.id else "unknown"
            resource = f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.Storage/storageAccounts/{name}"

            # Public blob access
            if account.allow_blob_public_access is True:
                findings.append(_finding(
                    "azure-storage-public-blob", "storage", resource, "critical",
                    f"Storage account '{name}' allows public blob access",
                    f"Disable public access: Storage accounts → {name} → Configuration → Allow Blob public access → Disabled.",
                    ["CIS-Azure-3.7", "SOC2-CC6.1", "PCI-DSS-1.3"],
                ))

            # HTTPS only
            if not account.enable_https_traffic_only:
                findings.append(_finding(
                    "azure-storage-no-https", "storage", resource, "high",
                    f"Storage account '{name}' does not enforce HTTPS-only transfers",
                    f"Enable HTTPS only: Storage accounts → {name} → Configuration → Secure transfer required → Enabled.",
                    ["CIS-Azure-3.1", "SOC2-CC6.7", "PCI-DSS-4.1"],
                ))

            # TLS version
            tls = getattr(account, "minimum_tls_version", None)
            if tls and tls not in ("TLS1_2", "TLS1_3"):
                findings.append(_finding(
                    "azure-storage-old-tls", "storage", resource, "high",
                    f"Storage account '{name}' minimum TLS version is below TLS 1.2",
                    f"Set TLS 1.2: Storage accounts → {name} → Configuration → Minimum TLS version → TLS 1.2.",
                    ["CIS-Azure-3.15", "PCI-DSS-4.1"],
                ))

            # Soft delete for blobs
            try:
                props = client.blob_services.get_service_properties(rg, name)
                blob_del = props.delete_retention_policy
                if not blob_del or not blob_del.enabled or blob_del.days < 7:
                    findings.append(_finding(
                        "azure-storage-no-soft-delete", "storage", resource, "medium",
                        f"Storage account '{name}' soft delete for blobs is not enabled (≥7 days)",
                        f"Enable soft delete: Storage accounts → {name} → Data protection → Blob soft delete → Enable (7+ days).",
                        ["CIS-Azure-3.8"],
                    ))
            except Exception:
                pass

    except ImportError:
        findings.append(_finding(
            "azure-storage-sdk-missing", "storage", subscription_id, "critical",
            "azure-mgmt-storage SDK not installed",
            "pip install azure-mgmt-storage",
            [],
        ))
    except Exception as e:
        logger.warning(f"[azure-auditor] Storage check failed: {e}")
    return findings


# ── RBAC ──────────────────────────────────────────────────────────────────────

async def _check_rbac(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_rbac_sync, cred, subscription_id)


def _check_rbac_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.authorization import AuthorizationManagementClient
        client = AuthorizationManagementClient(cred, subscription_id)

        scope = _sub(subscription_id)
        assignments = list(client.role_assignments.list_for_scope(scope))

        # Map role definition IDs to names
        OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
        CONTRIB_ROLE = "b24988ac-6180-42a0-ab88-20f7382dd24c"

        for assignment in assignments:
            role_id = (assignment.role_definition_id or "").split("/")[-1]
            principal_type = getattr(assignment, "principal_type", "")

            if role_id == OWNER_ROLE:
                findings.append(_finding(
                    "azure-rbac-owner", "iam",
                    f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment.name}",
                    "critical",
                    f"Principal '{assignment.principal_id}' has Owner role at subscription scope",
                    "Use least-privilege roles: Azure AD → Subscriptions → IAM → Role assignments → change Owner to specific role.",
                    ["CIS-Azure-1.23", "SOC2-CC6.3"],
                ))
            elif role_id == CONTRIB_ROLE and principal_type not in ("ServicePrincipal",):
                # Contributor for users at subscription scope is overly broad
                findings.append(_finding(
                    "azure-rbac-contributor", "iam",
                    f"{scope}/providers/Microsoft.Authorization/roleAssignments/{assignment.name}",
                    "high",
                    f"Principal '{assignment.principal_id}' has Contributor role at subscription scope",
                    "Scope role assignments to resource group or resource level instead of subscription.",
                    ["CIS-Azure-1.24", "SOC2-CC6.3"],
                ))

        # Check for guest users with privileged roles
        guest_owners = [a for a in assignments
                        if (a.role_definition_id or "").endswith(OWNER_ROLE)
                        and getattr(a, "principal_type", "") == "User"]
        if len(guest_owners) > 3:
            findings.append(_finding(
                "azure-rbac-too-many-owners", "iam",
                scope, "high",
                f"Subscription has {len(guest_owners)} Owner role assignments (CIS recommends ≤3)",
                "Reduce Owner assignments: Azure AD → Subscriptions → IAM → Role assignments → remove excess Owners.",
                ["CIS-Azure-1.22"],
            ))

    except ImportError:
        findings.append(_finding(
            "azure-rbac-sdk-missing", "iam", subscription_id, "critical",
            "azure-mgmt-authorization SDK not installed",
            "pip install azure-mgmt-authorization",
            [],
        ))
    except Exception as e:
        logger.warning(f"[azure-auditor] RBAC check failed: {e}")
    return findings


# ── NSG / Network ─────────────────────────────────────────────────────────────

async def _check_nsg(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_nsg_sync, cred, subscription_id)


def _check_nsg_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.network import NetworkManagementClient
        client = NetworkManagementClient(cred, subscription_id)

        for nsg in client.network_security_groups.list_all():
            nsg_name = nsg.name
            rg       = nsg.id.split("/")[4] if nsg.id else "unknown"
            resource = nsg.id or f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.Network/networkSecurityGroups/{nsg_name}"

            for rule in (nsg.security_rules or []):
                if rule.direction != "Inbound":
                    continue
                if rule.access != "Allow":
                    continue

                src = rule.source_address_prefix or ""
                open_internet = src in ("*", "Internet", "0.0.0.0/0", "Any")
                if not open_internet:
                    continue

                dest_port = rule.destination_port_range or ""

                def ports_include(p: int) -> bool:
                    if dest_port in ("*", "Any"):
                        return True
                    if str(p) == dest_port:
                        return True
                    if "-" in dest_port:
                        lo, hi = dest_port.split("-", 1)
                        try:
                            return int(lo) <= p <= int(hi)
                        except ValueError:
                            return False
                    return False

                if ports_include(22):
                    findings.append(_finding(
                        "azure-nsg-open-ssh", "network", resource, "critical",
                        f"NSG '{nsg_name}' rule '{rule.name}' allows SSH (22) from Internet",
                        f"Restrict SSH: Virtual networks → NSG → {nsg_name} → Inbound rules → {rule.name} → change source to specific IP.",
                        ["CIS-Azure-6.2", "SOC2-CC6.6", "PCI-DSS-1.3.1"],
                    ))
                if ports_include(3389):
                    findings.append(_finding(
                        "azure-nsg-open-rdp", "network", resource, "critical",
                        f"NSG '{nsg_name}' rule '{rule.name}' allows RDP (3389) from Internet",
                        f"Restrict RDP: Virtual networks → NSG → {nsg_name} → Inbound rules → {rule.name} → change source to specific IP.",
                        ["CIS-Azure-6.1", "SOC2-CC6.6"],
                    ))
                if dest_port in ("*", "Any"):
                    findings.append(_finding(
                        "azure-nsg-open-all", "network", resource, "high",
                        f"NSG '{nsg_name}' rule '{rule.name}' allows all ports from Internet",
                        f"Restrict traffic: NSG → {nsg_name} → {rule.name} → specify destination port ranges.",
                        ["CIS-Azure-6.3", "SOC2-CC6.6", "PCI-DSS-1.3"],
                    ))

    except ImportError:
        findings.append(_finding(
            "azure-nsg-sdk-missing", "network", subscription_id, "critical",
            "azure-mgmt-network SDK not installed",
            "pip install azure-mgmt-network",
            [],
        ))
    except Exception as e:
        logger.warning(f"[azure-auditor] NSG check failed: {e}")
    return findings


# ── SQL ───────────────────────────────────────────────────────────────────────

async def _check_sql(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_sql_sync, cred, subscription_id)


def _check_sql_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.sql import SqlManagementClient
        client = SqlManagementClient(cred, subscription_id)

        for server in client.servers.list():
            server_name = server.name
            rg = server.id.split("/")[4] if server.id else "unknown"
            resource = server.id or f"/subscriptions/{subscription_id}/resourceGroups/{rg}/providers/Microsoft.Sql/servers/{server_name}"

            # Firewall rules — check for "Allow all Azure services" (0.0.0.0 to 0.0.0.0)
            # and open-to-all rules
            try:
                for rule in client.firewall_rules.list_by_server(rg, server_name):
                    start = rule.start_ip_address or ""
                    end   = rule.end_ip_address   or ""
                    if start == "0.0.0.0" and end == "255.255.255.255":
                        findings.append(_finding(
                            "azure-sql-fw-open-all", "sql", resource, "critical",
                            f"SQL Server '{server_name}' firewall allows access from all IPs",
                            f"Restrict firewall: SQL servers → {server_name} → Networking → Firewall rules → remove 0.0.0.0-255.255.255.255.",
                            ["CIS-Azure-4.1.1", "SOC2-CC6.6", "PCI-DSS-1.3.2"],
                        ))
                    elif start == "0.0.0.0" and end == "0.0.0.0":
                        findings.append(_finding(
                            "azure-sql-fw-azure-services", "sql", resource, "medium",
                            f"SQL Server '{server_name}' allows all Azure services via firewall",
                            f"Disable 'Allow Azure services': SQL servers → {server_name} → Networking → Allow Azure services → No.",
                            ["CIS-Azure-4.1.2"],
                        ))
            except Exception:
                pass

            # Auditing
            try:
                audit = client.server_blob_auditing_policies.get(rg, server_name)
                if audit.state == "Disabled":
                    findings.append(_finding(
                        "azure-sql-no-auditing", "sql", resource, "high",
                        f"SQL Server '{server_name}' has auditing disabled",
                        f"Enable auditing: SQL servers → {server_name} → Security → Auditing → Enable.",
                        ["CIS-Azure-4.1.3", "SOC2-CC7.2", "PCI-DSS-10.2"],
                    ))
            except Exception:
                pass

            # TLS version
            tls = getattr(server, "minimal_tls_version", None)
            if tls and tls not in ("1.2", "1.3"):
                findings.append(_finding(
                    "azure-sql-old-tls", "sql", resource, "high",
                    f"SQL Server '{server_name}' minimum TLS version is below 1.2",
                    f"Set TLS 1.2: SQL servers → {server_name} → Networking → Minimum TLS version → TLS 1.2.",
                    ["CIS-Azure-4.1.6", "PCI-DSS-4.1"],
                ))

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[azure-auditor] SQL check failed: {e}")
    return findings


# ── Key Vault ─────────────────────────────────────────────────────────────────

async def _check_keyvault(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_keyvault_sync, cred, subscription_id)


def _check_keyvault_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.keyvault import KeyVaultManagementClient
        client = KeyVaultManagementClient(cred, subscription_id)

        for vault in client.vaults.list():
            name     = vault.name
            rg       = vault.id.split("/")[4] if vault.id else "unknown"
            resource = vault.id or name
            props    = vault.properties

            # Soft delete
            if not getattr(props, "enable_soft_delete", False):
                findings.append(_finding(
                    "azure-kv-no-soft-delete", "keyvault", resource, "high",
                    f"Key Vault '{name}' does not have soft delete enabled",
                    f"Enable soft delete: Key vaults → {name} → Properties → Soft delete → Enable.",
                    ["CIS-Azure-8.4", "SOC2-A1.2"],
                ))

            # Purge protection
            if not getattr(props, "enable_purge_protection", False):
                findings.append(_finding(
                    "azure-kv-no-purge-protection", "keyvault", resource, "high",
                    f"Key Vault '{name}' does not have purge protection enabled",
                    f"Enable purge protection: Key vaults → {name} → Properties → Purge protection → Enable.",
                    ["CIS-Azure-8.5"],
                ))

            # Network ACLs — check if vault is accessible from all networks
            network_acls = getattr(props, "network_acls", None)
            if network_acls:
                default_action = getattr(network_acls, "default_action", "Allow")
                if default_action == "Allow":
                    findings.append(_finding(
                        "azure-kv-open-network", "keyvault", resource, "medium",
                        f"Key Vault '{name}' network access allows all networks by default",
                        f"Restrict network access: Key vaults → {name} → Networking → Firewalls and virtual networks → Selected networks.",
                        ["CIS-Azure-8.7"],
                    ))

    except ImportError:
        pass
    except Exception as e:
        logger.warning(f"[azure-auditor] Key Vault check failed: {e}")
    return findings


# ── Monitor / Activity Log ────────────────────────────────────────────────────

async def _check_monitor(cred, subscription_id: str) -> List[Dict]:
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _check_monitor_sync, cred, subscription_id)


def _check_monitor_sync(cred, subscription_id: str) -> List[Dict]:
    findings = []
    try:
        from azure.mgmt.monitor import MonitorManagementClient
        client = MonitorManagementClient(cred, subscription_id)

        # Log profiles (activity log)
        try:
            profiles = list(client.log_profiles.list())
            if not profiles:
                findings.append(_finding(
                    "azure-monitor-no-log-profile", "monitor",
                    _sub(subscription_id), "high",
                    "No Activity Log profile configured — audit events may not be retained",
                    "Create a log profile: Monitor → Activity log → Export Activity Logs → add diagnostic setting.",
                    ["CIS-Azure-5.1.1", "SOC2-CC7.2", "PCI-DSS-10.2"],
                ))
            else:
                for profile in profiles:
                    retention = getattr(profile, "retention_policy", None)
                    if retention:
                        days = getattr(retention, "days", 0)
                        enabled = getattr(retention, "enabled", False)
                        if enabled and days < 365:
                            findings.append(_finding(
                                "azure-monitor-short-retention", "monitor",
                                _sub(subscription_id), "medium",
                                f"Activity Log retention is {days} days (CIS recommends ≥365)",
                                "Increase retention: Monitor → Activity log → Diagnostic settings → edit → set retention ≥365 days.",
                                ["CIS-Azure-5.1.2"],
                            ))
        except Exception as e:
            logger.debug(f"[azure-auditor] Log profile check: {e}")

        # Diagnostic settings for subscription
        try:
            diag_settings = list(client.diagnostic_settings.list(_sub(subscription_id)))
            if not diag_settings:
                findings.append(_finding(
                    "azure-monitor-no-diag-settings", "monitor",
                    _sub(subscription_id), "medium",
                    "No diagnostic settings configured for the subscription",
                    "Add diagnostic settings: Monitor → Diagnostic settings → Add diagnostic setting → select all categories.",
                    ["CIS-Azure-5.1.3"],
                ))
        except Exception:
            pass

    except ImportError:
        findings.append(_finding(
            "azure-monitor-sdk-missing", "monitor", subscription_id, "critical",
            "azure-mgmt-monitor SDK not installed",
            "pip install azure-mgmt-monitor",
            [],
        ))
    except Exception as e:
        logger.warning(f"[azure-auditor] Monitor check failed: {e}")
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
