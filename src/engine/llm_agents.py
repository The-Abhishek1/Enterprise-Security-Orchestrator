"""
llm_agents.py — enhanced LLM agents.

Improvements:
- AnalysisAgent: extracts CVE IDs, CVSS scores, mitigation, detection tips
- TaskProposerAgent: proposes tasks WITH specific flags
- ReportGeneratorAgent: includes CVE matches, attack chains, defensive priorities
- CVECorrelationAgent: NEW — matches findings against Xcloak CVE database
- GrafanaMetricsAgent: NEW — pushes scan metrics to Grafana/InfluxDB
"""
from typing import Dict, Any, List, Optional
import json
import asyncio
import uuid

from src.agents.planner.llm_factory import llm_factory
from src.agents.planner.prompt_templates import (
    ANALYSIS_SYSTEM_PROMPT, TASK_PROPOSER_PROMPT,
    REPORT_SYSTEM_PROMPT, get_report_prompt
)
from src.utils.logging import logger


def _prepare_findings(findings: List[Dict]) -> List[Dict]:
    """Strip large raw_data fields before sending to LLM."""
    clean = []
    for i, f in enumerate(findings):
        c = {k: v for k, v in f.items() if k not in ("raw_data",) and v is not None}
        c["_index"] = i
        # Truncate long strings
        for field in ("finding", "version", "impact"):
            if isinstance(c.get(field), str):
                c[field] = c[field][:200]
        clean.append(c)
    return clean


class AnalysisAgent:
    """
    Validates findings, assigns severity, extracts CVEs, suggests mitigations.
    Improved: CVE IDs in output, CVSS scores, mitigation per finding, detection tips.
    """
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except Exception:
            pass
    
    async def analyze(self, findings: List[Dict], target: str,
                      existing_cve_ids: Optional[List[str]] = None) -> Dict:
        if not findings:
            return {"validated_findings": [], "removed": 0, "summary": "No findings to analyze"}
        
        if not self.llm_client:
            # No LLM — just pass through with basic severity
            return {"validated_findings": findings, "removed": 0,
                    "summary": "LLM unavailable — findings unvalidated"}
        
        try:
            # Process in batches of 10
            all_validated = []
            total_removed = 0
            summary_parts = []
            
            for batch_start in range(0, len(findings), 10):
                batch = findings[batch_start:batch_start + 10]
                clean = _prepare_findings(batch)
                
                cve_hint = ""
                if existing_cve_ids:
                    cve_hint = f"\nKnown CVEs from our database for this target area: {', '.join(existing_cve_ids[:10])}"
                
                prompt = f"""Target: {target}{cve_hint}

Analyze these {len(clean)} security findings:
{json.dumps(clean, indent=2, default=str)}"""
                
                response = await asyncio.wait_for(
                    self.llm_client.generate_json(prompt, ANALYSIS_SYSTEM_PROMPT),
                    timeout=180.0
                )
                
                # Build validation map
                vmap = {v.get("index", -1): v for v in response.get("validated_findings", [])}
                
                for i, finding in enumerate(batch):
                    v = vmap.get(i, vmap.get(batch_start + i))
                    if not v:
                        all_validated.append({**finding, "validated": False})
                        continue
                    if v.get("false_positive"):
                        total_removed += 1
                        continue
                    enriched = {
                        **finding,
                        "validated":          True,
                        "validated_severity": v.get("severity", finding.get("severity","info")),
                        "cvss_score":         v.get("cvss_score", 0.0),
                        "impact":             v.get("impact", ""),
                        "mitigation":         v.get("mitigation", ""),
                        "detection_tip":      v.get("detection_tip", ""),
                        "defensive_note":     v.get("defensive_note", ""),
                        "false_positive":     False,
                    }
                    # Merge CVE IDs from LLM with parser-extracted ones
                    llm_cves  = v.get("cve_ids", [])
                    orig_cves = finding.get("cve_ids", [])
                    enriched["cve_ids"] = list(set(llm_cves + orig_cves))
                    all_validated.append(enriched)
                
                if response.get("summary"):
                    summary_parts.append(response["summary"])
            
            logger.info(f"🧠 Analysis: {len(all_validated)} valid, {total_removed} FP removed")
            return {
                "validated_findings": all_validated,
                "removed": total_removed,
                "summary": " ".join(summary_parts) or "Analysis complete",
                "critical_count": sum(1 for f in all_validated if f.get("validated_severity") == "critical"),
                "immediate_action_required": any(f.get("validated_severity") == "critical" for f in all_validated),
            }
        except asyncio.TimeoutError:
            logger.warning("Analysis agent timed out — returning unvalidated findings")
            return {"validated_findings": findings, "removed": 0, "summary": "Analysis timed out"}
        except Exception as e:
            logger.error(f"Analysis agent error: {e}")
            return {"validated_findings": findings, "removed": 0, "summary": f"Analysis error: {e}"}


class TaskProposerAgent:
    """Proposes follow-up tasks with specific tool flags based on findings."""
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except Exception:
            pass
    
    async def propose(self, findings: List[Dict], target: str, goal: str,
                      tools_used: List[str], allowed_tools: Optional[List[str]] = None,
                      dynamic_tasks_used: int = 0, max_dynamic: int = 3) -> Dict:
        if dynamic_tasks_used >= max_dynamic:
            return {"should_propose": False, "proposals": [],
                    "stop_reason": f"Max dynamic tasks ({max_dynamic}) reached"}
        
        if not self.llm_client:
            return {"should_propose": False, "proposals": [], "stop_reason": "LLM unavailable"}
        
        # Only interesting findings (not info-level port listings)
        interesting = [f for f in findings if f.get("validated_severity", f.get("severity","info")) in ("critical","high","medium")]
        
        if not interesting:
            return {"should_propose": False, "proposals": [],
                    "stop_reason": "No significant findings to follow up on"}
        
        try:
            allowed = f"\nAllowed tools: {', '.join(allowed_tools)}" if allowed_tools else ""
            prompt = f"""Target: {target}
Goal: {goal}
Tools already used: {', '.join(tools_used)}{allowed}
Dynamic tasks used so far: {dynamic_tasks_used}/{max_dynamic}

Findings that may warrant follow-up:
{json.dumps(_prepare_findings(interesting[:15]), indent=2, default=str)}

Should we run additional scans? If yes, propose specific tasks with exact flags."""
            
            response = await asyncio.wait_for(
                self.llm_client.generate_json(prompt, TASK_PROPOSER_PROMPT),
                timeout=120.0
            )
            
            # Filter proposals to allowed tools
            if allowed_tools and response.get("proposals"):
                response["proposals"] = [
                    p for p in response["proposals"]
                    if p.get("tool") in allowed_tools
                ]
                if not response["proposals"]:
                    response["should_propose"] = False
                    response["stop_reason"] = "Proposed tools not available in current tier"
            
            return response
        except asyncio.TimeoutError:
            return {"should_propose": False, "proposals": [], "stop_reason": "Proposal timed out"}
        except Exception as e:
            logger.error(f"Task proposer error: {e}")
            return {"should_propose": False, "proposals": [], "stop_reason": str(e)}


class ReportGeneratorAgent:
    """
    Generates professional pentest report with:
    - Executive summary
    - Finding details with CVEs and CVSS
    - Attack chain analysis
    - Defensive recommendations (prioritized)
    - CVE database matches
    """
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except Exception:
            pass
    
    async def generate(self, target: str, findings: List[Dict], duration: float,
                        tools_used: List[str], goal: str,
                        cve_matches: Optional[List[Dict]] = None) -> str:
        if not self.llm_client:
            return self._fallback_report(target, findings, duration, tools_used)
        
        try:
            prompt = get_report_prompt(
                target=target, findings=findings, duration=duration,
                tools_used=tools_used, goal=goal, cve_matches=cve_matches
            )
            
            report = await asyncio.wait_for(
                self.llm_client.generate(prompt, REPORT_SYSTEM_PROMPT),
                timeout=120.0
            )
            return report or self._fallback_report(target, findings, duration, tools_used)
        except asyncio.TimeoutError:
            logger.warning("Report generation timed out, using fallback")
            return self._fallback_report(target, findings, duration, tools_used)
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return self._fallback_report(target, findings, duration, tools_used)
    
    def _fallback_report(self, target: str, findings: List[Dict], duration: float,
                          tools_used: List[str]) -> str:
        counts: Dict[str,int] = {}
        for f in findings:
            s = f.get("validated_severity", f.get("severity","info"))
            counts[s] = counts.get(s,0) + 1
        
        lines = [
            f"# Penetration Test Report",
            f"",
            f"## Target: {target}",
            f"## Duration: {duration:.0f}s",
            f"## Tools: {', '.join(tools_used)}",
            f"",
        ]
        
        # Severity groups
        for sev in ("critical","high","medium","low","info"):
            group = [f for f in findings if f.get("validated_severity", f.get("severity","info")) == sev]
            if group:
                lines.append(f"## {sev.capitalize()} Findings ({len(group)})")
                for f in group[:10]:
                    port = f.get("port","")
                    desc = f.get("finding", f.get("service",""))[:150]
                    cves = ", ".join(f.get("cve_ids",[]))
                    mit  = f.get("mitigation","")
                    line = f"- {f.get('type','unknown')}"
                    if port: line += f" (port {port})"
                    if desc: line += f": {desc}"
                    if cves: line += f" | {cves}"
                    lines.append(line)
                    if mit:
                        lines.append(f"  **Fix:** {mit}")
        
        lines.extend(["", "## Recommendations", "- Review open ports", "- Patch identified services"])
        return "\n".join(lines)


class CVECorrelationAgent:
    """
    NEW: Matches scan findings against the Xcloak CVE database.
    Returns matched CVE records with CVSS scores and descriptions.
    Used to enrich reports and update the CVE page.
    """
    
    async def correlate(self, findings: List[Dict], pg_pool) -> List[Dict]:
        """Look up CVEs from findings in the local Xcloak CVE database."""
        if not pg_pool:
            return []
        
        matches = []
        seen_cves: set = set()
        
        # Collect all CVE IDs from findings
        all_cve_ids = []
        for f in findings:
            all_cve_ids.extend(f.get("cve_ids", []))
        
        # Also query by service/version
        service_terms = list(set(
            f"{f.get('service','')} {f.get('version','')}".strip()
            for f in findings if f.get("service")
        ))
        
        try:
            async with pg_pool.acquire() as c:
                # Match by CVE ID
                if all_cve_ids:
                    rows = await c.fetch(
                        "SELECT cve_id,description,cvss_score,severity,published_at "
                        "FROM cves WHERE cve_id = ANY($1::text[]) LIMIT 50",
                        list(set(all_cve_ids))
                    )
                    for r in rows:
                        if r["cve_id"] not in seen_cves:
                            seen_cves.add(r["cve_id"])
                            matches.append(dict(r))
                
                # Match by service/version keywords
                for term in service_terms[:10]:
                    if len(term) < 3:
                        continue
                    rows = await c.fetch(
                        "SELECT cve_id,description,cvss_score,severity "
                        "FROM cves WHERE description ILIKE $1 AND cvss_score >= 7.0 LIMIT 5",
                        f"%{term}%"
                    )
                    for r in rows:
                        if r["cve_id"] not in seen_cves:
                            seen_cves.add(r["cve_id"])
                            matches.append(dict(r))
        except Exception as e:
            logger.warning(f"CVE correlation failed: {e}")
        
        logger.info(f"🔗 CVE correlation: {len(matches)} matches found")
        return matches
    
    async def update_cve_scan_context(self, cve_ids: List[str], target: str,
                                       process_id: str, pg_pool) -> None:
        """Update CVE records with scan context (when this CVE was last seen)."""
        if not pg_pool or not cve_ids:
            return
        try:
            async with pg_pool.acquire() as c:
                await c.execute(
                    """UPDATE cves 
                       SET last_seen_at=NOW(), scan_count=COALESCE(scan_count,0)+1
                       WHERE cve_id = ANY($1::text[])""",
                    cve_ids
                )
        except Exception as e:
            logger.debug(f"CVE scan context update failed (non-critical): {e}")


class GrafanaMetricsAgent:
    """
    NEW: Pushes scan metrics to Grafana via InfluxDB line protocol or Pushgateway.
    Provides real-time visibility into scan activity across all users.
    """
    
    def __init__(self):
        import os
        self.grafana_url  = os.getenv("GRAFANA_PUSHGATEWAY_URL", "")
        self.influx_url   = os.getenv("INFLUXDB_URL", "")
        self.influx_token = os.getenv("INFLUXDB_TOKEN", "")
        self.influx_org   = os.getenv("INFLUXDB_ORG", "xcloak")
        self.influx_bucket = os.getenv("INFLUXDB_BUCKET", "eso_metrics")
        self.enabled      = bool(self.influx_url or self.grafana_url)
    
    async def push_scan_started(self, process_id: str, user_id: str,
                                  target: str, tier: str) -> None:
        if not self.enabled:
            return
        await self._push_metric("scan_started", 1, {
            "process_id": process_id, "user_id": user_id[:8],
            "target_hash": str(hash(target) % 100000), "tier": tier
        })
    
    async def push_scan_completed(self, process_id: str, user_id: str,
                                    duration: float, findings_count: int,
                                    risk_level: str, tier: str) -> None:
        if not self.enabled:
            return
        await self._push_metric("scan_completed", 1, {
            "process_id": process_id, "user_id": user_id[:8],
            "tier": tier, "risk_level": risk_level
        }, fields={
            "duration_seconds": duration,
            "findings_count":   findings_count,
        })
    
    async def push_finding_severity(self, severity_counts: Dict[str,int],
                                     process_id: str) -> None:
        if not self.enabled:
            return
        for sev, count in severity_counts.items():
            await self._push_metric("findings_by_severity", count, {
                "severity": sev, "process_id": process_id[:12]
            })
    
    async def _push_metric(self, measurement: str, value: float,
                             tags: Dict[str,str], fields: Optional[Dict] = None) -> None:
        if not self.influx_url:
            return
        try:
            import aiohttp
            tag_str = ",".join(f"{k}={v}" for k,v in tags.items() if v)
            field_str = f"value={value}"
            if fields:
                field_str += "," + ",".join(f"{k}={v}" for k,v in fields.items())
            line = f"{measurement},{tag_str} {field_str}"
            
            async with aiohttp.ClientSession() as session:
                await asyncio.wait_for(
                    session.post(
                        f"{self.influx_url}/api/v2/write",
                        params={"org": self.influx_org, "bucket": self.influx_bucket, "precision": "s"},
                        headers={"Authorization": f"Token {self.influx_token}", "Content-Type": "text/plain"},
                        data=line,
                    ),
                    timeout=3.0
                )
        except Exception as e:
            logger.debug(f"Metrics push failed (non-critical): {e}")


# ── Slack notification agent ───────────────────────────────────────────────────
class SlackNotificationAgent:
    """
    Sends Slack notifications for critical findings and completed scans.
    Set SLACK_WEBHOOK_URL in .env to enable.
    """
    
    def __init__(self):
        import os
        self.webhook_url = os.getenv("SLACK_WEBHOOK_URL", "")
        self.enabled     = bool(self.webhook_url)
    
    async def notify_scan_complete(self, target: str, findings_count: int,
                                     risk_level: str, process_id: str,
                                     critical_count: int = 0) -> None:
        if not self.enabled:
            return
        
        color = {"critical":"#FF0000","high":"#FF6600","medium":"#FFA500",
                  "low":"#00AA00","none":"#36A64F"}.get(risk_level, "#808080")
        
        text = f":shield: Scan complete: *{target}*"
        if critical_count > 0:
            text = f":rotating_light: *CRITICAL FINDINGS* on {target}"
        
        await self._send({
            "text": text,
            "attachments": [{
                "color":  color,
                "fields": [
                    {"title":"Risk Level", "value":risk_level.upper(), "short":True},
                    {"title":"Findings",   "value":str(findings_count), "short":True},
                    {"title":"Process ID", "value":process_id, "short":False},
                ]
            }]
        })
    
    async def notify_critical_finding(self, finding: Dict, target: str) -> None:
        if not self.enabled:
            return
        cves = ", ".join(finding.get("cve_ids",[]))
        await self._send({
            "text": f":rotating_light: Critical finding on *{target}*",
            "attachments": [{
                "color": "#FF0000",
                "fields": [
                    {"title":"Type",       "value":finding.get("type","unknown"),   "short":True},
                    {"title":"CVEs",       "value":cves or "N/A",                  "short":True},
                    {"title":"Finding",    "value":finding.get("finding","")[:200], "short":False},
                    {"title":"Mitigation","value":finding.get("mitigation","TBD"), "short":False},
                ]
            }]
        })
    
    async def _send(self, payload: Dict) -> None:
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await asyncio.wait_for(
                    session.post(self.webhook_url, json=payload),
                    timeout=5.0
                )
        except Exception as e:
            logger.debug(f"Slack notification failed (non-critical): {e}")


# Singletons
grafana_agent = GrafanaMetricsAgent()
slack_agent   = SlackNotificationAgent()
cve_agent     = CVECorrelationAgent()
