# src/engine/llm_agents.py

"""
LLM-powered agents for the execution engine.
Each agent is a single LLM call with a focused prompt.
No hardcoded logic — everything is decided by the LLM.
"""

from typing import Dict, Any, List, Optional
import json
import asyncio
import uuid

from src.agents.planner.llm_factory import llm_factory
from src.utils.logging import logger


class AnalysisAgent:
    """Validates findings, assigns severity, removes false positives."""
    
    SYSTEM_PROMPT = """You are a senior penetration tester analyzing scan results.

For each finding, determine:
1. Is it a true positive or false positive?
2. What is the actual severity? (critical/high/medium/low/info)
3. What's the security impact?

Respond with ONLY valid JSON:
{
  "validated_findings": [
    {
      "index": 0,
      "valid": true,
      "severity": "medium",
      "impact": "Brief impact description (max 20 words)",
      "false_positive": false
    }
  ],
  "summary": "Brief assessment (1-2 sentences)"
}

Rules:
- index = position in the findings list (0-based)
- Be skeptical of info-level nuclei findings — many are just technology detection
- Open ports alone are not vulnerabilities unless the service is dangerous
- Filtered ports are NOT findings — they indicate a firewall is working"""
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except:
            pass
    
    async def analyze(self, findings: List[Dict], target: str) -> Dict:
        """Analyze and validate findings."""
        
        if not self.llm_client or not findings:
            return {"validated_findings": findings, "removed": 0, "summary": "No LLM available"}
        
        try:
            clean_findings = _prepare_findings(findings[:10])
            
            prompt = f"""Target: {target}

Analyze these {len(clean_findings)} findings:
{json.dumps(clean_findings, indent=2)}"""

            response = await asyncio.wait_for(
                self.llm_client.generate_json(prompt, self.SYSTEM_PROMPT),
                timeout=20.0
            )
            
            # Apply LLM validation
            validated = []
            removed = 0
            
            validation_map = {}
            for item in response.get("validated_findings", []):
                validation_map[item.get("index", -1)] = item
            
            for i, finding in enumerate(findings):
                validation = validation_map.get(i)
                if validation:
                    if validation.get("false_positive", False):
                        removed += 1
                        continue
                    finding = {**finding}
                    finding["validated_severity"] = validation.get("severity", finding.get("severity", "info"))
                    finding["impact"] = validation.get("impact", "")
                    finding["validated"] = True
                    validated.append(finding)
                else:
                    finding = {**finding, "validated": False}
                    validated.append(finding)
            
            summary = response.get("summary", "Analysis complete")
            logger.info(f"🧠 Analysis: {len(validated)} valid, {removed} false positives removed")
            logger.info(f"🧠 {summary}")
            
            return {"validated_findings": validated, "removed": removed, "summary": summary}
            
        except Exception as e:
            logger.warning(f"⚠️ Analysis failed ({e}), accepting all findings")
            return {"validated_findings": findings, "removed": 0, "summary": f"Analysis failed: {e}"}


class TaskProposerAgent:
    """Proposes next tasks based on findings and execution history."""
    
    SYSTEM_PROMPT = """You are a penetration testing expert deciding what to scan next.

Available tools:
- nmap: Port scanning, service detection. Args: target, scan_type ("-sT -sV"), ports, timing ("-T4")
- nuclei: Vulnerability scanning. Args: target, severity ("critical,high,medium")
- gobuster: Directory brute-force on web servers. Args: target (http://...), mode ("dir"), wordlist ("/usr/share/wordlists/dirb/common.txt"), threads (20), extensions ("php,html,txt,bak")
- nikto: Web server vulnerability scanner. Args: target (http://...). Finds dangerous files, outdated software, server misconfigurations.
- ffuf: Fast web fuzzer. Args: target (http://...), wordlist ("/usr/share/wordlists/dirb/common.txt"), threads (20). Use instead of gobuster for faster results.
- whatweb: Web tech fingerprinting. Args: target, aggression (1-4). Identifies CMS, frameworks, server software.
- sqlmap: SQL injection testing. Args: target (URL with params), level (1-5), risk (1-3)

CRITICAL RULES:
- NEVER propose a tool that already ran against the same target
- Check "Already executed" list carefully
- gobuster/ffuf/nikto REQUIRE an HTTP URL (http:// or https://)
- sqlmap REQUIRES a URL with query parameters (e.g. ?id=1)
- Use whatweb for quick tech fingerprinting before deeper scans
- Use nikto for web server checks (complements nuclei)
- Use ffuf OR gobuster for directory discovery, not both
- If all useful scans are done, return empty proposals
- Max 2 proposals per round

Respond with ONLY valid JSON:
{
  "proposals": [
    {
      "task_name": "Short descriptive name",
      "tool": "nikto",
      "reason": "Why this is needed (1 sentence)",
      "priority": 8,
      "parameters": {
        "target": "http://example.com"
      }
    }
  ],
  "reasoning": "Overall strategy (1 sentence)"
}"""
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except:
            pass
    
    async def propose(
        self,
        findings: List[Dict],
        target: str,
        executed_tools: List[Dict],
        existing_task_names: set
    ) -> List[Dict]:
        """Propose next tasks. Returns list of {task_name, tool, parameters, reason, priority}."""
        
        if not self.llm_client or not findings:
            return []
        
        try:
            clean_findings = _prepare_findings(findings[:15])
            
            tools_ran = []
            for t in executed_tools:
                tools_ran.append(f"- {t['tool']} (task: \"{t.get('task_name','')}\", args: \"{t.get('args','')}\", findings: {t.get('findings_count',0)})")
            
            prompt = f"""Target: {target}

Already executed — DO NOT propose again:
{chr(10).join(tools_ran) if tools_ran else '- Nothing yet'}

Current findings:
{json.dumps(clean_findings, indent=2)}

What NEW tasks should run? Only tools that haven't run yet or target something new."""

            response = await asyncio.wait_for(
                self.llm_client.generate_json(prompt, self.SYSTEM_PROMPT),
                timeout=20.0
            )
            
            if response.get("reasoning"):
                logger.info(f"🤖 Strategy: {response['reasoning'][:120]}")
            
            proposals = []
            for item in response.get("proposals", []):
                name = item.get("task_name", "Unknown")
                if name in existing_task_names:
                    logger.info(f"   ⏭️ Skipped duplicate: {name}")
                    continue
                proposals.append({
                    "task_name": name,
                    "tool": item.get("tool", ""),
                    "parameters": item.get("parameters", {}),
                    "reason": item.get("reason", ""),
                    "priority": min(max(int(item.get("priority", 5)), 1), 10)
                })
            
            return proposals[:2]  # Hard cap at 2 per round
            
        except Exception as e:
            logger.warning(f"⚠️ Task proposal failed ({e})")
            return []


class ReportGeneratorAgent:
    """Generates structured pentest report from all findings."""
    
    SYSTEM_PROMPT = """You are a senior penetration tester writing a security assessment report.

Structure the report EXACTLY as:

# Penetration Test Report

## Executive Summary
(2-3 sentences: what was tested, overall risk level, most critical finding)

## Target Information
- Target: (target)
- Scan Duration: (duration)
- Tools Used: (tools)
- Tasks Executed: (count)

## Critical and High Risk Findings
(For each: what it is, why it matters, remediation steps. If none found, say so.)

## Medium and Low Risk Findings
(Brief summary. Include discovered paths, technology detections.)

## Open Ports and Services
(Markdown table: Port | State | Service | Version | Risk)

## Attack Surface Analysis
(What attack vectors exist based on findings. Be specific.)

## Recommendations
(Numbered list, most urgent first. Be specific and actionable.)

## Methodology
(What tools ran, in what order, why)

Rules:
- Be specific — reference actual ports, services, versions, paths
- Do NOT invent findings not in the data
- If no critical vulns found, say so honestly
- Include risk scores where available
- Keep under 1000 words"""
    
    def __init__(self):
        self.llm_client = None
        try:
            self.llm_client = llm_factory.get_client()
        except:
            pass
    
    async def generate(
        self,
        target: str,
        findings: List[Dict],
        executed_tools: List[Dict],
        risk_summary: Dict,
        duration_seconds: float,
        total_tasks: int,
        dynamic_tasks: int
    ) -> str:
        """Generate pentest report."""
        
        if not self.llm_client:
            return self._fallback_report(target, findings, executed_tools, duration_seconds)
        
        try:
            # Deduplicate findings
            seen = set()
            unique_findings = []
            for f in findings:
                key = f"{f.get('type')}:{f.get('port','')}:{f.get('service','')}:{f.get('finding','')[:50]}"
                if key not in seen:
                    seen.add(key)
                    unique_findings.append(f)
            
            open_ports = [f for f in unique_findings if f.get("type") == "open_port" and f.get("state") == "open"]
            filtered = [f for f in unique_findings if f.get("type") == "open_port" and f.get("state") == "filtered"]
            vulns = [f for f in unique_findings if f.get("type") in ["vulnerability", "sql_injection"]]
            paths = [f for f in unique_findings if f.get("type") == "discovered_path"]
            other = [f for f in unique_findings if f.get("type") == "finding"]
            
            tools_used = list(set(t["tool"] for t in executed_tools))
            
            prompt = f"""Target: {target}
Duration: {duration_seconds:.0f}s ({duration_seconds/60:.1f} min)
Tools: {', '.join(tools_used)}
Tasks: {total_tasks} ({dynamic_tasks} AI-proposed)

Risk Summary:
- Overall: {risk_summary.get('overall_risk', 'unknown')} (score: {risk_summary.get('overall_score', 0)})
- Critical: {risk_summary.get('critical_count', 0)}, High: {risk_summary.get('high_count', 0)}, Medium: {risk_summary.get('medium_count', 0)}

Open Ports ({len(open_ports)}):
{json.dumps([{"port":p["port"],"service":p.get("service",""),"version":p.get("version",""),"risk_score":p.get("risk_score",0)} for p in open_ports], indent=2)}

Filtered Ports: {len(filtered)} ({', '.join(str(p['port']) for p in filtered[:5])})

Vulnerabilities ({len(vulns)}):
{json.dumps([{"severity":v.get("validated_severity",v.get("severity","")),"template":v.get("template","")[:50],"finding":v.get("finding","")[:80],"risk_score":v.get("risk_score",0)} for v in vulns[:10]], indent=2)}

Discovered Paths ({len(paths)}):
{json.dumps([{"path":p["path"],"status":p.get("status_code",0),"risk_score":p.get("risk_score",0)} for p in paths[:15]], indent=2)}

Other Findings: {len(other)}

Execution History:
{json.dumps([{"tool":t["tool"],"task":t.get("task_name",""),"findings":t.get("findings_count",0)} for t in executed_tools], indent=2)}"""

            report = await asyncio.wait_for(
                self.llm_client.generate(prompt, self.SYSTEM_PROMPT),
                timeout=30.0
            )
            
            logger.info(f"📝 Report generated ({len(report)} chars)")
            return report
            
        except Exception as e:
            logger.warning(f"⚠️ Report generation failed ({e})")
            return self._fallback_report(target, findings, executed_tools, duration_seconds)
    
    def _fallback_report(self, target, findings, tools, duration):
        open_ports = [f for f in findings if f.get("type") == "open_port" and f.get("state") == "open"]
        report = f"# Penetration Test Report\n\n## Target: {target}\n## Duration: {duration:.0f}s\n\n"
        report += f"## Open Ports ({len(open_ports)})\n"
        for p in open_ports:
            report += f"- {p['port']}/{p.get('protocol','tcp')} {p.get('service','')} {p.get('version','')}\n"
        report += "\n## Recommendations\n- Review open ports\n- Patch services\n"
        return report


# ============================================================
# Shared helper
# ============================================================

def _prepare_findings(findings: List[Dict]) -> List[Dict]:
    """Clean findings for LLM consumption."""
    clean = []
    seen = set()
    for i, f in enumerate(findings):
        key = f"{f.get('type')}:{f.get('port','')}:{f.get('service','')}:{f.get('finding','')[:50]}"
        if key in seen:
            continue
        seen.add(key)
        
        entry = {"index": i, "type": f.get("type", "unknown")}
        if f.get("type") == "open_port":
            entry.update({"port": f.get("port"), "state": f.get("state"), "service": f.get("service"), "version": f.get("version","")[:60]})
        elif f.get("type") in ["vulnerability", "sql_injection"]:
            entry.update({"severity": f.get("severity"), "template": f.get("template","")[:50], "finding": f.get("finding","")[:100]})
        elif f.get("type") == "discovered_path":
            entry.update({"path": f.get("path"), "status_code": f.get("status_code", 0)})
        elif f.get("type") == "finding":
            entry.update({"severity": f.get("severity", "info"), "finding": f.get("finding","")[:100]})
        else:
            for k in ["severity", "finding", "port", "service", "status"]:
                if k in f:
                    entry[k] = str(f[k])[:80]
        clean.append(entry)
    return clean
