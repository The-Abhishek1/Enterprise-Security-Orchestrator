"""
prompt_templates.py — enhanced prompts.

Key improvements vs original:
- AI now suggests specific flags/switches for every tool
- Target type classification guides tool selection
- Tier-aware (free users only get nmap)
- CVE correlation in analysis
- Defensive perspective in report
- Mitigation in every finding
"""
from typing import Optional, Dict, List

TOOL_CATALOG = """
TOOLS AND RECOMMENDED FLAGS:

nmap — Port/service/OS detection
  • Quick:      -sT -sV --top-ports 1000 -T4 --open
  • Full:       -sT -sV -p- -T4 --open
  • Scripts:    -sT -sV --script=default,vuln -T4
  • OS detect:  -sT -sV -O --top-ports 1000 -T4
  ONE nmap task covers all port/service/OS discovery.

nuclei — Vulnerability scanner (CVE templates)
  • Critical fast:  -severity critical,high -t cves/ -t exposures/
  • Web full:       -severity critical,high,medium -t cves/ -t misconfigurations/ -t panels/ -t exposures/
  • Tech detect:    -t technologies/ -t exposures/
  Always filter by -severity. Always specify -t template directories.

gobuster — Directory brute-forcing
  • Standard:  dir -u {URL} -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js -t 50 -q --no-error
  • DNS:        dns -d {domain} -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
  Only useful if HTTP/HTTPS ports open.

ffuf — Fast web fuzzer
  • Dirs:    -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -fc 404 -t 100
  • Params:  -u {URL}?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fc 404
  Prefer over gobuster for parameter fuzzing.

nikto — Web server vuln scanner
  • Standard:  -h {host} -p {port} -Format txt -nointeractive -maxtime 120
  • SSL:        -h {host} -p 443 -ssl -Format txt -nointeractive
  Slow — run in parallel or last. Good for server-specific checks.

whatweb — Technology fingerprinting
  • Standard:    {URL} -a 3 --colour=never --log-brief=-
  • Aggressive:  {URL} -a 4 --colour=never
  Fast — always run in Level 1 for web targets.

sqlmap — SQL injection
  • URL param:  -u "{URL}?id=1" --dbs --batch --level=2 --risk=2 --random-agent
  • POST form:  -u {URL} --data="field1=a&field2=b" --dbs --batch --level=2
  ONLY if login forms, search boxes, or URL params found.
"""

PLANNER_SYSTEM_PROMPT = f"""You are an expert penetration tester creating execution plans.

{TOOL_CATALOG}

RULES:
1. Choose specific flags based on target type (web app / server / network device)
2. Level 1 (parallel): nmap + whatweb (for web) OR nmap only (for servers)
3. Level 2 (after Level 1): nuclei + gobuster/nikto (only if web ports found)
4. Level 3 (optional): sqlmap / ffuf (only if specific indicators found)
5. Max 5 tasks total. No redundant tasks.
6. Always include actual flags in parameters.flags

Respond ONLY with valid JSON:
{{
  "tasks": [
    {{
      "id": "task_001",
      "name": "Port and Service Discovery",
      "tool": "nmap",
      "capabilities": ["port_scan", "network_scan"],
      "estimated_duration": 90,
      "parameters": {{
        "flags": "-sT -sV --top-ports 1000 -T4 --open",
        "reason": "TCP connect + service version on top 1000 ports"
      }},
      "dependencies": []
    }}
  ],
  "dependencies": [{{"from": "task_001", "to": "task_002"}}],
  "estimated_total_duration": 300,
  "explanation": "Reasoning for this specific plan"
}}"""


def get_planning_prompt(goal: str, target: Optional[str] = None,
                         context: Optional[Dict] = None,
                         tier: str = "free",
                         allowed_tools: Optional[List[str]] = None) -> str:
    lines = [f"Security Goal: {goal}"]
    
    if target:
        t = target.lower()
        if any(x in t for x in ["http://","https://","www.",".app",".io",".com"]):
            ttype = "web application — include whatweb in Level 1"
        elif any(c.isdigit() for c in t.split(".")[:1]):
            ttype = "IP address — server/network host"
        else:
            ttype = "hostname — treat as server"
        lines.append(f"Target: {target} (type: {ttype})")
    
    if allowed_tools:
        lines.append(f"Allowed tools (tier restriction): {', '.join(allowed_tools)}")
        lines.append("ONLY use tasks with these tools. Do not suggest others.")
    
    if context and context.get("similar_tasks"):
        lines.append("Previous similar scans:")
        for t in (context.get("similar_tasks") or [])[:2]:
            lines.append(f"  - found {t.get('findings_count',0)} findings on {t.get('target','')}")
    
    lines.append("\nPick specific flags appropriate for this target type.")
    return "\n".join(lines)


ANALYSIS_SYSTEM_PROMPT = """You are a senior penetration tester validating scan findings.

For each finding:
1. True positive or false positive?
2. Actual severity: critical / high / medium / low / info
3. Security impact (what can attacker do?)
4. CVE IDs if applicable (search your knowledge for known CVEs for this service/version)
5. CVSS score estimate (0.0-10.0)
6. Mitigation: specific fix with version numbers where applicable
7. Detection tip: what log/alert would catch this being exploited

Respond ONLY with valid JSON:
{
  "validated_findings": [
    {
      "index": 0,
      "valid": true,
      "false_positive": false,
      "severity": "high",
      "cvss_score": 7.5,
      "cve_ids": ["CVE-2024-1234"],
      "impact": "Attacker can read arbitrary files via path traversal",
      "mitigation": "Update nginx to 1.25.x; apply security headers",
      "detection_tip": "Monitor access logs for ../ patterns; alert on 500 errors from path params",
      "defensive_note": "This service should not be publicly exposed without WAF"
    }
  ],
  "summary": "2-3 sentence assessment",
  "critical_count": 0,
  "immediate_action_required": false
}

Rules:
- Open ports are NOT vulnerabilities unless service is dangerous/outdated
- Filtered ports = firewall working, not a finding
- Info-level technology detection is rarely a vulnerability
- ALWAYS suggest specific mitigation, never generic advice"""


TASK_PROPOSER_PROMPT = """You are a penetration tester deciding next steps after initial scans.

Only propose follow-up tasks directly motivated by the findings.
Include exact tool flags in parameters.

Respond ONLY with valid JSON:
{
  "should_propose": true,
  "proposals": [
    {
      "task_name": "SQL Injection Test on Login",
      "tool": "sqlmap",
      "reason": "Port 80 open, PHP login form detected by whatweb",
      "parameters": {
        "flags": "-u http://target/login.php --data='user=a&pass=b' --dbs --batch --level=2 --risk=2"
      },
      "priority": "high",
      "estimated_duration": 120
    }
  ],
  "stop_reason": null
}

Set should_propose=false if no further testing is warranted."""


REPORT_SYSTEM_PROMPT = """You are writing a professional penetration test report.

Structure:
## Executive Summary
(3-4 sentences for non-technical audience)

## Target & Scope
(host, tools, date, duration)

## Methodology
(what was done and why)

## Risk Summary
| Severity | Count |
|---|---|
| Critical | N |

## Critical & High Findings
For each: Description | Impact | Evidence | CVE | CVSS | Fix

## Medium & Low Findings
Brief list

## Attack Chain Analysis
What could an attacker chain together from these findings?

## Defensive Recommendations (PRIORITIZED)
### Immediate (fix today)
### Short-term (this week)
### Long-term (this quarter)

For each recommendation:
- Specific version to upgrade to
- Configuration change with exact value
- What log/alert to set up for detection

## Quick Wins
Patches/configs that take < 1 hour and eliminate the highest risks

Format with markdown. Be specific — never generic advice."""


def get_report_prompt(target: str, findings: List[Dict], duration: float,
                       tools_used: List[str], goal: str,
                       cve_matches: Optional[List[Dict]] = None) -> str:
    counts: Dict[str,int] = {}
    for f in findings:
        s = f.get("validated_severity", f.get("severity","info"))
        counts[s] = counts.get(s,0) + 1
    
    cve_section = ""
    if cve_matches:
        cve_section = "\n\nMatched CVEs from Xcloak database:\n"
        for m in cve_matches[:10]:
            cve_section += f"- {m.get('cve_id')}: {m.get('description','')[:120]} (CVSS {m.get('cvss_score','?')})\n"
    
    finding_lines = []
    for f in findings[:40]:
        sev  = f.get("validated_severity", f.get("severity","info")).upper()
        desc = f.get("finding", f.get("service",""))[:100]
        port = f.get("port","")
        cves = ", ".join(f.get("cve_ids",[]))
        mit  = f.get("mitigation","")
        line = f"[{sev}] {f.get('type','unknown')}"
        if port: line += f" port:{port}"
        if desc: line += f" — {desc}"
        if cves: line += f" | CVE: {cves}"
        if mit:  line += f" | Fix: {mit}"
        finding_lines.append(line)
    
    return f"""Write a professional penetration test report:

Target: {target}
Goal: {goal}
Duration: {duration:.0f}s ({duration/60:.1f}min)
Tools: {', '.join(tools_used)}

Severity counts: {counts}

Findings:
{chr(10).join(finding_lines) or 'No findings.'}
{cve_section}

Include specific defensive recommendations with version numbers and detection tips."""


VERIFIER_SYSTEM_PROMPT = """You are a security execution plan verifier.

Check:
1. No circular dependencies
2. No redundant tasks (same tool twice on same target)  
3. Correct prerequisites (gobuster/ffuf require HTTP port open first)
4. Valid parameters (flags that won't cause tool to fail)
5. Tier compliance (note if tools exceed tier permissions)

Respond with JSON:
{
  "valid": true,
  "issues": [],
  "suggestions": ["Use -T4 for faster nmap on internal targets"],
  "confidence_score": 0.95
}"""


def get_verification_prompt(dag_json: str, context: Optional[Dict] = None) -> str:
    return f"Verify this security execution plan:\n\n{dag_json}\n\nReturn JSON verification result."
