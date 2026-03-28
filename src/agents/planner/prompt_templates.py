# src/agents/planner/prompt_templates.py
from typing import Optional, Dict

PLANNER_SYSTEM_PROMPT = """You are an expert security orchestration planner.

You have access to these SPECIFIC TOOLS (use tool names, not abstract capabilities):
- nmap: Port scanning, service detection, OS detection. ONE nmap task covers ALL of these.
- nuclei: Vulnerability scanning with templates. Finds CVEs, misconfigurations, exposed panels.
- gobuster: Directory/file brute-forcing on web servers. Requires HTTP ports open.
- ffuf: Fast web fuzzer — directory discovery, parameter fuzzing. Alternative to gobuster, faster.
- nikto: Web server vulnerability scanner — checks for dangerous files, outdated software, misconfigurations.
- whatweb: Web technology fingerprinting — identifies CMS, frameworks, libraries, server software.
- sqlmap: SQL injection testing. Only useful if web forms or URL parameters exist.

CRITICAL RULES:
- Create 1-2 tasks for initial reconnaissance, NOT 3+ redundant nmap tasks
- A typical plan: Level 1 = nmap scan, Level 2 = nuclei vuln scan (depends on nmap)
- For web targets, consider adding whatweb (fast fingerprinting) in Level 1 parallel with nmap
- Use nikto for web server-specific vulnerability checks
- Use ffuf OR gobuster for directory discovery, not both
- NEVER create separate tasks for "network discovery", "DNS enumeration", and "port scanning" — nmap does all three

For each task specify:
- id: unique (e.g. "task_001")  
- name: descriptive name
- tool: which tool to use (nmap/nuclei/gobuster/sqlmap)
- capabilities: array of capability strings
- estimated_duration: seconds
- parameters: tool-specific params
- dependencies: array of task IDs this depends on

Respond with ONLY valid JSON:
{
  "tasks": [
    {
      "id": "task_001",
      "name": "Port and Service Scan",
      "tool": "nmap",
      "capabilities": ["port_scan", "network_scan"],
      "estimated_duration": 60,
      "parameters": {"scan_type": "-sT -sV", "ports": "1-1000", "timing": "-T4"}
    },
    {
      "id": "task_002", 
      "name": "Vulnerability Scan",
      "tool": "nuclei",
      "capabilities": ["vuln_scan"],
      "estimated_duration": 120,
      "parameters": {"severity": "critical,high,medium"}
    }
  ],
  "dependencies": [
    {"from": "task_001", "to": "task_002"}
  ],
  "estimated_total_duration": 180,
  "explanation": "Brief explanation"
}"""


def get_planning_prompt(goal: str, target: Optional[str] = None, context: Optional[Dict] = None) -> str:
    prompt = f"Security Goal: {goal}\n"
    
    if target:
        prompt += f"Target: {target}\n"
    
    if context and context.get("similar_tasks"):
        prompt += "\nSimilar previous tasks:\n"
        for task in context["similar_tasks"][:3]:
            prompt += f"- {task.get('name')}: {task.get('description', '')}\n"
    
    prompt += """
Create an efficient plan. Remember:
- ONE nmap task for all port/service/network discovery
- Add nuclei for vuln scanning (depends on nmap)
- Add gobuster only if web ports are likely
- Keep it minimal — 2-3 tasks max
"""
    
    return prompt


VERIFIER_SYSTEM_PROMPT = """You are a DAG verifier for security workflows.

Validate the plan is:
1. Acyclic (no circular dependencies)
2. Complete (all info available)
3. Efficient (no redundant tasks)

Respond with JSON:
{
  "valid": true,
  "issues": [],
  "suggestions": [],
  "confidence_score": 0.95
}"""


def get_verification_prompt(dag_json: str, context: Optional[Dict] = None) -> str:
    return f"""
Verify this execution plan:

{dag_json}

Check for cycles, missing dependencies, redundant tasks, and security concerns.
Return JSON with verification results.
"""
