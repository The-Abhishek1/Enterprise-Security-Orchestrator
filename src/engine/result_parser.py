"""
result_parser.py — hardened output parser.

Improvements:
- Extracts CVE IDs from nuclei/nikto output
- Extracts version strings for CVE correlation
- Better nmap script output parsing (vuln scripts)
- whatweb technology extraction
- Generic LLM fallback for unknown tools
- Target field added to all findings
"""
from typing import Dict, Any, List, Optional
import re
import json

from src.utils.logging import logger


# Strip ANSI color codes
ANSI_RE = re.compile(r'\x1b\[[0-9;]*[mGKH]|\[[0-9;]*m')
# CVE pattern
CVE_RE  = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)


def _clean(text: str) -> str:
    return ANSI_RE.sub('', text).strip()


def _extract_cves(text: str) -> List[str]:
    return list(set(CVE_RE.findall(text)))


class ResultParser:
    """Converts raw tool stdout/stderr → structured findings with CVE IDs and version info."""
    
    def parse(self, tool_name: str, stdout: str, stderr: str,
              exit_code: int, target: str = "") -> List[Dict]:
        raw = _clean(stdout + "\n" + (stderr or ""))
        if not raw.strip():
            return []
        
        parser = {
            "nmap":    self._parse_nmap,
            "nuclei":  self._parse_nuclei,
            "gobuster":self._parse_gobuster,
            "ffuf":    self._parse_ffuf,
            "nikto":   self._parse_nikto,
            "whatweb": self._parse_whatweb,
            "sqlmap":  self._parse_sqlmap,
        }.get(tool_name, self._parse_generic)
        
        findings = parser(raw, exit_code, target)
        
        # Enrich all findings with common fields
        for f in findings:
            f.setdefault("source", tool_name)
            f.setdefault("target", target)
            f.setdefault("severity", "info")
            # Extract any CVE IDs from the finding text
            text = f.get("finding","") + " " + f.get("version","") + " " + f.get("template","")
            cves = _extract_cves(text)
            if cves and not f.get("cve_ids"):
                f["cve_ids"] = cves
        
        logger.info(f"📊 Parsed {len(findings)} findings from {tool_name}")
        return findings
    
    def _parse_nmap(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = _clean(line)
            if not line:
                continue
            
            # Open port lines: "80/tcp   open  http    Apache httpd 2.4.41"
            if '/tcp' in line or '/udp' in line:
                m = re.match(r'^(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)(?:\s+(.*))?$', line)
                if m and m.group(3) in ('open', 'filtered'):
                    port, proto, state, service = m.group(1), m.group(2), m.group(3), m.group(4)
                    version = (m.group(5) or "").strip()
                    
                    # Extract CVEs from version string
                    cves = _extract_cves(version)
                    
                    # Assess severity by service
                    sev = self._service_severity(service, port)
                    
                    findings.append({
                        "type":     "open_port",
                        "port":     int(port),
                        "protocol": proto,
                        "state":    state,
                        "service":  service,
                        "version":  version,
                        "severity": sev if state == "open" else "info",
                        "finding":  f"{state} {port}/{proto} {service} {version}".strip(),
                        "cve_ids":  cves,
                    })
            
            # Host up
            elif "Host is up" in line:
                findings.append({"type": "host_status", "status": "up", "severity": "info",
                                  "finding": "Host is up and responding"})
            
            # Nmap script output (vuln scripts)
            elif "VULNERABLE" in line or "CVE-" in line:
                cves = _extract_cves(line)
                findings.append({
                    "type": "vulnerability",
                    "severity": "high",
                    "finding": _clean(line)[:300],
                    "cve_ids": cves,
                    "source": "nmap-scripts",
                })
        
        return findings
    
    def _service_severity(self, service: str, port: str) -> str:
        """Assign base severity by service type."""
        s = service.lower()
        dangerous = {"telnet":"high","ftp":"medium","smtp":"low","snmp":"medium",
                     "rdp":"medium","vnc":"high","rpcbind":"medium","nfs":"high",
                     "mysql":"medium","postgresql":"medium","mssql":"medium",
                     "redis":"high","mongodb":"high","cassandra":"medium","memcache":"medium"}
        for svc, sev in dangerous.items():
            if svc in s:
                return sev
        return "info"
    
    def _parse_nuclei(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        
        # Nuclei line format: [timestamp] [template-id] [severity] [url] [info]
        # Or: [critical] [CVE-2024-xxx] [url] matched at [url]
        nuclei_re = re.compile(
            r'\[(\w+)\]\s+\[([^\]]+)\]\s+(?:\[([^\]]+)\]\s+)?(.+)'
        )
        
        for line in output.split('\n'):
            line = _clean(line)
            if not line or line.startswith('[INF]') or line.startswith('[WRN]'):
                continue
            
            m = nuclei_re.match(line)
            if m:
                severity_or_ts = m.group(1).lower()
                template_id    = m.group(2)
                extra          = m.group(3) or ""
                url_or_info    = m.group(4).strip()
                
                # Determine severity
                sev_map = {"critical":"critical","high":"high","medium":"medium",
                           "low":"low","info":"info","informational":"info"}
                severity = sev_map.get(severity_or_ts, sev_map.get(extra.lower(), "info"))
                
                cves = _extract_cves(template_id + " " + line)
                
                findings.append({
                    "type":     "vulnerability",
                    "severity": severity,
                    "template": template_id,
                    "finding":  url_or_info[:300],
                    "cve_ids":  cves,
                    "source":   "nuclei",
                })
        
        return findings
    
    def _parse_gobuster(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        for line in output.split('\n'):
            line = _clean(line)
            if not line or line.startswith('=') or line.startswith('/usr') or 'Error' in line:
                continue
            # Format: /path (Status: 200) [Size: 1234]
            m = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)', line)
            if m:
                path, status = m.group(1), int(m.group(2))
                sev = "medium" if status in (200,301,302) else "low" if status == 403 else "info"
                findings.append({
                    "type":        "discovered_path",
                    "path":        path,
                    "status_code": status,
                    "severity":    sev,
                    "finding":     f"Path {path} returned HTTP {status}",
                })
        return findings
    
    def _parse_ffuf(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        # ffuf JSON output or line-by-line
        try:
            data = json.loads(output)
            for r in data.get("results", []):
                findings.append({
                    "type":        "discovered_path",
                    "path":        r.get("input", {}).get("FUZZ", r.get("url","")),
                    "status_code": r.get("status", 0),
                    "severity":    "medium" if r.get("status") in (200,301,302) else "low",
                    "finding":     f"ffuf: {r.get('url','')} → {r.get('status',0)}",
                })
        except (json.JSONDecodeError, Exception):
            # Plain text fallback
            for line in output.split('\n'):
                line = _clean(line)
                m = re.search(r'(https?://\S+)\s+\[Status:\s*(\d+)', line)
                if m:
                    findings.append({
                        "type":        "discovered_path",
                        "path":        m.group(1),
                        "status_code": int(m.group(2)),
                        "severity":    "medium",
                        "finding":     f"ffuf: {m.group(1)} → HTTP {m.group(2)}",
                    })
        return findings
    
    def _parse_nikto(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        for line in output.split('\n'):
            line = _clean(line)
            if not line or line.startswith('-') or line.startswith('+') and 'Target' in line:
                continue
            if line.startswith('+') or line.startswith('+ '):
                content = line.lstrip('+ ').strip()
                if not content or 'nikto' in content.lower():
                    continue
                cves = _extract_cves(content)
                sev = "high" if cves else ("medium" if any(w in content.lower() for w in ["outdated","vulnerable","dangerous","allows"]) else "low")
                findings.append({
                    "type":    "web_vulnerability",
                    "severity": sev,
                    "finding": content[:300],
                    "cve_ids": cves,
                    "source":  "nikto",
                })
        return findings
    
    def _parse_whatweb(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        for line in output.split('\n'):
            line = _clean(line)
            if not line:
                continue
            # WhatWeb: http://target [200] Apache[2.4.41], PHP[7.4.3], ...
            m = re.match(r'(https?://\S+)\s+\[(\d+)\]\s+(.*)', line)
            if m:
                url, status, tech_str = m.group(1), m.group(2), m.group(3)
                
                # Parse technologies
                techs = re.findall(r'(\w[\w\-\.]+)\[([^\]]*)\]', tech_str)
                
                for tech, version in techs:
                    cves = _extract_cves(f"{tech} {version}")
                    findings.append({
                        "type":     "technology_detected",
                        "severity": "info",
                        "finding":  f"{tech} {version}".strip(),
                        "service":  tech,
                        "version":  version,
                        "path":     url,
                        "cve_ids":  cves,
                    })
                
                # If no technologies parsed, add raw
                if not techs:
                    findings.append({
                        "type":    "technology_detected",
                        "severity":"info",
                        "finding": tech_str[:200],
                    })
        return findings
    
    def _parse_sqlmap(self, output: str, exit_code: int, target: str) -> List[Dict]:
        findings = []
        injectable = False
        
        for line in output.split('\n'):
            line = _clean(line)
            if "is vulnerable" in line.lower() or "injectable" in line.lower():
                injectable = True
            if injectable or "parameter" in line.lower() and "is vulnerable" in line.lower():
                findings.append({
                    "type":    "sql_injection",
                    "severity":"critical",
                    "finding": line[:300],
                    "cve_ids": [],
                    "source":  "sqlmap",
                })
                injectable = False
            elif "database:" in line.lower() or "available databases" in line.lower():
                findings.append({
                    "type":    "sql_injection_data",
                    "severity":"critical",
                    "finding": f"SQL injection data: {line[:200]}",
                })
        
        return findings
    
    def _parse_generic(self, output: str, exit_code: int, target: str) -> List[Dict]:
        """Generic parser for unrecognized tools — extract CVEs and errors."""
        findings = []
        cves = _extract_cves(output)
        if cves:
            for cve in cves:
                findings.append({
                    "type":    "vulnerability",
                    "severity":"medium",
                    "finding": f"CVE reference found: {cve}",
                    "cve_ids": [cve],
                })
        elif exit_code != 0:
            findings.append({
                "type":    "tool_error",
                "severity":"info",
                "finding": f"Tool exited with code {exit_code}: {output[:200]}",
            })
        return findings
