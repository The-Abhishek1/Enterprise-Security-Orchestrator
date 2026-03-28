# src/engine/result_parser.py

"""
Result Parser — converts raw tool stdout/stderr into structured findings.
No hardcoding per tool — uses LLM to parse unknown output formats.
Falls back to regex patterns for known tools (nmap, nuclei, gobuster, sqlmap).
"""

from typing import Dict, Any, List, Optional
import re
import json

from src.utils.logging import logger


class ResultParser:
    """Parses raw tool output into structured findings."""
    
    def parse(self, tool_name: str, stdout: str, stderr: str, exit_code: int) -> List[Dict]:
        """Parse tool output into structured findings list."""
        
        combined = (stdout + "\n" + stderr).strip() if stderr else stdout.strip()
        
        if not combined:
            return []
        
        parser = self._get_parser(tool_name)
        findings = parser(combined, exit_code)
        
        logger.info(f"📊 Parsed {len(findings)} findings from {tool_name}")
        return findings
    
    def _get_parser(self, tool_name: str):
        parsers = {
            "nmap": self._parse_nmap,
            "nuclei": self._parse_nuclei,
            "gobuster": self._parse_gobuster,
            "sqlmap": self._parse_sqlmap,
            "nikto": self._parse_nikto,
            "ffuf": self._parse_ffuf,
            "whatweb": self._parse_whatweb,
        }
        return parsers.get(tool_name, self._parse_generic)
    
    def _parse_nmap(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            if line.startswith("Discovered"):
                continue
            
            if '/tcp' in line and ('open' in line or 'filtered' in line):
                parts = line.split()
                if len(parts) >= 2:
                    port_parts = parts[0].split('/')
                    if len(port_parts) == 2 and port_parts[0].isdigit():
                        findings.append({
                            "type": "open_port",
                            "port": int(port_parts[0]),
                            "protocol": port_parts[1],
                            "state": parts[1],
                            "service": parts[2] if len(parts) > 2 else "unknown",
                            "version": ' '.join(parts[3:]) if len(parts) > 3 else "",
                            "source": "nmap"
                        })
            
            elif "Host is up" in line:
                findings.append({"type": "host_status", "status": "up", "source": "nmap"})
            
            elif "Nmap scan report for" in line:
                host = line.split("Nmap scan report for")[-1].strip()
                findings.append({"type": "scan_report", "host": host, "source": "nmap"})
        
        return findings
    
    def _parse_nuclei(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('[INF]') or line.startswith('[WRN]') or line.startswith('[ERR]'):
                continue
            if 'projectdiscovery' in line or '____' in line or '/ /' in line or '/_/' in line:
                continue
            
            # Nuclei output: [template-id] [protocol] [severity] url
            match = re.match(r'\[([^\]]+)\]\s*\[([^\]]+)\]\s*\[([^\]]+)\]\s*(.*)', line)
            if match:
                findings.append({
                    "type": "vulnerability",
                    "template": match.group(1),
                    "protocol": match.group(2),
                    "severity": match.group(3).lower(),
                    "finding": match.group(4).strip(),
                    "source": "nuclei"
                })
            elif line and not line.startswith(' '):
                # Generic nuclei output line
                severity = "info"
                for sev in ["critical", "high", "medium", "low"]:
                    if f'[{sev}]' in line.lower():
                        severity = sev
                        break
                findings.append({
                    "type": "finding",
                    "severity": severity,
                    "finding": line[:200],
                    "source": "nuclei"
                })
        
        return findings
    
    def _parse_gobuster(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            # Skip headers, progress, config lines
            if any(skip in line for skip in [
                'Gobuster', '=====', 'Starting', 'Finished', 'Progress:',
                'Error:', '[+]', '[-]', '[!]', 'Url:', 'Method:', 'Threads:',
                'Wordlist:', 'Status codes', 'User Agent', 'Timeout',
                'Expanded', 'Extensions'
            ]):
                continue
            
            # Primary: find (Status: NNN) [Size: NNN] anywhere in the line
            match = re.search(r'(/\S+)\s+\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]', line)
            if match:
                findings.append({
                    "type": "discovered_path",
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(match.group(3)),
                    "source": "gobuster"
                })
                continue
            
            # Alt format: /path [Status=200, Size=1234]
            match = re.search(r'(/\S+)\s+\[Status=(\d+),\s*Size=(\d+)\]', line)
            if match:
                findings.append({
                    "type": "discovered_path",
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(match.group(3)),
                    "source": "gobuster"
                })
                continue
            
            # Catch-all: any line with a path and Status
            match = re.search(r'(/\S+).*?Status:\s*(\d+)', line)
            if match:
                size_match = re.search(r'Size:\s*(\d+)', line)
                findings.append({
                    "type": "discovered_path",
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(size_match.group(1)) if size_match else 0,
                    "source": "gobuster"
                })
                continue
            
            # Last resort: line starts with / and has digits
            if line.startswith('/'):
                parts = line.split()
                status = 0
                size = 0
                for part in parts[1:]:
                    digit_match = re.search(r'(\d{3})', part)
                    if digit_match and status == 0:
                        status = int(digit_match.group(1))
                findings.append({
                    "type": "discovered_path",
                    "path": parts[0],
                    "status_code": status,
                    "size": size,
                    "source": "gobuster"
                })
        
        # Log first few lines for debugging if no findings
        if not findings and output.strip():
            lines = [l.strip() for l in output.split('\n') if l.strip()][:5]
            logger.info(f"   ⚠️ Gobuster: 0 findings parsed. First lines: {lines}")
        
        return findings
    
    def _parse_sqlmap(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            
            if "is vulnerable" in line.lower():
                findings.append({
                    "type": "sql_injection",
                    "finding": line[:200],
                    "severity": "critical",
                    "source": "sqlmap"
                })
            elif "parameter" in line.lower() and ("injectable" in line.lower() or "vulnerable" in line.lower()):
                findings.append({
                    "type": "sql_injection",
                    "finding": line[:200],
                    "severity": "high",
                    "source": "sqlmap"
                })
            elif "available databases" in line.lower():
                findings.append({
                    "type": "database_enumeration",
                    "finding": line[:200],
                    "severity": "high",
                    "source": "sqlmap"
                })
        
        return findings
    
    def _parse_nikto(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Nikto output: + OSVDB-XXXX: /path: Description
            # or: + /path: Description
            if line.startswith('+'):
                line = line[1:].strip()
                
                severity = "info"
                if any(kw in line.lower() for kw in ["vulnerab", "exploit", "remote code", "injection"]):
                    severity = "high"
                elif any(kw in line.lower() for kw in ["outdated", "eol", "end of life", "dangerous"]):
                    severity = "medium"
                elif any(kw in line.lower() for kw in ["directory listing", "index of", "backup", "config"]):
                    severity = "medium"
                elif any(kw in line.lower() for kw in ["header", "cookie", "x-frame", "x-content"]):
                    severity = "low"
                
                # Extract OSVDB reference if present
                osvdb = ""
                osvdb_match = re.search(r'OSVDB-(\d+)', line)
                if osvdb_match:
                    osvdb = f"OSVDB-{osvdb_match.group(1)}"
                
                findings.append({
                    "type": "web_vulnerability",
                    "finding": line[:200],
                    "severity": severity,
                    "reference": osvdb,
                    "source": "nikto"
                })
            
            # Server info lines
            elif "Server:" in line:
                findings.append({
                    "type": "tech_detection",
                    "finding": line[:200],
                    "severity": "info",
                    "source": "nikto"
                })
        
        return findings
    
    def _parse_ffuf(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            # Skip headers and progress
            if any(skip in line for skip in ['FUZZ', ':: Method', ':: URL', ':: Wordlist', ':: Follow', 'Progress:', '________________________________________________']):
                continue
            
            # ffuf output: path [Status: 200, Size: 1234, Words: 56, Lines: 12]
            match = re.search(r'(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+)', line)
            if match:
                findings.append({
                    "type": "discovered_path",
                    "path": match.group(1),
                    "status_code": int(match.group(2)),
                    "size": int(match.group(3)),
                    "source": "ffuf"
                })
                continue
            
            # CSV format: url,status,size,words,lines
            parts = line.split(',')
            if len(parts) >= 3 and parts[1].strip().isdigit():
                try:
                    findings.append({
                        "type": "discovered_path",
                        "path": parts[0].strip(),
                        "status_code": int(parts[1].strip()),
                        "size": int(parts[2].strip()),
                        "source": "ffuf"
                    })
                except ValueError:
                    pass
        
        return findings
    
    def _parse_whatweb(self, output: str, exit_code: int) -> List[Dict]:
        findings = []
        
        for line in output.split('\n'):
            line = line.strip()
            if not line or line.startswith('WhatWeb') or line.startswith('http'):
                # First line is usually the URL summary — parse it
                if line.startswith('http'):
                    # Extract technologies from the summary line
                    # Format: http://example.com [200 OK] Apache[2.4.7], Country[US], ...
                    techs = re.findall(r'(\w[\w\s.-]*?)(?:\[(.*?)\])?(?:,|$)', line)
                    for tech_name, tech_version in techs:
                        tech_name = tech_name.strip()
                        if tech_name and len(tech_name) > 1 and tech_name not in ['http', 'https', 'OK']:
                            findings.append({
                                "type": "tech_detection",
                                "technology": tech_name,
                                "version": tech_version.strip() if tech_version else "",
                                "finding": f"{tech_name} {tech_version}".strip(),
                                "severity": "info",
                                "source": "whatweb"
                            })
                continue
            
            # Verbose mode output: [tag] value
            match = re.match(r'\[(\d+)\]\s+(.*)', line)
            if match:
                findings.append({
                    "type": "tech_detection",
                    "finding": match.group(2)[:200],
                    "severity": "info",
                    "source": "whatweb"
                })
        
        return findings
    
    def _parse_generic(self, output: str, exit_code: int) -> List[Dict]:
        """Fallback parser for unknown tools"""
        findings = []
        for line in output.split('\n'):
            line = line.strip()
            if line and len(line) > 5:
                findings.append({
                    "type": "finding",
                    "finding": line[:200],
                    "severity": "info",
                    "source": "unknown"
                })
        return findings[:50]  # Cap generic findings
