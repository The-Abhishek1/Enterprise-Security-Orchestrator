# src/engine/risk_engine.py

"""
Risk Engine — assigns CVSS-like scores, prioritizes findings, determines stop conditions.
"""

from typing import Dict, Any, List
from datetime import datetime

from src.utils.logging import logger


# Base CVSS-like scores by finding type and context
SEVERITY_SCORES = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 2.5,
    "info": 0.5,
}

# Service risk multipliers
SERVICE_RISK = {
    "telnet": 1.5,      # Unencrypted remote access
    "ftp": 1.3,         # Often misconfigured
    "mysql": 1.2,       # Database exposed
    "postgresql": 1.2,
    "mssql": 1.2,
    "oracle": 1.2,
    "redis": 1.3,       # Often unauthenticated
    "mongodb": 1.3,
    "ssh": 0.8,         # Expected, usually secure
    "http": 1.0,
    "https": 0.9,
    "ssl/http": 0.9,
}


class RiskEngine:
    """Scores findings, prioritizes targets, and determines if scanning should continue."""
    
    def __init__(self):
        self.risk_history: List[Dict] = []
    
    def score_findings(self, findings: List[Dict]) -> List[Dict]:
        """Add CVSS-like risk scores to each finding."""
        
        scored = []
        for finding in findings:
            scored_finding = {**finding}
            scored_finding["risk_score"] = self._calculate_score(finding)
            scored_finding["risk_label"] = self._score_to_label(scored_finding["risk_score"])
            scored.append(scored_finding)
        
        # Sort by risk score descending
        scored.sort(key=lambda f: f["risk_score"], reverse=True)
        return scored
    
    def get_risk_summary(self, findings: List[Dict]) -> Dict:
        """Generate overall risk summary from all findings."""
        
        scored = self.score_findings(findings)
        
        if not scored:
            return {
                "overall_risk": "none",
                "overall_score": 0.0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "info_count": 0,
                "top_findings": [],
                "requires_immediate_action": False
            }
        
        # Count by severity
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in scored:
            label = f.get("risk_label", "info")
            if label in counts:
                counts[label] += 1
        
        # Overall score = weighted average with emphasis on worst findings
        max_score = max(f["risk_score"] for f in scored)
        avg_score = sum(f["risk_score"] for f in scored) / len(scored)
        overall = (max_score * 0.6) + (avg_score * 0.4)
        
        summary = {
            "overall_risk": self._score_to_label(overall),
            "overall_score": round(overall, 1),
            "critical_count": counts["critical"],
            "high_count": counts["high"],
            "medium_count": counts["medium"],
            "low_count": counts["low"],
            "info_count": counts["info"],
            "top_findings": scored[:5],
            "requires_immediate_action": counts["critical"] > 0 or counts["high"] > 2
        }
        
        self.risk_history.append({
            "timestamp": datetime.utcnow().isoformat(),
            "summary": summary
        })
        
        return summary
    
    def should_continue_scanning(
        self,
        findings: List[Dict],
        dynamic_tasks_added: int,
        max_dynamic_tasks: int,
        budget_remaining: float,
        elapsed_seconds: float,
        max_duration: float
    ) -> Dict[str, Any]:
        """Determine if scanning should continue or stop."""
        
        reasons_to_stop = []
        reasons_to_continue = []
        
        # Budget check
        if budget_remaining <= 0:
            reasons_to_stop.append("Budget exhausted")
        
        # Duration check
        if elapsed_seconds >= max_duration * 0.9:
            reasons_to_stop.append(f"Approaching time limit ({elapsed_seconds:.0f}s / {max_duration:.0f}s)")
        
        # Dynamic task cap
        if dynamic_tasks_added >= max_dynamic_tasks:
            reasons_to_stop.append(f"Dynamic task cap reached ({dynamic_tasks_added}/{max_dynamic_tasks})")
        
        # Risk-based decisions
        summary = self.get_risk_summary(findings)
        
        if summary["critical_count"] > 0:
            reasons_to_continue.append(f"{summary['critical_count']} critical findings need deeper investigation")
        
        if summary["high_count"] > 0 and dynamic_tasks_added < max_dynamic_tasks:
            reasons_to_continue.append(f"{summary['high_count']} high-risk findings warrant follow-up")
        
        # Open web ports are always worth exploring further
        open_web_ports = [
            f for f in findings 
            if f.get("type") == "open_port" 
            and f.get("state") == "open" 
            and f.get("service") in ["http", "https", "ssl/http", "http-proxy"]
        ]
        if open_web_ports and dynamic_tasks_added < max_dynamic_tasks:
            reasons_to_continue.append(f"{len(open_web_ports)} open web ports — directory/vuln scanning recommended")
        
        # If no significant findings AND no web ports AND we already did dynamic tasks, stop
        if summary["overall_score"] < 2.0 and not open_web_ports and dynamic_tasks_added > 0:
            reasons_to_stop.append("Low risk profile — further scanning unlikely to find significant issues")
        
        should_continue = len(reasons_to_stop) == 0 and len(reasons_to_continue) > 0
        
        decision = {
            "should_continue": should_continue,
            "reasons_to_stop": reasons_to_stop,
            "reasons_to_continue": reasons_to_continue,
            "risk_summary": summary
        }
        
        if reasons_to_stop:
            logger.info(f"🛑 Stop conditions: {', '.join(reasons_to_stop)}")
        if reasons_to_continue:
            logger.info(f"🟢 Continue reasons: {', '.join(reasons_to_continue)}")
        
        return decision
    
    def _calculate_score(self, finding: Dict) -> float:
        """Calculate CVSS-like score for a single finding."""
        
        finding_type = finding.get("type", "unknown")
        
        if finding_type == "open_port":
            return self._score_port(finding)
        elif finding_type in ["vulnerability", "sql_injection"]:
            return self._score_vulnerability(finding)
        elif finding_type == "discovered_path":
            return self._score_path(finding)
        elif finding_type == "finding":
            severity = finding.get("severity", "info")
            return SEVERITY_SCORES.get(severity, 0.5)
        else:
            return 0.5
    
    def _score_port(self, finding: Dict) -> float:
        state = finding.get("state", "")
        service = finding.get("service", "unknown")
        
        if state == "filtered":
            return 1.0  # Filtered = firewall present, low concern
        
        if state == "open":
            base = 3.0
            multiplier = SERVICE_RISK.get(service, 1.0)
            
            # Version-based risk
            version = finding.get("version", "")
            if version:
                # Old versions are riskier
                for old_indicator in ["2.", "3.", "4.", "5.", "1.0", "1.1"]:
                    if version.startswith(old_indicator):
                        multiplier *= 1.2
                        break
            
            return min(base * multiplier, 8.0)
        
        return 0.5
    
    def _score_vulnerability(self, finding: Dict) -> float:
        severity = finding.get("severity", "info")
        base = SEVERITY_SCORES.get(severity, 0.5)
        
        # Boost for specific vulnerability types
        finding_text = finding.get("finding", "").lower()
        if "rce" in finding_text or "remote code" in finding_text:
            base = max(base, 9.5)
        elif "sql injection" in finding_text:
            base = max(base, 8.5)
        elif "xss" in finding_text:
            base = max(base, 6.0)
        elif "ssrf" in finding_text:
            base = max(base, 7.0)
        
        return base
    
    def _score_path(self, finding: Dict) -> float:
        path = finding.get("path", "").lower()
        status = finding.get("status_code", 0)
        
        # Admin/sensitive paths
        sensitive_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/manager", "/.env", "/config", "/backup", "/.git"]
        for sp in sensitive_paths:
            if sp in path:
                return 6.0 if status == 200 else 3.0
        
        if status == 200:
            return 2.0
        elif status in [301, 302]:
            return 1.5
        elif status == 403:
            return 1.0  # Exists but forbidden — interesting
        
        return 0.5
    
    def _score_to_label(self, score: float) -> str:
        if score >= 9.0:
            return "critical"
        elif score >= 7.0:
            return "high"
        elif score >= 4.0:
            return "medium"
        elif score >= 2.0:
            return "low"
        return "info"
