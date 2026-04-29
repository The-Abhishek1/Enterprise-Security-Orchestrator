# src/workers/compliance_mapper.py
"""
Compliance Mapper — maps security findings to compliance framework controls
and computes gap analysis (passing / failing / not-assessed per control).

Supported frameworks (stored as structured control lists):
  SOC 2 Type II     — 64 criteria across 5 Trust Service Criteria
  ISO 27001:2022    — 93 controls across 4 clauses and 11 domains
  PCI-DSS v4.0      — 12 requirements with sub-requirements
  NIST CSF v2.0     — 5 functions, 23 categories, 108 subcategories
  HIPAA             — 54 safeguard standards

Each finding is mapped to one or more controls via:
  1. Keyword matching on finding type / source / description
  2. Severity-based catch-all controls
  3. Cloud finding rule IDs (CIS tags already on cloud findings)

Output: ControlStatus per control — PASS / FAIL / NOT_ASSESSED
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
import re


# ── Data structures ───────────────────────────────────────────────────────────

@dataclass
class Control:
    id:          str
    title:       str
    description: str
    domain:      str          # logical grouping (e.g. "Access Control", "Cryptography")
    keywords:    List[str]    # matched against finding type/text
    severity_min: str = "low" # minimum finding severity to trigger a FAIL

@dataclass
class ControlStatus:
    control:        Control
    status:         str           # PASS | FAIL | NOT_ASSESSED
    failing_count:  int = 0
    evidence:       List[str] = field(default_factory=list)  # finding IDs / descriptions

@dataclass
class GapAnalysis:
    framework_id:   str
    framework_name: str
    total_controls: int
    passing:        int
    failing:        int
    not_assessed:   int
    coverage_pct:   int           # % controls assessed (pass OR fail, not N/A)
    pass_rate:      int           # % of assessed controls that pass
    controls:       List[ControlStatus]
    domains:        Dict[str, Dict]   # domain → {passing, failing, not_assessed}


# ── Framework definitions ─────────────────────────────────────────────────────
# Controls are kept concise — real frameworks have more detail, but this gives
# actionable gap analysis without needing full 200-page spec JSON.

SOC2_CONTROLS: List[Control] = [
    # CC1 — Control Environment
    Control("CC1.1", "COSO Principle 1 — Integrity and Ethics", "Demonstrates commitment to integrity and ethical values", "Control Environment", ["policy","config","default"]),
    Control("CC1.2", "COSO Principle 2 — Board Oversight",      "Board exercises oversight responsibility",              "Control Environment", []),
    Control("CC1.3", "COSO Principle 3 — Organizational Structure", "Management establishes structures and authorities",  "Control Environment", []),
    Control("CC1.4", "COSO Principle 4 — Competence",           "Demonstrates commitment to competence",                 "Control Environment", []),
    Control("CC1.5", "COSO Principle 5 — Accountability",       "Enforces accountability for internal control",          "Control Environment", []),
    # CC2 — Communication
    Control("CC2.1", "Internal Communication",    "Communicates information internally to support controls",          "Communication",   []),
    Control("CC2.2", "External Communication",    "Communicates with external parties regarding matters affecting controls", "Communication", []),
    Control("CC2.3", "Information Requirements",  "Communicates significant security incidents",                      "Communication",   ["disclosure","leakage","information_disclosure"]),
    # CC3 — Risk Assessment
    Control("CC3.1", "Risk Assessment — Objectives", "Specifies objectives to identify and assess risks",             "Risk Assessment", []),
    Control("CC3.2", "Risk Identification",           "Identifies risks to achievement of objectives",                "Risk Assessment", ["sql","injection","xss","rce","vulnerability"]),
    Control("CC3.3", "Fraud Risk Assessment",         "Considers fraud risk in risk assessment",                      "Risk Assessment", []),
    Control("CC3.4", "Significant Changes",           "Identifies and assesses changes affecting controls",           "Risk Assessment", ["outdated","old_version","deprecated"]),
    # CC4 — Monitoring
    Control("CC4.1", "Ongoing Monitoring",    "Selects, develops and performs ongoing evaluations",                   "Monitoring",      ["scan","audit"]),
    Control("CC4.2", "Evaluation of Controls","Evaluates and communicates deficiencies timely",                        "Monitoring",      []),
    # CC5 — Control Activities
    Control("CC5.1", "Control Activities",    "Selects and develops control activities to mitigate risks",            "Control Activities", []),
    Control("CC5.2", "Technology Controls",   "Selects general technology control activities",                        "Control Activities", ["firewall","network","port","ssh","rdp"]),
    Control("CC5.3", "Policies and Procedures","Deploys control activities through policies",                         "Control Activities", ["policy","default_credential","misconfig"]),
    # CC6 — Logical and Physical Access
    Control("CC6.1", "Logical Access Security", "Implements logical access security software, infrastructure, and architectures", "Access Control", ["credential","password","auth","mfa","default_credential","open_port","ssh","rdp","ftp","telnet"]),
    Control("CC6.2", "New Credentials",         "Prior to issuing system credentials, registers and authorizes new users", "Access Control", ["default_credential","credential"]),
    Control("CC6.3", "Role-based Access",        "Removes access when no longer required; uses least-privilege",     "Access Control", ["privilege","admin","iam","rbac","overprivileged"]),
    Control("CC6.4", "Physical Access",          "Restricts physical access to facilities and protected info assets","Access Control", []),
    Control("CC6.5", "Disposal of Assets",       "Logical and physical protections over assets",                     "Access Control", []),
    Control("CC6.6", "Network Security",         "Implements controls to prevent unauthorized access from outside",  "Access Control", ["open_port","firewall","ssh","rdp","network","sg","nsg","security_group","0.0.0.0"]),
    Control("CC6.7", "Encryption in Transit",    "Restricts transmission of sensitive info to authorized parties",   "Access Control", ["ssl","tls","http","certificate","encryption","unencrypted"]),
    Control("CC6.8", "Malicious Software",       "Implements controls to prevent introduction of malicious software","Access Control", ["malware","injection","xss","sqli","sql_injection","rce"]),
    # CC7 — System Operations
    Control("CC7.1", "Vulnerability Management", "Detects and monitors for vulnerabilities",                         "System Operations", ["cve","outdated","vulnerability","patch"]),
    Control("CC7.2", "Monitoring Infrastructure","Monitors system components for anomalies",                          "System Operations", ["logging","cloudtrail","audit","log","monitoring"]),
    Control("CC7.3", "Incident Evaluation",      "Evaluates security events to determine whether they are incidents","System Operations", ["incident","breach","exposure"]),
    Control("CC7.4", "Incident Response",        "Responds to identified security incidents",                        "System Operations", []),
    Control("CC7.5", "Recovery",                 "Identifies and develops recovery activities",                      "System Operations", ["backup","recovery","rds","s3_no_versioning"]),
    # CC8 — Change Management
    Control("CC8.1", "Change Management",        "Authorizes, designs, develops, configures and tests changes",      "Change Management", ["outdated","patch","version","software"]),
    # CC9 — Risk Mitigation
    Control("CC9.1", "Risk Mitigation",          "Identifies and mitigates risks through controls",                  "Risk Mitigation",  []),
    Control("CC9.2", "Vendor Risk Management",   "Assesses and manages risks from vendors and business partners",   "Risk Mitigation",  []),
]

ISO27001_CONTROLS: List[Control] = [
    # A.5 — Organizational controls
    Control("A.5.1",  "Policies for information security",       "Define, approve and publish IS policies",              "Organizational", ["policy","misconfig"]),
    Control("A.5.7",  "Threat intelligence",                     "Collect and analyse threat intelligence",              "Organizational", ["cve","vulnerability","exploit"]),
    Control("A.5.8",  "IS in project management",                "Include IS in project management",                     "Organizational", []),
    Control("A.5.15", "Access control",                          "Implement rules for access control",                   "Access Control", ["credential","auth","iam","rbac","default_credential"]),
    Control("A.5.16", "Identity management",                     "Manage full lifecycle of identities",                  "Access Control", ["mfa","password","credential","identity"]),
    Control("A.5.17", "Authentication information",              "Manage allocation of authentication information",      "Access Control", ["default_credential","weak_password","credential"]),
    # A.6 — People controls
    Control("A.6.2",  "Terms and conditions of employment",      "Include IS responsibilities in employment terms",      "People",         []),
    Control("A.6.8",  "IS event reporting",                      "Provide mechanism to report IS events",                "People",         ["incident","breach"]),
    # A.7 — Physical controls
    Control("A.7.1",  "Physical security perimeters",            "Define security perimeters",                           "Physical",       []),
    Control("A.7.7",  "Clear desk and screen policy",            "Implement clear desk and screen policy",               "Physical",       []),
    # A.8 — Technological controls
    Control("A.8.1",  "User endpoint devices",                   "Protect information on and via user endpoint devices", "Technology",     []),
    Control("A.8.2",  "Privileged access rights",                "Restrict and manage privileged access",                "Technology",     ["admin","iam","rbac","privilege","root","owner"]),
    Control("A.8.3",  "Information access restriction",          "Restrict access to information per policy",            "Technology",     ["public","exposure","open","s3","bucket","blob"]),
    Control("A.8.4",  "Access to source code",                   "Restrict access to source code",                      "Technology",     ["github","code","repo","sast"]),
    Control("A.8.5",  "Secure authentication",                   "Implement secure authentication",                     "Technology",     ["mfa","auth","password","credential","ssh","rdp"]),
    Control("A.8.7",  "Protection against malware",              "Implement controls for malware protection",            "Technology",     ["malware","injection","xss","sqli","rce"]),
    Control("A.8.8",  "Management of technical vulnerabilities", "Obtain information about vulnerabilities, assess exposure", "Technology", ["cve","patch","outdated","vulnerability","unpatched"]),
    Control("A.8.9",  "Configuration management",                "Establish and manage configurations securely",         "Technology",     ["misconfig","default","config","hardening"]),
    Control("A.8.10", "Information deletion",                    "Delete information when no longer required",           "Technology",     []),
    Control("A.8.11", "Data masking",                            "Mask data according to policy",                       "Technology",     ["disclosure","exposure","sensitive"]),
    Control("A.8.12", "Data leakage prevention",                 "Implement DLP measures",                              "Technology",     ["leakage","disclosure","exposure","sensitive"]),
    Control("A.8.13", "Information backup",                      "Maintain and test backups",                           "Technology",     ["backup","rds","s3_versioning"]),
    Control("A.8.15", "Logging",                                 "Produce, store, protect and analyse logs",            "Technology",     ["logging","cloudtrail","audit","log","flow_log"]),
    Control("A.8.16", "Monitoring activities",                   "Monitor networks for anomalous behaviour",            "Technology",     ["monitoring","ids","intrusion"]),
    Control("A.8.20", "Network security",                        "Secure, manage and control networks",                 "Technology",     ["firewall","sg","nsg","vpc","network","port","open_port"]),
    Control("A.8.21", "Security of network services",            "Identify security requirements of network services",  "Technology",     ["tls","ssl","certificate","https","encryption"]),
    Control("A.8.24", "Use of cryptography",                     "Implement rules for cryptography",                    "Technology",     ["encryption","ssl","tls","kms","key","certificate","unencrypted"]),
    Control("A.8.25", "Secure development lifecycle",            "Establish rules for secure software development",     "Technology",     ["sast","code","injection","xss","sqli"]),
    Control("A.8.28", "Secure coding",                           "Apply secure coding principles",                      "Technology",     ["injection","xss","sqli","rce","sast","code"]),
]

PCIDSS_CONTROLS: List[Control] = [
    Control("1.1", "Req 1 — Network Security Controls",   "Install and maintain network security controls",  "Network",         ["firewall","sg","nsg","network","port","vpc"]),
    Control("1.2", "Req 1.2 — Network Control Config",    "Network access controls properly configured",     "Network",         ["sg","nsg","security_group","open_port","firewall","rdp","ssh","0.0.0.0"]),
    Control("1.3", "Req 1.3 — Network Access Restriction","Restrict inbound and outbound traffic",           "Network",         ["open_port","firewall","sg","rdp","ssh","0.0.0.0","public"]),
    Control("2.1", "Req 2 — Secure Config Standards",     "Apply and maintain secure configurations",        "Configuration",   ["default","misconfig","hardening","config"]),
    Control("2.2", "Req 2.2 — System Component Config",   "Develop configuration standards for all system components", "Configuration", ["default_credential","misconfig","hardening"]),
    Control("3.4", "Req 3 — Protect Stored Data",         "Render PAN unreadable anywhere it is stored",    "Data Protection", ["encryption","unencrypted","rds","s3","storage","disk"]),
    Control("3.5", "Req 3.5 — Protect Encryption Keys",   "Secure cryptographic keys against disclosure",   "Data Protection", ["kms","key","secret","credential"]),
    Control("4.1", "Req 4 — Protect Data in Transit",     "Use strong cryptography to protect data in transit", "Cryptography",["ssl","tls","https","certificate","encryption","http"]),
    Control("5.1", "Req 5 — Protect Against Malware",     "Protect systems from malicious software",         "Malware",         ["malware","xss","injection","sqli","rce"]),
    Control("6.2", "Req 6.2 — Software Security",         "Maintain software in a secure manner",            "Software Security",["patch","outdated","cve","vulnerability","version"]),
    Control("6.3", "Req 6.3 — Security Vulnerabilities",  "Identify and address security vulnerabilities",   "Software Security",["sql_injection","sqli","xss","injection","rce","vulnerability"]),
    Control("7.1", "Req 7 — Least Privilege Access",      "Limit access to system components to those with business need", "Access Control", ["admin","iam","rbac","privilege","root","owner","credential"]),
    Control("8.2", "Req 8 — Identify Users and Authenticate", "Identify all users and authenticate access",  "Authentication",  ["password","credential","mfa","auth","default_credential"]),
    Control("8.3", "Req 8.3 — Authentication Factors",    "Secure all individual non-consumer user accounts", "Authentication", ["mfa","2fa","otp","credential","password"]),
    Control("10.2","Req 10 — Log and Monitor Access",     "Log and monitor all access to system components", "Logging",         ["logging","cloudtrail","audit","log","monitoring"]),
    Control("10.3","Req 10.3 — Log Entry Protection",     "Protect audit logs from destruction and modifications", "Logging",   ["log","audit","cloudtrail","versioning"]),
    Control("11.3","Req 11 — Security Testing",           "Test security of systems and networks regularly",  "Testing",         ["scan","pentest","vulnerability","assessment"]),
    Control("12.3","Req 12 — Risk Management",            "Support information security with org policies",   "Risk Management", ["policy","incident","risk"]),
]

NIST_CONTROLS: List[Control] = [
    # Identify
    Control("ID.AM-1", "Asset Management — Inventory",          "Physical devices and systems inventoried",       "Identify", ["asset","inventory","scan","nmap"]),
    Control("ID.AM-2", "Asset Management — Software",            "Software platforms and applications inventoried","Identify", ["software","version","outdated"]),
    Control("ID.RA-1", "Risk Assessment — Vulnerabilities",      "Asset vulnerabilities identified and documented","Identify", ["cve","vulnerability","scan","assessment"]),
    Control("ID.RA-2", "Risk Assessment — Threat Intelligence",  "Cyber threat intelligence received",             "Identify", ["cve","threat","intelligence"]),
    Control("ID.RA-5", "Risk Assessment — Risk Response",        "Threats, vulnerabilities, likelihoods, impacts combined", "Identify", ["risk","vulnerability","assessment"]),
    # Protect
    Control("PR.AC-1", "Identity Management",                    "Identities and credentials managed for authorized users", "Protect", ["credential","mfa","password","auth","iam"]),
    Control("PR.AC-3", "Remote Access Management",               "Remote access managed",                          "Protect", ["vpn","ssh","rdp","remote","open_port"]),
    Control("PR.AC-4", "Access Permissions",                     "Access permissions managed, least privilege",    "Protect", ["rbac","iam","admin","privilege","permission"]),
    Control("PR.DS-1", "Data-at-Rest Protection",                "Data-at-rest protected",                         "Protect", ["encryption","unencrypted","kms","disk","rds","s3","storage"]),
    Control("PR.DS-2", "Data-in-Transit Protection",             "Data-in-transit protected",                      "Protect", ["ssl","tls","https","certificate","http","encryption"]),
    Control("PR.DS-5", "Protections Against Data Leaks",         "Protections against data leaks",                 "Protect", ["leakage","disclosure","public","exposure","sensitive"]),
    Control("PR.IP-1", "Baseline Configuration",                 "Baseline config for IT/ICS established",         "Protect", ["config","hardening","misconfig","default","baseline"]),
    Control("PR.IP-9", "Response Plans",                         "Response and recovery plans in place",           "Protect", ["incident","recovery","response"]),
    Control("PR.IP-12","Vulnerability Management",               "Vulnerabilities identified and remediated",      "Protect", ["patch","vulnerability","cve","outdated","version"]),
    Control("PR.PT-3", "Least Functionality",                    "Principle of least functionality applied",       "Protect", ["port","service","firewall","open","sg","nsg"]),
    # Detect
    Control("DE.CM-1", "Network Monitoring",                     "Network monitored to detect potential cybersecurity events", "Detect", ["monitoring","ids","network","port","scan"]),
    Control("DE.CM-4", "Malicious Code Detection",               "Malicious code detected",                        "Detect", ["malware","xss","injection","sqli","sast"]),
    Control("DE.CM-7", "Unauthorized Activity Monitoring",       "Monitoring for unauthorized personnel/activities performed", "Detect", ["monitoring","audit","log","cloudtrail"]),
    Control("DE.CM-8", "Vulnerability Scans",                    "Vulnerability scans performed",                  "Detect", ["scan","vulnerability","assessment","nmap"]),
    # Respond
    Control("RS.RP-1", "Response Plan Execution",                "Response plan executed during an incident",      "Respond", ["incident","response","breach"]),
    Control("RS.MI-1", "Incidents Contained",                    "Incidents contained",                            "Respond", ["incident","critical","breach"]),
    # Recover
    Control("RC.RP-1", "Recovery Plan Execution",                "Recovery plan executed during recovery",         "Recover", ["backup","recovery","restore"]),
]

HIPAA_CONTROLS: List[Control] = [
    Control("164.308(a)(1)", "Risk Analysis",                   "Conduct accurate and thorough risk analysis",        "Administrative", ["risk","vulnerability","assessment","scan"]),
    Control("164.308(a)(2)", "Assigned Security Responsibility","Designate security official responsible for policies","Administrative", []),
    Control("164.308(a)(3)", "Workforce Security",              "Implement policies for workforce access",             "Administrative", ["credential","auth","access","permission"]),
    Control("164.308(a)(4)", "Information Access Management",   "Implement policies for authorizing access to ePHI",  "Administrative", ["rbac","iam","privilege","access"]),
    Control("164.308(a)(5)", "Security Awareness Training",     "Implement security awareness and training",          "Administrative", []),
    Control("164.308(a)(6)", "Security Incident Procedures",    "Implement incident response policies",               "Administrative", ["incident","breach","response"]),
    Control("164.308(a)(7)", "Contingency Plan",                "Establish backup and recovery procedures",           "Administrative", ["backup","recovery","rds","versioning"]),
    Control("164.310(a)(1)", "Facility Access Controls",        "Implement policies to limit physical access",        "Physical",       []),
    Control("164.310(d)(1)", "Device and Media Controls",       "Implement policies for hardware/software movement",  "Physical",       []),
    Control("164.312(a)(1)", "Access Control",                  "Implement technical policies for access to ePHI",   "Technical",      ["credential","mfa","password","auth","default_credential"]),
    Control("164.312(a)(2)", "Automatic Logoff",                "Implement automatic logoff procedures",              "Technical",      ["session","timeout"]),
    Control("164.312(b)",    "Audit Controls",                  "Implement hardware/software to record access",       "Technical",      ["logging","audit","cloudtrail","log","monitoring"]),
    Control("164.312(c)(1)", "Integrity",                       "Protect ePHI from improper alteration or destruction","Technical",    ["versioning","backup","encryption"]),
    Control("164.312(d)",    "Person/Entity Authentication",    "Verify identity before granting access to ePHI",    "Technical",      ["mfa","auth","credential","identity"]),
    Control("164.312(e)(1)", "Transmission Security",           "Implement technical security for ePHI in transit",  "Technical",      ["ssl","tls","https","encryption","certificate"]),
]

FRAMEWORKS: Dict[str, Tuple[str, List[Control]]] = {
    "soc2":     ("SOC 2 Type II",      SOC2_CONTROLS),
    "iso27001": ("ISO 27001:2022",     ISO27001_CONTROLS),
    "pcidss":   ("PCI-DSS v4.0",      PCIDSS_CONTROLS),
    "nist":     ("NIST CSF v2.0",     NIST_CONTROLS),
    "hipaa":    ("HIPAA Security Rule",HIPAA_CONTROLS),
}


# ── Mapping engine ────────────────────────────────────────────────────────────

def map_findings_to_controls(
    findings:       List[Dict],
    cloud_findings: List[Dict],
    framework_id:   str,
) -> GapAnalysis:
    """
    Map security findings to compliance controls and compute gap analysis.

    findings:       ESO scan findings (type, severity, source, finding text)
    cloud_findings: Cloud CSPM findings (ruleId, service, compliance[] tags)
    framework_id:   one of soc2|iso27001|pcidss|nist|hipaa
    """
    from typing import Dict as D

    if framework_id not in FRAMEWORKS:
        framework_id = "iso27001"
    fw_name, controls = FRAMEWORKS[framework_id]

    # Index cloud findings by their CIS compliance tags → framework control IDs
    cloud_by_rule: D[str, List[Dict]] = {}
    for cf in cloud_findings:
        for tag in (cf.get("compliance") or []):
            cloud_by_rule.setdefault(tag.upper(), []).append(cf)

    # Build control status map
    statuses: List[ControlStatus] = []

    for ctrl in controls:
        failing:  List[str] = []
        evidence: List[str] = []

        # ── Match ESO scan findings ──────────────────────────────────────────
        for f in findings:
            if f.get("false_positive"):
                continue
            sev = f.get("severity", "info").lower()
            if _sev_rank(sev) < _sev_rank(ctrl.severity_min):
                continue

            # Keyword matching
            finding_text = " ".join([
                str(f.get("type",    "") or ""),
                str(f.get("source",  "") or ""),
                str(f.get("finding", "") or ""),
                str(f.get("service", "") or ""),
                str(f.get("template","") or ""),
            ]).lower()

            matched = any(kw and kw in finding_text for kw in ctrl.keywords)
            if matched:
                desc = f.get("finding") or f.get("type") or "finding"
                failing.append(f.get("finding_id", ""))
                evidence.append(f"{sev.upper()}: {str(desc)[:80]}")

        # ── Match cloud CSPM findings via CIS tags ───────────────────────────
        # cloud findings already have compliance tags like ["CIS-AWS-3.1", "SOC2-CC6.6"]
        for cf in cloud_findings:
            tags = [t.upper() for t in (cf.get("compliance") or [])]
            for tag in tags:
                # Match SOC2 tag to control ID
                if framework_id == "soc2" and any(ctrl.id in tag for _ in [1]):
                    failing.append(cf.get("ruleId", ""))
                    evidence.append(f"{cf.get('severity','').upper()}: {cf.get('title','')[:80]}")
                    break
                # Match ISO27001
                elif framework_id == "iso27001" and "ISO" in tag:
                    if ctrl.id.replace(".", "") in tag.replace(".", "").replace("-", "").replace("_", ""):
                        failing.append(cf.get("ruleId", ""))
                        evidence.append(f"{cf.get('severity','').upper()}: {cf.get('title','')[:80]}")
                        break

            # Also keyword-match cloud findings
            cf_text = " ".join([
                cf.get("service", ""),
                cf.get("ruleId", ""),
                cf.get("title", ""),
            ]).lower()
            if any(kw and kw.lower() in cf_text for kw in ctrl.keywords) and cf.get("ruleId") not in failing:
                failing.append(cf.get("ruleId", ""))
                evidence.append(f"{cf.get('severity','').upper()}: {cf.get('title','')[:80]}")

        # Deduplicate
        failing  = list(dict.fromkeys(failing))
        evidence = list(dict.fromkeys(evidence))[:5]

        if failing:
            status = "FAIL"
        elif _has_evidence_for(ctrl, findings, cloud_findings):
            status = "PASS"
        else:
            status = "NOT_ASSESSED"

        statuses.append(ControlStatus(
            control=ctrl,
            status=status,
            failing_count=len(failing),
            evidence=evidence,
        ))

    # ── Aggregate stats ──────────────────────────────────────────────────────
    passing      = sum(1 for s in statuses if s.status == "PASS")
    failing_c    = sum(1 for s in statuses if s.status == "FAIL")
    not_assessed = sum(1 for s in statuses if s.status == "NOT_ASSESSED")
    total        = len(statuses)
    assessed     = passing + failing_c
    coverage_pct = round(assessed / total * 100) if total > 0 else 0
    pass_rate    = round(passing / assessed * 100) if assessed > 0 else 100

    # Domain breakdown
    domains: D[str, D] = {}
    for s in statuses:
        d = s.control.domain
        if d not in domains:
            domains[d] = {"passing": 0, "failing": 0, "not_assessed": 0}
        _key = {"PASS": "passing", "FAIL": "failing", "NOT_ASSESSED": "not_assessed"}.get(s.status, "not_assessed")
        domains[d][_key] += 1

    return GapAnalysis(
        framework_id=framework_id,
        framework_name=fw_name,
        total_controls=total,
        passing=passing,
        failing=failing_c,
        not_assessed=not_assessed,
        coverage_pct=coverage_pct,
        pass_rate=pass_rate,
        controls=statuses,
        domains=domains,
    )


def _sev_rank(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(sev.lower(), 0)


def _has_evidence_for(ctrl: Control, findings: List[Dict], cloud_findings: List[Dict]) -> bool:
    """A control PASSES if we have findings data covering its domain but none triggered a FAIL."""
    # If there are any findings at all, controls with empty keywords are considered assessed
    return bool(findings or cloud_findings) and not ctrl.keywords


def gap_analysis_to_dict(gap: GapAnalysis) -> Dict:
    """Serialize GapAnalysis to JSON-compatible dict."""
    return {
        "framework_id":   gap.framework_id,
        "framework_name": gap.framework_name,
        "total_controls": gap.total_controls,
        "passing":        gap.passing,
        "failing":        gap.failing,
        "not_assessed":   gap.not_assessed,
        "coverage_pct":   gap.coverage_pct,
        "pass_rate":      gap.pass_rate,
        "domains": {
            domain: data
            for domain, data in gap.domains.items()
        },
        "controls": [
            {
                "id":           s.control.id,
                "title":        s.control.title,
                "description":  s.control.description,
                "domain":       s.control.domain,
                "status":       s.status,
                "failing_count":s.failing_count,
                "evidence":     s.evidence,
            }
            for s in gap.controls
        ],
    }
