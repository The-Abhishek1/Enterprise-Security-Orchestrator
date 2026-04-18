"""
compliance_report.py — Compliance-mapped pentest PDF reports.

Extends existing PDFReportGenerator with framework mappings.
Supports: SOC2, ISO27001, PCI-DSS, NIST-CSF

Each finding is mapped to relevant control IDs automatically.
Route: POST /api/v1/reports/compliance
Tier required: enterprise
"""
from typing import Dict, Any, List, Optional
from datetime import datetime
import io

from src.utils.logging import logger

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white, grey
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether
    )
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


# ── Framework control mappings ────────────────────────────────────────────────
# Maps finding type/severity to compliance control IDs

SOC2_CONTROLS: Dict[str, List[str]] = {
    "open_port":          ["CC6.6", "CC6.1"],
    "ssl_issue":          ["CC6.7", "CC6.1"],
    "sql_injection":      ["CC6.6", "CC3.2"],
    "xss":                ["CC6.6", "CC3.2"],
    "default_credential": ["CC6.1", "CC6.2"],
    "outdated_software":  ["CC7.1", "CC6.8"],
    "misconfig":          ["CC6.3", "CC6.1"],
    "information_disclosure": ["CC6.1", "CC6.7"],
    "critical":           ["CC6.6", "CC7.2", "CC3.4"],
    "high":               ["CC6.6", "CC7.1"],
}

ISO27001_CONTROLS: Dict[str, List[str]] = {
    "open_port":          ["A.13.1.1", "A.9.4.2"],
    "ssl_issue":          ["A.10.1.1", "A.13.2.1"],
    "sql_injection":      ["A.14.2.5", "A.12.6.1"],
    "xss":                ["A.14.2.5", "A.12.6.1"],
    "default_credential": ["A.9.2.4", "A.9.3.1"],
    "outdated_software":  ["A.12.6.1", "A.14.2.2"],
    "misconfig":          ["A.12.5.1", "A.14.2.2"],
    "information_disclosure": ["A.13.2.1", "A.8.2.3"],
    "critical":           ["A.16.1.5", "A.12.6.1", "A.18.2.2"],
    "high":               ["A.12.6.1", "A.14.2.2"],
}

PCIDSS_CONTROLS: Dict[str, List[str]] = {
    "open_port":          ["Req 1.3", "Req 1.2"],
    "ssl_issue":          ["Req 4.1", "Req 4.2"],
    "sql_injection":      ["Req 6.3.1", "Req 6.4"],
    "xss":                ["Req 6.3.1", "Req 6.4"],
    "default_credential": ["Req 2.1", "Req 8.2"],
    "outdated_software":  ["Req 6.2", "Req 6.3"],
    "misconfig":          ["Req 2.2", "Req 6.2"],
    "information_disclosure": ["Req 3.4", "Req 4.1"],
    "critical":           ["Req 6.3.1", "Req 11.3", "Req 12.3"],
    "high":               ["Req 6.2", "Req 11.3"],
}

NIST_CONTROLS: Dict[str, List[str]] = {
    "open_port":          ["PR.AC-3", "PR.PT-3"],
    "ssl_issue":          ["PR.DS-2", "PR.DS-5"],
    "sql_injection":      ["PR.DS-5", "DE.CM-4"],
    "xss":                ["PR.DS-5", "DE.CM-4"],
    "default_credential": ["PR.AC-1", "PR.AC-4"],
    "outdated_software":  ["PR.IP-12", "DE.CM-8"],
    "misconfig":          ["PR.IP-1", "DE.CM-7"],
    "information_disclosure": ["PR.DS-5", "PR.AC-3"],
    "critical":           ["RS.RP-1", "RS.MI-1", "PR.IP-9"],
    "high":               ["DE.CM-4", "PR.IP-12"],
}

FRAMEWORKS = {
    "soc2":     ("SOC 2 Type II", SOC2_CONTROLS),
    "iso27001": ("ISO 27001:2022", ISO27001_CONTROLS),
    "pcidss":   ("PCI-DSS v4.0", PCIDSS_CONTROLS),
    "nist":     ("NIST CSF v2.0", NIST_CONTROLS),
}


def _get_controls(finding: Dict, framework_map: Dict[str, List[str]]) -> List[str]:
    """Get relevant controls for a finding based on type + severity."""
    controls: set = set()

    finding_type = finding.get("type", "").lower()
    severity     = finding.get("validated_severity", finding.get("severity", "info"))

    # Match by type keywords
    for key, ctrl_list in framework_map.items():
        if key in finding_type or key in finding.get("finding", "").lower():
            controls.update(ctrl_list)

    # Add severity-based controls
    if severity in framework_map:
        controls.update(framework_map[severity])

    return sorted(controls)[:4]  # cap at 4 controls per finding


# ── Colors ────────────────────────────────────────────────────────────────────
PRIMARY   = HexColor("#0f172a") if HAS_REPORTLAB else None
ACCENT    = HexColor("#00aaff") if HAS_REPORTLAB else None
CRITICAL  = HexColor("#dc2626") if HAS_REPORTLAB else None
HIGH      = HexColor("#ea580c") if HAS_REPORTLAB else None
MEDIUM    = HexColor("#ca8a04") if HAS_REPORTLAB else None
LOW       = HexColor("#2563eb") if HAS_REPORTLAB else None
INFO_CLR  = HexColor("#6b7280") if HAS_REPORTLAB else None
BG_LIGHT  = HexColor("#f8fafc") if HAS_REPORTLAB else None
BG_DARK   = HexColor("#1e293b") if HAS_REPORTLAB else None

SEV_COLORS = {
    "critical": CRITICAL, "high": HIGH,
    "medium": MEDIUM, "low": LOW, "info": INFO_CLR,
}


class ComplianceReportGenerator:
    """Generates compliance-mapped pentest PDF reports."""

    def generate(self, scan_data: Dict, framework: str = "iso27001") -> Optional[bytes]:
        if not HAS_REPORTLAB:
            logger.warning("reportlab not installed")
            return None

        framework = framework.lower()
        if framework not in FRAMEWORKS:
            framework = "iso27001"

        fw_name, fw_map = FRAMEWORKS[framework]

        buffer = io.BytesIO()
        styles = self._build_styles()

        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=20*mm, rightMargin=20*mm,
            topMargin=25*mm, bottomMargin=20*mm,
            title=f"Compliance Report — {fw_name}",
        )

        story = self._build_story(scan_data, styles, fw_name, fw_map)
        doc.build(story, onFirstPage=self._page_header, onLaterPages=self._page_header)

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logger.info(f"📋 Compliance PDF generated ({len(pdf_bytes)} bytes, {fw_name})")
        return pdf_bytes

    # ── Story ─────────────────────────────────────────────────────────────────

    def _build_story(self, data: Dict, s, fw_name: str, fw_map: Dict) -> list:
        story = []
        target   = data.get("target", "Unknown")
        findings = data.get("findings", [])
        rs       = data.get("risk_summary", {})
        tools    = data.get("tools_used", [])
        duration = data.get("duration", 0)
        report_date = datetime.utcnow().strftime("%Y-%m-%d")

        # ── Cover page ──────────────────────────────────────────────────────
        story.append(Spacer(1, 30))

        # Header bar
        story.append(Table(
            [[Paragraph("COMPLIANCE ASSESSMENT REPORT", s["cover_title"])]],
            colWidths=[170*mm],
            style=[("BACKGROUND", (0,0), (-1,-1), PRIMARY),
                   ("TOPPADDING", (0,0), (-1,-1), 14),
                   ("BOTTOMPADDING", (0,0), (-1,-1), 14),
                   ("LEFTPADDING", (0,0), (-1,-1), 12)],
        ))

        story.append(Spacer(1, 16))
        story.append(Paragraph(f"Framework: <b>{fw_name}</b>", s["cover_sub"]))
        story.append(Paragraph(f"Target: <b>{target}</b>", s["cover_sub"]))
        story.append(Paragraph(f"Date: {report_date}  |  Tools: {', '.join(tools) or 'N/A'}  |  Duration: {duration:.0f}s", s["cover_meta"]))
        story.append(HRFlowable(width="100%", thickness=1, color=ACCENT, spaceAfter=10, spaceBefore=10))

        # Risk summary
        crit = rs.get("critical_count", 0)
        high = rs.get("high_count", 0)
        med  = rs.get("medium_count", 0)
        low  = rs.get("low_count", 0)
        overall = rs.get("overall_risk", "unknown").upper()
        overall_score = rs.get("overall_score", 0)

        story.append(Paragraph("Executive Summary", s["section"]))
        story.append(Paragraph(
            f"This assessment of <b>{target}</b> identified <b>{len(findings)}</b> findings "
            f"({crit} critical, {high} high, {med} medium, {low} low) with an overall risk "
            f"rating of <b>{overall}</b> ({overall_score:.1f}/10). "
            f"Controls are mapped to {fw_name} requirements below.",
            s["body"]
        ))
        story.append(Spacer(1, 10))

        # Summary table
        summary_data = [
            ["Risk Level", "Count", "Compliance Impact"],
            ["CRITICAL", str(crit), "Immediate remediation required — likely fails audit"],
            ["HIGH",     str(high), "Remediate before next assessment cycle"],
            ["MEDIUM",   str(med),  "Remediate within 90 days"],
            ["LOW",      str(low),  "Remediate within 180 days — informational risk"],
        ]
        t = Table(summary_data, colWidths=[45*mm, 25*mm, 100*mm])
        t.setStyle(TableStyle([
            ("BACKGROUND",   (0,0), (-1,0), PRIMARY),
            ("TEXTCOLOR",    (0,0), (-1,0), white),
            ("FONTSIZE",     (0,0), (-1,-1), 9),
            ("ALIGN",        (0,0), (-1,-1), "LEFT"),
            ("VALIGN",       (0,0), (-1,-1), "MIDDLE"),
            ("GRID",         (0,0), (-1,-1), 0.4, grey),
            ("TOPPADDING",   (0,0), (-1,-1), 5),
            ("BOTTOMPADDING",(0,0), (-1,-1), 5),
            ("LEFTPADDING",  (0,0), (-1,-1), 6),
            ("BACKGROUND",   (0,1), (0,1), CRITICAL),
            ("TEXTCOLOR",    (0,1), (0,1), white),
            ("BACKGROUND",   (0,2), (0,2), HIGH),
            ("TEXTCOLOR",    (0,2), (0,2), white),
            ("BACKGROUND",   (0,3), (0,3), MEDIUM),
            ("BACKGROUND",   (0,4), (0,4), LOW),
            ("TEXTCOLOR",    (0,4), (0,4), white),
        ]))
        story.append(t)
        story.append(PageBreak())

        # ── Compliance control mapping ───────────────────────────────────────
        story.append(Paragraph(f"{fw_name} — Control Mapping", s["section"]))
        story.append(Paragraph(
            "Each finding below is mapped to the relevant compliance controls. "
            "Findings that map to multiple controls require coordinated remediation.",
            s["body"]
        ))
        story.append(Spacer(1, 8))

        # Group findings by severity
        sev_order = ["critical", "high", "medium", "low", "info"]
        grouped: Dict[str, List] = {sv: [] for sv in sev_order}
        for f in findings:
            sv = f.get("validated_severity", f.get("severity", "info"))
            grouped.setdefault(sv, []).append(f)

        # Build control mapping table
        ctrl_rows = [["#", "Finding", "Severity", "Controls", "Recommendation"]]
        row_colors = []
        idx = 1
        sev_color_map = {
            "critical": CRITICAL, "high": HIGH,
            "medium": MEDIUM, "low": LOW, "info": INFO_CLR,
        }

        for sv in sev_order:
            for f in grouped.get(sv, []):
                controls    = _get_controls(f, fw_map)
                finding_txt = (f.get("finding") or f.get("service") or f.get("type") or "")[:80]
                mitigation  = (f.get("mitigation") or "Review and remediate")[:100]
                ctrl_txt    = "\n".join(controls) if controls else "N/A"
                port_info   = f" (port {f['port']})" if f.get("port") else ""

                ctrl_rows.append([
                    str(idx),
                    f"{finding_txt}{port_info}",
                    sv.upper(),
                    ctrl_txt,
                    mitigation,
                ])
                row_colors.append((sv, idx))
                idx += 1

                if idx > 60:  # cap at 60 findings per table
                    break

        if len(ctrl_rows) > 1:
            col_w = [10*mm, 50*mm, 22*mm, 38*mm, 50*mm]
            ct = Table(ctrl_rows, colWidths=col_w, repeatRows=1)
            table_style = [
                ("BACKGROUND",   (0,0), (-1,0), PRIMARY),
                ("TEXTCOLOR",    (0,0), (-1,0), white),
                ("FONTSIZE",     (0,0), (-1,-1), 7.5),
                ("ALIGN",        (0,0), (-1,-1), "LEFT"),
                ("VALIGN",       (0,0), (-1,-1), "TOP"),
                ("GRID",         (0,0), (-1,-1), 0.3, grey),
                ("TOPPADDING",   (0,0), (-1,-1), 4),
                ("BOTTOMPADDING",(0,0), (-1,-1), 4),
                ("LEFTPADDING",  (0,0), (-1,-1), 4),
                ("ROWBACKGROUNDS", (0,1), (-1,-1), [white, BG_LIGHT]),
            ]
            # Color severity column
            for sv, row_i in row_colors:
                clr = sev_color_map.get(sv, grey)
                table_style.append(("BACKGROUND", (2, row_i), (2, row_i), clr))
                table_style.append(("TEXTCOLOR",  (2, row_i), (2, row_i), white))
            ct.setStyle(TableStyle(table_style))
            story.append(ct)
        else:
            story.append(Paragraph("No findings to map.", s["body"]))

        story.append(PageBreak())

        # ── Remediation plan ────────────────────────────────────────────────
        story.append(Paragraph("Remediation Plan", s["section"]))
        story.append(Paragraph(
            "The following remediation timeline is recommended to achieve compliance. "
            "Critical and high findings must be resolved before any formal audit.",
            s["body"]
        ))
        story.append(Spacer(1, 8))

        timeline_data = [
            ["Timeline", "Severity", "Action Required", "Evidence Needed"],
            ["Immediate\n(0–7 days)",    "Critical", "Patch or mitigate all critical findings", "Patched version screenshot + rescan"],
            ["30 days",                  "High",     "Resolve all high severity findings",       "Ticket closure + rescan evidence"],
            ["90 days",                  "Medium",   "Remediate medium severity findings",       "Change log + updated config"],
            ["180 days",                 "Low",      "Address low severity findings",             "Risk acceptance or patch"],
            ["Continuous",               "All",      "Schedule quarterly automated rescans",     "XCloak scan history + reports"],
        ]
        rt = Table(timeline_data, colWidths=[30*mm, 25*mm, 70*mm, 45*mm], repeatRows=1)
        rt.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), PRIMARY),
            ("TEXTCOLOR",     (0,0), (-1,0), white),
            ("FONTSIZE",      (0,0), (-1,-1), 8),
            ("ALIGN",         (0,0), (-1,-1), "LEFT"),
            ("VALIGN",        (0,0), (-1,-1), "TOP"),
            ("GRID",          (0,0), (-1,-1), 0.3, grey),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 5),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [white, BG_LIGHT]),
        ]))
        story.append(rt)
        story.append(Spacer(1, 16))

        # ── Attestation box ─────────────────────────────────────────────────
        story.append(Paragraph("Assessor Declaration", s["section"]))
        story.append(Paragraph(
            "This report was generated by XCloak automated security assessment platform using "
            f"AI-orchestrated tooling. Assessment date: {report_date}. "
            "Findings were validated by AI analysis to remove false positives. "
            "This report is intended to support compliance activities and should be reviewed "
            "by a qualified security professional before submission to an auditor.",
            s["body"]
        ))

        sig_data = [
            ["Field", "Value"],
            ["Platform",       "XCloak Enterprise Security Orchestrator"],
            ["Assessment Date", report_date],
            ["Target",         target],
            ["Framework",      fw_name],
            ["Total Findings", str(len(findings))],
            ["Overall Risk",   f"{overall} ({overall_score:.1f}/10)"],
        ]
        st = Table(sig_data, colWidths=[60*mm, 110*mm])
        st.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0), BG_DARK),
            ("TEXTCOLOR",     (0,0), (-1,0), white),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("GRID",          (0,0), (-1,-1), 0.3, grey),
            ("TOPPADDING",    (0,0), (-1,-1), 5),
            ("BOTTOMPADDING", (0,0), (-1,-1), 5),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("ROWBACKGROUNDS",(0,1), (-1,-1), [white, BG_LIGHT]),
        ]))
        story.append(Spacer(1, 10))
        story.append(st)

        return story

    # ── Styles ────────────────────────────────────────────────────────────────

    def _build_styles(self):
        s = getSampleStyleSheet()
        s.add(ParagraphStyle("cover_title", parent=s["Title"],
            fontSize=18, textColor=white, spaceAfter=0, alignment=TA_LEFT))
        s.add(ParagraphStyle("cover_sub", parent=s["Normal"],
            fontSize=12, textColor=HexColor("#334155"), spaceAfter=4))
        s.add(ParagraphStyle("cover_meta", parent=s["Normal"],
            fontSize=9, textColor=grey, spaceAfter=4))
        s.add(ParagraphStyle("section", parent=s["Heading1"],
            fontSize=14, textColor=PRIMARY, spaceBefore=14, spaceAfter=6))
        s.add(ParagraphStyle("body", parent=s["Normal"],
            fontSize=9.5, leading=14, spaceAfter=6, alignment=TA_JUSTIFY))
        return s

    # ── Page header/footer ────────────────────────────────────────────────────

    @staticmethod
    def _page_header(canvas, doc):
        canvas.saveState()
        canvas.setFont("Helvetica-Bold", 7)
        canvas.setFillColor(HexColor("#94a3b8"))
        canvas.drawString(doc.leftMargin, 12*mm, "XCloak — Compliance Assessment Report — CONFIDENTIAL")
        canvas.drawRightString(A4[0] - doc.rightMargin, 12*mm, f"Page {canvas.getPageNumber()}")
        canvas.restoreStore if False else None  # no-op
        canvas.restoreState()


# Singleton
compliance_generator = ComplianceReportGenerator()
