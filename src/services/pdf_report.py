# src/services/pdf_report.py

"""
PDF Report Generator — creates downloadable pentest reports.
Uses reportlab for PDF creation.
"""

from typing import Dict, Any, List, Optional
from datetime import datetime
import io
import os
import re

from src.utils.logging import logger

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import inch, mm
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, black, white, grey
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_JUSTIFY
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable, KeepTogether
    )
    from reportlab.platypus.flowables import Flowable
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False
    logger.warning("⚠️ reportlab not installed — PDF export disabled (pip install reportlab)")


# Colors
PRIMARY = HexColor("#1a1a2e") if HAS_REPORTLAB else None
ACCENT = HexColor("#e94560") if HAS_REPORTLAB else None
SUCCESS = HexColor("#0f3460") if HAS_REPORTLAB else None
BG_LIGHT = HexColor("#f5f5f5") if HAS_REPORTLAB else None
SEVERITY_COLORS = {
    "critical": HexColor("#dc2626"),
    "high": HexColor("#ea580c"),
    "medium": HexColor("#ca8a04"),
    "low": HexColor("#2563eb"),
    "info": HexColor("#6b7280"),
    "none": HexColor("#9ca3af"),
} if HAS_REPORTLAB else {}


def _build_styles():
    """Create custom paragraph styles."""
    styles = getSampleStyleSheet()

    styles.add(ParagraphStyle(
        'ReportTitle', parent=styles['Title'],
        fontSize=24, textColor=PRIMARY, spaceAfter=6, alignment=TA_LEFT
    ))
    styles.add(ParagraphStyle(
        'ReportSubtitle', parent=styles['Normal'],
        fontSize=12, textColor=grey, spaceAfter=20, alignment=TA_LEFT
    ))
    styles.add(ParagraphStyle(
        'SectionHeading', parent=styles['Heading1'],
        fontSize=16, textColor=PRIMARY, spaceBefore=18, spaceAfter=8,
        borderWidth=0, borderPadding=0
    ))
    styles.add(ParagraphStyle(
        'SubHeading', parent=styles['Heading2'],
        fontSize=13, textColor=SUCCESS, spaceBefore=12, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        'ESOBody', parent=styles['Normal'],
        fontSize=10, leading=14, alignment=TA_JUSTIFY, spaceAfter=6
    ))
    styles.add(ParagraphStyle(
        'FindingText', parent=styles['Normal'],
        fontSize=9, leading=12, leftIndent=12, spaceAfter=4
    ))
    styles.add(ParagraphStyle(
        'SmallText', parent=styles['Normal'],
        fontSize=8, textColor=grey
    ))
    return styles


class PDFReportGenerator:
    """Generates professional pentest PDF reports."""

    def generate(self, scan_data: Dict) -> Optional[bytes]:
        """
        Generate PDF from scan data.
        Returns PDF bytes or None if reportlab unavailable.
        """
        if not HAS_REPORTLAB:
            logger.warning("reportlab not installed — cannot generate PDF")
            return None

        buffer = io.BytesIO()
        styles = _build_styles()

        doc = SimpleDocTemplate(
            buffer, pagesize=A4,
            leftMargin=20 * mm, rightMargin=20 * mm,
            topMargin=25 * mm, bottomMargin=20 * mm
        )

        story = self._build_story(scan_data, styles)
        doc.build(story, onFirstPage=self._header_footer, onLaterPages=self._header_footer)

        pdf_bytes = buffer.getvalue()
        buffer.close()
        logger.info(f"📄 PDF report generated ({len(pdf_bytes)} bytes)")
        return pdf_bytes

    # ------------------------------------------------------------------ #
    # Story builder
    # ------------------------------------------------------------------ #
    def _build_story(self, data: Dict, s) -> list:
        story = []
        target = data.get("target", "Unknown")
        risk_level = data.get("risk_level", data.get("risk_summary", {}).get("overall_risk", "none"))
        risk_score = data.get("risk_score", data.get("risk_summary", {}).get("overall_score", 0))
        duration = data.get("duration_seconds", data.get("duration", 0))
        tools = data.get("tools_used", [])
        report_md = data.get("report", "")

        # -- Title page --
        story.append(Spacer(1, 40))
        story.append(Paragraph("PENETRATION TEST REPORT", s['ReportTitle']))
        story.append(HRFlowable(width="100%", thickness=2, color=ACCENT, spaceAfter=12))
        story.append(Paragraph(f"Target: <b>{target}</b>", s['ReportSubtitle']))
        story.append(Paragraph(
            f"Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}  |  "
            f"Duration: {duration:.0f}s  |  "
            f"Risk: <b>{risk_level.upper()}</b> ({risk_score:.1f}/10)",
            s['ReportSubtitle']
        ))
        if tools:
            story.append(Paragraph(f"Tools: {', '.join(tools)}", s['ReportSubtitle']))

        story.append(Spacer(1, 10))

        # -- Risk summary table --
        rs = data.get("risk_summary", {})
        if rs:
            story.append(Paragraph("Risk Summary", s['SectionHeading']))
            risk_table_data = [
                ["Overall", "Critical", "High", "Medium", "Low", "Info"],
                [
                    f"{rs.get('overall_risk', 'N/A').upper()} ({rs.get('overall_score', 0):.1f})",
                    str(rs.get("critical_count", 0)),
                    str(rs.get("high_count", 0)),
                    str(rs.get("medium_count", 0)),
                    str(rs.get("low_count", 0)),
                    str(rs.get("info_count", 0)),
                ]
            ]
            t = Table(risk_table_data, colWidths=[100, 60, 60, 60, 60, 60])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
                ('TEXTCOLOR', (0, 0), (-1, 0), white),
                ('FONTSIZE', (0, 0), (-1, -1), 9),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('GRID', (0, 0), (-1, -1), 0.5, grey),
                ('BACKGROUND', (0, 1), (-1, 1), BG_LIGHT),
            ]))
            story.append(t)
            story.append(Spacer(1, 12))

        # -- Parse markdown report into PDF sections --
        if report_md:
            story.extend(self._render_markdown(report_md, s))
        else:
            story.append(Paragraph("No detailed report available.", s['ESOBody']))

        # -- Scan metadata --
        story.append(Spacer(1, 20))
        story.append(HRFlowable(width="100%", thickness=1, color=grey, spaceAfter=8))
        meta_lines = [
            f"Process ID: {data.get('process_id', 'N/A')}",
            f"Total Tasks: {data.get('total_tasks', 0)} ({data.get('dynamic_tasks', 0)} AI-proposed)",
            f"Findings: {data.get('findings_count', 0)}",
            f"LLM Calls: {data.get('llm_calls', 0)}",
        ]
        for line in meta_lines:
            story.append(Paragraph(line, s['SmallText']))

        return story

    # ------------------------------------------------------------------ #
    # Markdown → PDF flowables
    # ------------------------------------------------------------------ #
    def _render_markdown(self, md: str, s) -> list:
        """Convert markdown report text into reportlab flowables."""
        elements = []
        lines = md.split('\n')
        i = 0
        table_rows = []
        in_table = False

        while i < len(lines):
            line = lines[i].strip()

            # Skip the top-level title (already rendered)
            if line.startswith('# ') and 'Penetration Test Report' in line:
                i += 1
                continue

            # Section heading
            if line.startswith('## '):
                if in_table:
                    elements.extend(self._flush_table(table_rows, s))
                    table_rows, in_table = [], False
                elements.append(Paragraph(line[3:], s['SectionHeading']))
                i += 1
                continue

            # Sub-heading
            if line.startswith('### '):
                elements.append(Paragraph(line[4:], s['SubHeading']))
                i += 1
                continue

            # Table row
            if '|' in line and not line.startswith('#'):
                cells = [c.strip() for c in line.split('|') if c.strip()]
                if cells and not all(set(c) <= {'-', ' ', '|'} for c in cells):
                    table_rows.append(cells)
                    in_table = True
                i += 1
                continue

            # Numbered list
            if re.match(r'^\d+\.', line):
                if in_table:
                    elements.extend(self._flush_table(table_rows, s))
                    table_rows, in_table = [], False
                text = re.sub(r'^\d+\.\s*', '', line)
                elements.append(Paragraph(f"• {text}", s['FindingText']))
                i += 1
                continue

            # Bullet
            if line.startswith('- '):
                if in_table:
                    elements.extend(self._flush_table(table_rows, s))
                    table_rows, in_table = [], False
                elements.append(Paragraph(f"• {line[2:]}", s['FindingText']))
                i += 1
                continue

            # Regular paragraph
            if line:
                if in_table:
                    elements.extend(self._flush_table(table_rows, s))
                    table_rows, in_table = [], False
                # Bold markers
                text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', line)
                elements.append(Paragraph(text, s['ESOBody']))

            i += 1

        if in_table:
            elements.extend(self._flush_table(table_rows, s))

        return elements

    def _flush_table(self, rows, s) -> list:
        if not rows:
            return []
        # Normalize column count
        max_cols = max(len(r) for r in rows)
        norm = [r + [''] * (max_cols - len(r)) for r in rows]

        col_width = min(480 // max_cols, 120)
        t = Table(norm, colWidths=[col_width] * max_cols)
        style = [
            ('BACKGROUND', (0, 0), (-1, 0), PRIMARY),
            ('TEXTCOLOR', (0, 0), (-1, 0), white),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 0.5, grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]
        # Alternate row shading
        for idx in range(1, len(norm)):
            if idx % 2 == 0:
                style.append(('BACKGROUND', (0, idx), (-1, idx), BG_LIGHT))
        t.setStyle(TableStyle(style))
        return [t, Spacer(1, 8)]

    # ------------------------------------------------------------------ #
    # Header / footer
    # ------------------------------------------------------------------ #
    @staticmethod
    def _header_footer(canvas, doc):
        canvas.saveState()
        # Footer
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(grey)
        canvas.drawString(
            doc.leftMargin, 12 * mm,
            f"Enterprise Security Orchestrator — Generated {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}"
        )
        canvas.drawRightString(
            A4[0] - doc.rightMargin, 12 * mm,
            f"Page {canvas.getPageNumber()}"
        )
        canvas.restoreState()


# Singleton
pdf_generator = PDFReportGenerator()
