"""
ITTC-AI PDF Generator Service — creates professional, publication-quality SOC reports.

Supports:
  1. Individual Security Alert & Incident Triage Dossiers
  2. SOC Aggregate Threat Intelligence & Executive Summary Reports

Uses ReportLab with custom NumberedCanvas for dynamic "Page X of Y" numbering,
running headers and footers, sanitized typography, responsive tables,
and cybersecurity visual hierarchy.
"""

from __future__ import annotations

import io
import re
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# ==============================================================================
# 1. COLOR PALETTE & DESIGN TOKENS
# ==============================================================================

COLOR_PRIMARY_NAVY = HexColor("#0f172a")      # Slate 900
COLOR_SECONDARY_NAVY = HexColor("#1e293b")    # Slate 800
COLOR_ACCENT_BLUE = HexColor("#2563eb")       # Blue 600
COLOR_ACCENT_CYAN = HexColor("#0891b2")       # Cyan 600
COLOR_BORDER = HexColor("#cbd5e1")            # Slate 300
COLOR_BORDER_LIGHT = HexColor("#e2e8f0")      # Slate 200
COLOR_TEXT_DARK = HexColor("#0f172a")         # Slate 900
COLOR_TEXT_MUTED = HexColor("#475569")        # Slate 600
COLOR_TEXT_LIGHT = HexColor("#ffffff")        # White
COLOR_BG_CARD = HexColor("#f8fafc")           # Slate 50
COLOR_BG_ZEBRA = HexColor("#f1f5f9")          # Slate 100

# Severity Colors
COLOR_SEV_CRITICAL_BG = HexColor("#fee2e2")
COLOR_SEV_CRITICAL_TEXT = HexColor("#991b1b")
COLOR_SEV_HIGH_BG = HexColor("#ffedd5")
COLOR_SEV_HIGH_TEXT = HexColor("#9a3412")
COLOR_SEV_MEDIUM_BG = HexColor("#fef3c7")
COLOR_SEV_MEDIUM_TEXT = HexColor("#92400e")
COLOR_SEV_LOW_BG = HexColor("#dbeafe")
COLOR_SEV_LOW_TEXT = HexColor("#1e40af")


# ==============================================================================
# 2. STRING SANITIZATION FOR REPORTLAB
# ==============================================================================

def sanitize_text(val: Any) -> str:
    """
    Sanitize untrusted text for safe inclusion in ReportLab Paragraphs.
    Strips non-Latin-1 characters (including emojis) to prevent Type 1 font encoding errors,
    replaces common unicode punctuation, and escapes XML characters.
    """
    if val is None:
        return ""
    text = str(val)
    # Common typographic substitutions
    text = text.replace("\u2014", "--").replace("\u2013", "-")
    text = text.replace("\u2018", "'").replace("\u2019", "'")
    text = text.replace("\u201c", '"').replace("\u201d", '"')
    text = text.replace("\u2022", "*").replace("\u2026", "...")
    # Filter to latin-1 to avoid font encoder failure with Type 1 core fonts
    clean = text.encode("latin-1", errors="replace").decode("latin-1")
    return escape(clean)


def redact_sensitive(text: str) -> str:
    """Mask credentials, passwords, tokens, and API keys before report inclusion."""
    if not text:
        return ""
    redacted = re.sub(
        r"(?i)(password|passwd|secret|api_key|token|access_token|auth_token)\s*[:=]\s*['\"]?([^\s'\"&]+)['\"]?",
        r"\1=***REDACTED***",
        text,
    )
    redacted = re.sub(
        r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}",
        "Bearer ***REDACTED***",
        redacted,
    )
    return redacted


# ==============================================================================
# 3. NUMBERED CANVAS (PAGE X OF Y & RUNNING HEADERS/FOOTERS)
# ==============================================================================

class NumberedCanvas(canvas.Canvas):
    """
    Two-pass canvas that computes total pages dynamically and stamps
    running headers (on pages > 1) and running footers (on all pages).
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self._saved_page_states: List[Dict[str, Any]] = []

    def showPage(self) -> None:
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count: int) -> None:
        self.saveState()
        self.setFont("Helvetica", 7.5)
        self.setFillColor(HexColor("#64748b"))

        # Running Header (pages > 1)
        if self._pageNumber > 1:
            self.drawString(36, 762, "ITTC-AI Security Operations Center | Incident Intelligence Report")
            self.setStrokeColor(HexColor("#cbd5e1"))
            self.setLineWidth(0.5)
            self.line(36, 756, 576, 756)

        # Running Footer (all pages)
        self.setStrokeColor(HexColor("#cbd5e1"))
        self.setLineWidth(0.5)
        self.line(36, 42, 576, 42)

        self.drawString(36, 30, "CONFIDENTIAL -- FOR INTERNAL SOC & AUTHORIZED AUDIT USE ONLY")
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(576, 30, page_str)
        self.restoreState()


# ==============================================================================
# 4. TYPOGRAPHY & STYLESHEET
# ==============================================================================

def get_report_styles() -> Dict[str, ParagraphStyle]:
    """Create typography hierarchy for report generation."""
    styles = getSampleStyleSheet()

    custom_styles = {
        "BannerTitle": ParagraphStyle(
            "BannerTitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=16,
            leading=20,
            textColor=COLOR_TEXT_LIGHT,
        ),
        "BannerSubtitle": ParagraphStyle(
            "BannerSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            leading=13,
            textColor=HexColor("#93c5fd"),
        ),
        "BannerMeta": ParagraphStyle(
            "BannerMeta",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10.5,
            textColor=HexColor("#cbd5e1"),
        ),
        "SectionHeading": ParagraphStyle(
            "SectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=HexColor("#1e3a8a"),
            spaceBefore=12,
            spaceAfter=4,
        ),
        "SubSectionHeading": ParagraphStyle(
            "SubSectionHeading",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            leading=12,
            textColor=HexColor("#0f172a"),
            spaceBefore=6,
            spaceAfter=3,
        ),
        "Body": ParagraphStyle(
            "ReportBody",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11.5,
            textColor=HexColor("#334155"),
        ),
        "BodyBold": ParagraphStyle(
            "BodyBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=11.5,
            textColor=COLOR_TEXT_DARK,
        ),
        "TableHeader": ParagraphStyle(
            "ReportTableHeader",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            leading=10.5,
            textColor=COLOR_TEXT_LIGHT,
        ),
        "TableCell": ParagraphStyle(
            "ReportTableCell",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10.5,
            textColor=HexColor("#334155"),
        ),
        "TableCellBold": ParagraphStyle(
            "TableCellBold",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=10.5,
            textColor=COLOR_TEXT_DARK,
        ),
        "TableCellMono": ParagraphStyle(
            "TableCellMono",
            parent=styles["Normal"],
            fontName="Courier",
            fontSize=7,
            leading=9,
            textColor=HexColor("#0f172a"),
        ),
        "BadgeText": ParagraphStyle(
            "BadgeText",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=7.5,
            leading=9,
            alignment=1,  # Center
        ),
        "CalloutText": ParagraphStyle(
            "CalloutText",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            leading=11.5,
            textColor=HexColor("#1e293b"),
        ),
        "Disclaimer": ParagraphStyle(
            "ReportDisclaimer",
            parent=styles["Normal"],
            fontName="Helvetica-Oblique",
            fontSize=7.5,
            leading=10.5,
            textColor=HexColor("#64748b"),
        ),
    }

    return custom_styles


# ==============================================================================
# 5. UI COMPONENT HELPERS
# ==============================================================================

def create_banner(
    title: str,
    subtitle: str,
    meta_lines: List[str],
    styles: Dict[str, ParagraphStyle],
) -> Table:
    """Create a dark executive header banner block."""
    meta_html = "<br/>".join(meta_lines)
    content = [
        [
            Paragraph(f"<b>ITTC-AI</b> | {sanitize_text(title)}", styles["BannerTitle"]),
            Paragraph(meta_html, styles["BannerMeta"]),
        ],
        [
            Paragraph(sanitize_text(subtitle), styles["BannerSubtitle"]),
            Paragraph("", styles["BannerMeta"]),
        ],
    ]

    t = Table(content, colWidths=[360, 180])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_PRIMARY_NAVY),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("ALIGN", (1, 0), (1, -1), "RIGHT"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ])
    )
    return t


def create_section_header(title: str, styles: Dict[str, ParagraphStyle]) -> List[Any]:
    """Create a structured section header with an accent rule."""
    p = Paragraph(f"<b>{sanitize_text(title)}</b>", styles["SectionHeading"])
    hr = HRFlowable(width="100%", thickness=0.75, color=COLOR_ACCENT_BLUE, spaceBefore=2, spaceAfter=6)
    return [p, hr]


def create_callout_box(
    text: str,
    styles: Dict[str, ParagraphStyle],
    bg_color: colors.Color = COLOR_BG_CARD,
    border_color: colors.Color = COLOR_BORDER,
    is_disclaimer: bool = False,
) -> Table:
    """Create a clean bordered callout card."""
    style = styles["Disclaimer"] if is_disclaimer else styles["CalloutText"]
    p = Paragraph(sanitize_text(text), style)
    t = Table([[p]], colWidths=[540])
    t.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), bg_color),
            ("BOX", (0, 0), (-1, -1), 0.75, border_color),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ])
    )
    return t


def get_severity_badge_style(sev: str) -> tuple[colors.Color, colors.Color]:
    """Return background and text color for severity level."""
    s = str(sev).lower().strip()
    if s == "critical":
        return COLOR_SEV_CRITICAL_BG, COLOR_SEV_CRITICAL_TEXT
    if s == "high":
        return COLOR_SEV_HIGH_BG, COLOR_SEV_HIGH_TEXT
    if s == "medium":
        return COLOR_SEV_MEDIUM_BG, COLOR_SEV_MEDIUM_TEXT
    return COLOR_SEV_LOW_BG, COLOR_SEV_LOW_TEXT


# ==============================================================================
# 6. FEATURE ONE: INDIVIDUAL ALERT / INCIDENT REPORT BUILDER
# ==============================================================================

def build_alert_pdf(report: Dict[str, Any]) -> bytes:
    """
    Build a multi-page, production-grade PDF for an Individual Alert / Incident Report.
    Adheres strictly to Sections A through J requirements.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=48,
        bottomMargin=48,
    )

    styles = get_report_styles()
    story: List[Any] = []

    # ---------------------------------------------------------
    # A. Report Identification & Cover Header
    # ---------------------------------------------------------
    meta = [
        f"<b>Report ID:</b> {sanitize_text(report.get('report_id', 'N/A'))}",
        f"<b>Generated:</b> {sanitize_text(report.get('generated_at', ''))[:19].replace('T', ' ')} UTC",
        f"<b>Classification:</b> TLP:AMBER | {sanitize_text(report.get('report_status', 'FINAL'))}",
    ]
    banner = create_banner(
        title="SECURITY ALERT TRIAGE & INCIDENT DOSSIER",
        subtitle=f"Alert Reference: {report.get('alert_id', 'UNKNOWN')} -- Endpoint: {report.get('alert_details', {}).get('host', 'N/A')}",
        meta_lines=meta,
        styles=styles,
    )
    story.append(banner)
    story.append(Spacer(1, 10))

    # Identification summary table
    inc_id = report.get("incident_id") or "None (Standalone / Uncorrelated Alert)"
    id_table_data = [
        [
            Paragraph("<b>Target Alert ID:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(report.get("alert_id", "")), styles["TableCellMono"]),
            Paragraph("<b>Correlated Incident:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(inc_id), styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Detection Source:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(report.get("alert_details", {}).get("source", "").upper()), styles["TableCell"]),
            Paragraph("<b>Reporting Timezone:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(report.get("reporting_timezone", "UTC")), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Incident Status:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(report.get("incident_status", "OPEN")), styles["TableCell"]),
            Paragraph("<b>Assessment Status:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(report.get("report_status", "FINAL / VERIFIED")), styles["TableCell"]),
        ],
    ]
    id_table = Table(id_table_data, colWidths=[110, 160, 120, 150])
    id_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(id_table)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # B. Executive Summary
    # ---------------------------------------------------------
    story.extend(create_section_header("B. EXECUTIVE SUMMARY", styles))
    exec_sum = report.get("executive_summary", {})
    story.append(Paragraph(f"<b>Detection Overview:</b> {sanitize_text(exec_sum.get('detection_overview', ''))}", styles["Body"]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<b>Security Significance:</b> {sanitize_text(exec_sum.get('security_significance', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))

    # Established Facts vs Uncertainties Table
    facts = exec_sum.get("established_facts", [])
    uncertainties = exec_sum.get("uncertainties", [])

    facts_p = [Paragraph(f"&bull; {sanitize_text(f)}", styles["TableCell"]) for f in facts] or [Paragraph("None specified", styles["TableCell"])]
    uncert_p = [Paragraph(f"&bull; {sanitize_text(u)}", styles["TableCell"]) for u in uncertainties] or [Paragraph("None specified", styles["TableCell"])]

    exec_grid = [
        [Paragraph("<b>Available Evidence Establishes:</b>", styles["TableCellBold"]), Paragraph("<b>Key Uncertainties & Telemetry Gaps:</b>", styles["TableCellBold"])],
        [facts_p, uncert_p],
    ]
    t_exec = Table(exec_grid, colWidths=[270, 270])
    t_exec.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_BG_ZEBRA),
            ("BACKGROUND", (0, 1), (-1, 1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(t_exec)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # C. Alert Details
    # ---------------------------------------------------------
    story.extend(create_section_header("C. ALERT DETAILS & TELEMETRY ATTRIBUTES", styles))
    details = report.get("alert_details", {})
    details_data = [
        [
            Paragraph("<b>Event Timestamp:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("timestamp", ""))[:19].replace("T", " "), styles["TableCell"]),
            Paragraph("<b>Detection Source:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("source", "").upper()), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Target Host / Asset:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("host", "N/A")), styles["TableCellBold"]),
            Paragraph("<b>Associated User:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("user", "Not recorded / System")), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Source IP Address:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("src_ip", "N/A")), styles["TableCellMono"]),
            Paragraph("<b>Destination IP:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("dst_ip", "N/A")), styles["TableCellMono"]),
        ],
        [
            Paragraph("<b>Event Category:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("event_type", "security_alert")), styles["TableCell"]),
            Paragraph("<b>Rule Identifier:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("rule_id", "N/A")), styles["TableCellMono"]),
        ],
        [
            Paragraph("<b>Event Description:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("event_summary", "")), styles["TableCell"]),
            Paragraph("<b>Source Severity:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(details.get("source_severity", "").upper()), styles["TableCellBold"]),
        ],
    ]
    t_details = Table(details_data, colWidths=[110, 160, 110, 160])
    t_details.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("SPAN", (1, 4), (1, 4)),  # Keep layout clean
        ])
    )
    story.append(t_details)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # D. Severity and Risk Assessment
    # ---------------------------------------------------------
    story.extend(create_section_header("D. SEVERITY & EXPLAINABLE RISK ASSESSMENT", styles))
    sev_risk = report.get("severity_and_risk", {})
    score = sev_risk.get("ittc_risk_score", 50)
    conf = sev_risk.get("confidence_score", 0.5)
    priority = sev_risk.get("investigation_priority", "P2 - High Priority")

    sev_bg, sev_text_color = get_severity_badge_style(sev_risk.get("ittc_severity", "medium"))

    sev_summary_data = [
        [
            Paragraph("<b>Original Source Severity:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sanitize_text(sev_risk.get('source_severity', '').upper())}</b>", styles["TableCellBold"]),
            Paragraph("<b>ITTC Composite Risk Score:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{score} / 100</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>ITTC Severity Classification:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sanitize_text(sev_risk.get('ittc_severity', '').upper())}</b>", styles["TableCellBold"]),
            Paragraph("<b>Investigation Priority:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sanitize_text(priority)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Confidence Score:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{int(conf * 100)}%</b>", styles["TableCellBold"]),
            Paragraph("<b>Assessment Basis:</b>", styles["TableCellBold"]),
            Paragraph("Deterministic ML + Telemetry", styles["TableCell"]),
        ],
    ]
    t_sev = Table(sev_summary_data, colWidths=[140, 130, 140, 130])
    t_sev.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_sev)
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<i>Confidence note: {sanitize_text(sev_risk.get('confidence_explanation', ''))}</i>", styles["Disclaimer"]))
    story.append(Spacer(1, 5))

    # Explainable Risk Factors Table
    factors = sev_risk.get("assessment_factors", [])
    if factors:
        factor_rows = [
            [
                Paragraph("<b>Contributing Factor</b>", styles["TableHeader"]),
                Paragraph("<b>Impact Score</b>", styles["TableHeader"]),
                Paragraph("<b>Telemetry Evidence</b>", styles["TableHeader"]),
            ]
        ]
        for f in factors:
            factor_rows.append([
                Paragraph(sanitize_text(f.get("factor", "")), styles["TableCellBold"]),
                Paragraph(f"+{sanitize_text(f.get('impact', 0))}", styles["TableCellMono"]),
                Paragraph(sanitize_text(f.get("evidence", "")), styles["TableCell"]),
            ])
        t_factors = Table(factor_rows, colWidths=[150, 70, 320])
        t_factors.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_factors)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # E. Impact and Damage Assessment
    # ---------------------------------------------------------
    story.extend(create_section_header("E. IMPACT & DAMAGE ASSESSMENT", styles))
    impact = report.get("impact_assessment", {})
    impact_data = [
        [
            Paragraph("<b>Confirmed Observations:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text("; ".join(impact.get("confirmed_observations", [])) or "Activity recorded in security telemetry"), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Observed Impact:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(impact.get("observed_impact", "None observed")), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Potential Impact:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(impact.get("potential_impact", "Lateral movement, persistent access, credential theft")), styles["TableCell"]),
        ],
        [
            Paragraph("<b>Affected Assets:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(", ".join(impact.get("affected_assets", [])) or "Endpoint host"), styles["TableCell"]),
        ],
        [
            Paragraph("<b>C / I / A Implications:</b>", styles["TableCellBold"]),
            Paragraph(
                f"<b>Confidentiality:</b> {sanitize_text(impact.get('confidentiality_impact', 'Unknown'))}<br/>"
                f"<b>Integrity:</b> {sanitize_text(impact.get('integrity_impact', 'Unknown'))}<br/>"
                f"<b>Availability:</b> {sanitize_text(impact.get('availability_impact', 'Unknown'))}",
                styles["TableCell"],
            ),
        ],
    ]
    t_impact = Table(impact_data, colWidths=[150, 390])
    t_impact.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(t_impact)
    story.append(Spacer(1, 4))

    # Mandatory disclaimer from requirements
    disclaimer_text = impact.get("damage_disclaimer") or "Actual damage could not be established from the available evidence."
    story.append(create_callout_box(disclaimer_text, styles, bg_color=HexColor("#fef2f2"), border_color=HexColor("#fca5a5"), is_disclaimer=True))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # F. Supporting Evidence
    # ---------------------------------------------------------
    story.extend(create_section_header("F. SUPPORTING EVIDENCE & TELEMETRY EXCERPTS", styles))
    evidence = report.get("supporting_evidence", {})

    log_excerpt = redact_sensitive(evidence.get("log_excerpt", ""))
    story.append(Paragraph("<b>Primary Log Excerpt:</b>", styles["SubSectionHeading"]))
    story.append(create_callout_box(log_excerpt[:450] if log_excerpt else "No raw log excerpt attached", styles, bg_color=COLOR_BG_ZEBRA))
    story.append(Spacer(1, 5))

    # Extracted IOCs Table
    iocs = evidence.get("iocs", [])
    if iocs:
        ioc_rows = [
            [
                Paragraph("<b>IOC Type</b>", styles["TableHeader"]),
                Paragraph("<b>Indicator Value</b>", styles["TableHeader"]),
                Paragraph("<b>Reputation / Threat Intel</b>", styles["TableHeader"]),
            ]
        ]
        for ioc in iocs:
            rep = (ioc.get("reputation") or "Unknown").capitalize()
            source = ioc.get("source", "")
            status = ioc.get("provider_status", "")
            mal_count = ioc.get("malicious_count")
            total_eng = ioc.get("total_engines")

            ti_desc = rep
            if mal_count is not None and total_eng:
                ti_desc += f" ({mal_count}/{total_eng} engines)"
            elif ioc.get("detections") is not None:
                ti_desc += f" ({ioc.get('detections')} detections)"

            if "virustotal" in source.lower() and status == "available":
                ti_desc += " [VT Live]"
            elif status == "fallback" or "mock" in source.lower() or "synthetic" in source.lower():
                ti_desc += " [Fallback/Offline]"
            elif status == "unavailable":
                ti_desc += " [TI Unavailable]"

            ioc_rows.append([
                Paragraph(sanitize_text(ioc.get("type", "").upper()), styles["TableCellBold"]),
                Paragraph(sanitize_text(ioc.get("value", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(ti_desc), styles["TableCell"]),
            ])
        t_iocs = Table(ioc_rows, colWidths=[90, 250, 200])
        t_iocs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_iocs)
        story.append(Spacer(1, 6))

    # Related alerts in incident if any
    related_alerts = evidence.get("related_alerts", [])
    if related_alerts:
        story.append(Paragraph(f"<b>Correlated Cluster Alerts ({len(related_alerts)} related):</b>", styles["SubSectionHeading"]))
        rel_rows = [
            [
                Paragraph("<b>Alert ID</b>", styles["TableHeader"]),
                Paragraph("<b>Timestamp</b>", styles["TableHeader"]),
                Paragraph("<b>Source</b>", styles["TableHeader"]),
                Paragraph("<b>Event Summary</b>", styles["TableHeader"]),
            ]
        ]
        for ra in related_alerts[:5]:
            rel_rows.append([
                Paragraph(sanitize_text(ra.get("alert_id", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(ra.get("timestamp", ""))[:16].replace("T", " "), styles["TableCell"]),
                Paragraph(sanitize_text(ra.get("source", "").upper()), styles["TableCellBold"]),
                Paragraph(sanitize_text(ra.get("event", ""))[:120], styles["TableCell"]),
            ])
        t_rel = Table(rel_rows, colWidths=[80, 100, 60, 300])
        t_rel.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_rel)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # G. Attack and Root-Cause Analysis
    # ---------------------------------------------------------
    story.extend(create_section_header("G. ATTACK SEQUENCE & ROOT-CAUSE ANALYSIS", styles))
    attack = report.get("attack_analysis", {})

    story.append(Paragraph(f"<b>Investigative Hypothesis:</b> {sanitize_text(' '.join(attack.get('plausible_explanations', [])))}", styles["Body"]))
    story.append(Spacer(1, 4))

    attack_table_data = [
        [
            Paragraph("<b>Confirmed Findings:</b>", styles["TableCellBold"]),
            Paragraph("; ".join([sanitize_text(f) for f in attack.get("confirmed_findings", [])]) or "Observed alert signature", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Missing Information:</b>", styles["TableCellBold"]),
            Paragraph("; ".join([sanitize_text(m) for m in attack.get("missing_information", [])]) or "Parent process hierarchy, memory dump", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Additional Investigation:</b>", styles["TableCellBold"]),
            Paragraph("; ".join([sanitize_text(a) for a in attack.get("additional_investigation_required", [])]) or "Review Sysmon and authentication logs", styles["TableCell"]),
        ],
        [
            Paragraph("<b>Root Cause Status:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(attack.get("root_cause_status", "Unknown")), styles["TableCellBold"]),
        ],
    ]
    t_attack = Table(attack_table_data, colWidths=[150, 390])
    t_attack.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ])
    )
    story.append(t_attack)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # H. Remediation Recommendations
    # ---------------------------------------------------------
    story.extend(create_section_header("H. PRIORITIZED REMEDIATION RECOMMENDATIONS", styles))
    story.append(Paragraph("<i>Note: Recommendations must be approved by an authorized analyst prior to execution.</i>", styles["Disclaimer"]))
    story.append(Spacer(1, 4))

    recs = report.get("remediation_recommendations", [])
    if recs:
        rec_rows = [
            [
                Paragraph("<b>Priority</b>", styles["TableHeader"]),
                Paragraph("<b>Action</b>", styles["TableHeader"]),
                Paragraph("<b>Rationale & Evidence</b>", styles["TableHeader"]),
                Paragraph("<b>Expected Outcome & Caution</b>", styles["TableHeader"]),
            ]
        ]
        for r in recs:
            rec_rows.append([
                Paragraph(sanitize_text(r.get("priority", "P2")), styles["TableCellBold"]),
                Paragraph(sanitize_text(r.get("action", "")), styles["TableCellBold"]),
                Paragraph(
                    f"<b>Reason:</b> {sanitize_text(r.get('reason', ''))}<br/>"
                    f"<b>Evidence:</b> {sanitize_text(r.get('justification', ''))}",
                    styles["TableCell"],
                ),
                Paragraph(
                    f"<b>Outcome:</b> {sanitize_text(r.get('expected_outcome', ''))}<br/>"
                    f"<b>Caution:</b> {sanitize_text(r.get('caution', 'None'))}",
                    styles["TableCell"],
                ),
            ])
        t_recs = Table(rec_rows, colWidths=[65, 125, 180, 170])
        t_recs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(t_recs)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # I. Prevention Measures
    # ---------------------------------------------------------
    story.extend(create_section_header("I. DEFENSIVE PREVENTION & DETECTION IMPROVEMENTS", styles))
    prev_measures = report.get("prevention_measures", [])
    for pm in prev_measures:
        story.append(Paragraph(f"&bull; {sanitize_text(pm)}", styles["Body"]))
        story.append(Spacer(1, 2))
    story.append(Spacer(1, 8))

    # ---------------------------------------------------------
    # J. Analyst Conclusion
    # ---------------------------------------------------------
    story.extend(create_section_header("J. ANALYST CONCLUSION & INVESTIGATION STATUS", styles))
    conclusion = report.get("analyst_conclusion", {})

    story.append(Paragraph(f"<b>Overall Assessment:</b> {sanitize_text(conclusion.get('overall_assessment', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Outstanding Uncertainties:</b> {sanitize_text(conclusion.get('outstanding_uncertainties', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))

    next_steps = conclusion.get("recommended_next_steps", [])
    if next_steps:
        story.append(Paragraph("<b>Recommended Next Investigation Steps:</b>", styles["SubSectionHeading"]))
        for ns in next_steps:
            story.append(Paragraph(f"  [ ] {sanitize_text(ns)}", styles["Body"]))
            story.append(Spacer(1, 1.5))
        story.append(Spacer(1, 4))

    # Resolution disclaimer (mandatory)
    res_disclaimer = conclusion.get("resolution_disclaimer") or (
        "The generation of this assessment does not automatically resolve or close the incident. "
        "The incident remains under active operational review until explicitly resolved by an analyst."
    )
    story.append(create_callout_box(res_disclaimer, styles, bg_color=HexColor("#eff6ff"), border_color=HexColor("#bfdbfe"), is_disclaimer=True))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ==============================================================================
# 7. FEATURE TWO: AGGREGATE SOC SECURITY REPORT BUILDER
# ==============================================================================

def build_soc_pdf(report: Dict[str, Any]) -> bytes:
    """
    Build a multi-page, executive-ready PDF for the Aggregate SOC Security Report.
    Adheres strictly to Sections A through K requirements.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=48,
        bottomMargin=48,
    )

    styles = get_report_styles()
    story: List[Any] = []

    # ---------------------------------------------------------
    # A. Report Cover & Metadata
    # ---------------------------------------------------------
    period_str = report.get("reporting_period", {}).get("display", "Custom Reporting Interval")
    meta = [
        f"<b>Report ID:</b> {sanitize_text(report.get('report_id', 'N/A'))}",
        f"<b>Generated:</b> {sanitize_text(report.get('generated_at', ''))[:19].replace('T', ' ')} UTC",
        "<b>Classification:</b> TLP:AMBER | SOC EXECUTIVE",
    ]
    banner = create_banner(
        title="SOC AGGREGATE SECURITY INTELLIGENCE REPORT",
        subtitle=f"Reporting Window: {period_str}",
        meta_lines=meta,
        styles=styles,
    )
    story.append(banner)
    story.append(Spacer(1, 10))

    # Metadata Summary Bar
    start_ts = report.get("reporting_period", {}).get("start_time", "")
    end_ts = report.get("reporting_period", {}).get("end_time", "")
    meta_bar = [
        [
            Paragraph("<b>Reporting Interval:</b>", styles["TableCellBold"]),
            Paragraph(f"{sanitize_text(start_ts)[:19].replace('T', ' ')} to {sanitize_text(end_ts)[:19].replace('T', ' ')} UTC", styles["TableCell"]),
            Paragraph("<b>Telemetry Scope:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(", ".join(report.get("data_sources_included", ["Wazuh", "Suricata"]))), styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Total Alerts Scanned:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{report.get('security_statistics', {}).get('total_alerts', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>Correlated Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{report.get('security_statistics', {}).get('active_incidents', 0)}</b>", styles["TableCellBold"]),
        ],
    ]
    t_meta = Table(meta_bar, colWidths=[120, 180, 110, 130])
    t_meta.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_meta)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # B. Executive Summary
    # ---------------------------------------------------------
    story.extend(create_section_header("B. EXECUTIVE SUMMARY", styles))
    exec_text = report.get("executive_summary", "")
    story.append(Paragraph(sanitize_text(exec_text), styles["Body"]))
    story.append(Spacer(1, 5))

    # Zero-alert reminder callout
    total_alerts = report.get("security_statistics", {}).get("total_alerts", 0)
    if total_alerts == 0:
        story.append(create_callout_box(
            "Note: Zero alerts were recorded in the active telemetry store during this interval. "
            "The absence of logged alerts indicates no detection rule triggers occurred within the queried period, "
            "but does not definitively prove absence of malicious activity or threat actor presence. "
            "Continuous verification of sensor health and log ingestion pipelines is advised.",
            styles,
            bg_color=HexColor("#fef2f2"),
            border_color=HexColor("#fca5a5"),
            is_disclaimer=True,
        ))
        story.append(Spacer(1, 8))

    # ---------------------------------------------------------
    # C. Monitoring and Data Coverage
    # ---------------------------------------------------------
    story.extend(create_section_header("C. MONITORING & TELEMETRY DATA COVERAGE", styles))
    coverage = report.get("monitoring_coverage", [])
    cov_rows = [
        [
            Paragraph("<b>Telemetry Source</b>", styles["TableHeader"]),
            Paragraph("<b>Coverage Type</b>", styles["TableHeader"]),
            Paragraph("<b>Query Status</b>", styles["TableHeader"]),
            Paragraph("<b>Records In Period</b>", styles["TableHeader"]),
            Paragraph("<b>Operational Status Notes</b>", styles["TableHeader"]),
        ]
    ]
    for c in coverage:
        cov_rows.append([
            Paragraph(sanitize_text(c.get("source", "")), styles["TableCellBold"]),
            Paragraph(sanitize_text(c.get("type", "")), styles["TableCell"]),
            Paragraph(sanitize_text(c.get("status", "")), styles["TableCellBold"]),
            Paragraph(str(c.get("records_count", 0)), styles["TableCellMono"]),
            Paragraph(sanitize_text(c.get("notes", "")), styles["TableCell"]),
        ])
    t_cov = Table(cov_rows, colWidths=[120, 90, 85, 75, 170])
    t_cov.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_cov)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # D. Security Statistics
    # ---------------------------------------------------------
    story.extend(create_section_header("D. SECURITY STATISTICS & TELEMETRY METRICS", styles))
    stats = report.get("security_statistics", {})
    sev_counts = stats.get("severity_counts", {})
    source_counts = stats.get("source_counts", {})
    status_counts = stats.get("incident_status_counts", {})

    stats_grid = [
        [
            Paragraph("<b>Total Normalized Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{stats.get('total_alerts', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>Critical Severity Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('critical', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Correlated Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{stats.get('active_incidents', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>High Severity Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('high', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Distinct Affected Hosts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{stats.get('distinct_hosts_count', 0)}</b> ({sanitize_text(', '.join(stats.get('affected_hosts', [])[:3]))})", styles["TableCell"]),
            Paragraph("<b>Medium Severity Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('medium', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>ML Anomalies Flagged:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{stats.get('anomalies_count', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>Low Severity Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('low', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Telemetry Source Split:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(", ".join(f"{k.upper()}: {v}" for k, v in source_counts.items()) or "None"), styles["TableCell"]),
            Paragraph("<b>Incident Statuses:</b>", styles["TableCellBold"]),
            Paragraph(sanitize_text(", ".join(f"{k}: {v}" for k, v in status_counts.items()) or "None"), styles["TableCell"]),
        ],
    ]
    t_stats = Table(stats_grid, colWidths=[140, 130, 140, 130])
    t_stats.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 5),
            ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ])
    )
    story.append(t_stats)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # E. Critical and High-Priority Findings
    # ---------------------------------------------------------
    story.extend(create_section_header("E. CRITICAL & HIGH-PRIORITY SECURITY FINDINGS", styles))
    findings = report.get("critical_high_findings", [])
    if findings:
        find_rows = [
            [
                Paragraph("<b>Alert / Ref</b>", styles["TableHeader"]),
                Paragraph("<b>Timestamp</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeader"]),
                Paragraph("<b>Host & Event Summary</b>", styles["TableHeader"]),
                Paragraph("<b>MITRE ATT&CK</b>", styles["TableHeader"]),
            ]
        ]
        for f in findings:
            find_rows.append([
                Paragraph(sanitize_text(f.get("alert_id", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(f.get("timestamp", ""))[:16].replace("T", " "), styles["TableCell"]),
                Paragraph(sanitize_text(f.get("severity", "").upper()), styles["TableCellBold"]),
                Paragraph(
                    f"<b>{sanitize_text(f.get('host', ''))}</b> -- {sanitize_text(f.get('event', ''))[:140]}",
                    styles["TableCell"],
                ),
                Paragraph(sanitize_text(", ".join(f.get("mitre_techniques", [])) or "None"), styles["TableCellMono"]),
            ])
        t_find = Table(find_rows, colWidths=[70, 85, 60, 235, 90])
        t_find.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(t_find)
    else:
        story.append(Paragraph("No critical or high-severity events were detected during this reporting period.", styles["Body"]))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # F. Incident & Threat Analysis
    # ---------------------------------------------------------
    story.extend(create_section_header("F. INCIDENT & ATTACK SEQUENCE ANALYSIS", styles))
    threat_analysis = report.get("threat_analysis", {})

    story.append(Paragraph(f"<b>Correlated Threat Activity:</b> {sanitize_text(threat_analysis.get('correlated_patterns', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Observed IOC Associations:</b> {sanitize_text(threat_analysis.get('iocs_summary', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))
    story.append(Paragraph(f"<b>Attack Chain Synthesis:</b> {sanitize_text(threat_analysis.get('attack_chains', ''))}", styles["Body"]))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # G. Impact Assessment
    # ---------------------------------------------------------
    story.extend(create_section_header("G. OPERATIONAL & ASSET IMPACT ASSESSMENT", styles))
    impact = report.get("impact_assessment", {})
    story.append(Paragraph(f"<b>Observed Telemetry Impact:</b> {sanitize_text(impact.get('observed_impact', ''))}", styles["Body"]))
    story.append(Spacer(1, 3))
    story.append(Paragraph(f"<b>Potential Risk Scenarios:</b> {sanitize_text(impact.get('potential_consequences', ''))}", styles["Body"]))
    story.append(Spacer(1, 3))
    story.append(create_callout_box(
        impact.get("damage_disclaimer") or "Actual enterprise damage could not be established from the available telemetry alone.",
        styles,
        bg_color=COLOR_BG_CARD,
        border_color=COLOR_BORDER,
        is_disclaimer=True,
    ))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # H. Response & Investigation Status
    # ---------------------------------------------------------
    story.extend(create_section_header("H. RESPONSE & INVESTIGATION STATUS", styles))
    resp_status = report.get("response_status", {})
    story.append(Paragraph(f"<b>Active Incidents Overview:</b> {sanitize_text(resp_status.get('overview', ''))}", styles["Body"]))
    story.append(Spacer(1, 4))

    actions = resp_status.get("recorded_actions", [])
    if actions:
        story.append(Paragraph("<b>Recorded Active Response Containment Actions:</b>", styles["SubSectionHeading"]))
        act_rows = [
            [
                Paragraph("<b>Response ID</b>", styles["TableHeader"]),
                Paragraph("<b>Timestamp</b>", styles["TableHeader"]),
                Paragraph("<b>Action & Target</b>", styles["TableHeader"]),
                Paragraph("<b>Actor</b>", styles["TableHeader"]),
                Paragraph("<b>Execution Mode</b>", styles["TableHeader"]),
                Paragraph("<b>State</b>", styles["TableHeader"]),
            ]
        ]
        for act in actions:
            act_rows.append([
                Paragraph(sanitize_text(act.get("response_id", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(act.get("timestamp", ""))[:16].replace("T", " "), styles["TableCell"]),
                Paragraph(f"{sanitize_text(act.get('action', ''))} &rarr; {sanitize_text(act.get('target', ''))}", styles["TableCellBold"]),
                Paragraph(sanitize_text(act.get("actor", "analyst")), styles["TableCell"]),
                Paragraph(sanitize_text(act.get("mode", "simulated").upper()), styles["TableCellBold"]),
                Paragraph(sanitize_text(act.get("state", "COMPLETED")), styles["TableCellBold"]),
            ])
        t_act = Table(act_rows, colWidths=[80, 85, 155, 75, 75, 70])
        t_act.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_act)
    else:
        story.append(Paragraph("No Active Response containment actions were triggered or executed in this reporting period.", styles["Body"]))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # I. Recommended Actions
    # ---------------------------------------------------------
    story.extend(create_section_header("I. STRATEGIC & TACTICAL SOC RECOMMENDATIONS", styles))
    recs = report.get("recommended_actions", [])
    if recs:
        rec_rows = [
            [
                Paragraph("<b>Priority</b>", styles["TableHeader"]),
                Paragraph("<b>Recommended Action</b>", styles["TableHeader"]),
                Paragraph("<b>Rationale & Strategic Impact</b>", styles["TableHeader"]),
            ]
        ]
        for r in recs:
            rec_rows.append([
                Paragraph(sanitize_text(r.get("priority", "P2")), styles["TableCellBold"]),
                Paragraph(sanitize_text(r.get("action", "")), styles["TableCellBold"]),
                Paragraph(sanitize_text(r.get("reason", "")), styles["TableCell"]),
            ])
        t_soc_recs = Table(rec_rows, colWidths=[70, 180, 290])
        t_soc_recs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(t_soc_recs)
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # J. Trends
    # ---------------------------------------------------------
    story.extend(create_section_header("J. HISTORICAL TRENDS & PERIOD COMPARISON", styles))
    trends = report.get("trends", {})
    comp_note = trends.get("comparison_text") or "Historical comparison with prior period could not be calculated due to lack of baseline historical telemetry for that interval."
    story.append(create_callout_box(comp_note, styles, bg_color=COLOR_BG_CARD, border_color=COLOR_BORDER, is_disclaimer=False))
    story.append(Spacer(1, 10))

    # ---------------------------------------------------------
    # K. Appendix
    # ---------------------------------------------------------
    story.extend(create_section_header("K. APPENDIX -- RAW TELEMETRY REFERENCE REGISTER", styles))
    appendix = report.get("appendix", {})
    alert_list = appendix.get("alerts", [])
    if alert_list:
        app_rows = [
            [
                Paragraph("<b>Alert ID</b>", styles["TableHeader"]),
                Paragraph("<b>Timestamp</b>", styles["TableHeader"]),
                Paragraph("<b>Host</b>", styles["TableHeader"]),
                Paragraph("<b>Source</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeader"]),
                Paragraph("<b>Event Type</b>", styles["TableHeader"]),
            ]
        ]
        for a in alert_list[:15]:
            app_rows.append([
                Paragraph(sanitize_text(a.get("alert_id", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(a.get("timestamp", ""))[:16].replace("T", " "), styles["TableCell"]),
                Paragraph(sanitize_text(a.get("host", "")), styles["TableCell"]),
                Paragraph(sanitize_text(a.get("source", "").upper()), styles["TableCellBold"]),
                Paragraph(sanitize_text(a.get("severity", "").upper()), styles["TableCellBold"]),
                Paragraph(sanitize_text(a.get("event_type", "")), styles["TableCell"]),
            ])
        t_app = Table(app_rows, colWidths=[75, 95, 75, 60, 65, 170], repeatRows=1)
        t_app.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_app)
        if len(alert_list) > 15:
            story.append(Spacer(1, 3))
            story.append(Paragraph(f"<i>Showing first 15 of {len(alert_list)} total alerts in this reporting interval.</i>", styles["Disclaimer"]))
    else:
        story.append(Paragraph("No alerts in interval to display in register.", styles["Body"]))

    # Build document
    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ==============================================================================
# 8. FEATURE THREE: AGGREGATED DAILY SOC SUMMARY REPORT BUILDER
# ==============================================================================

def build_daily_summary_pdf(report: Dict[str, Any]) -> bytes:
    """
    Build a multi-page, executive-ready PDF for the Aggregated Daily SOC Summary Report.
    Summarizes all correlated incidents generated or active within the 24-hour cycle.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=48,
        bottomMargin=48,
    )

    styles = get_report_styles()
    story: List[Any] = []

    # 1. Header Banner
    period_str = report.get("reporting_period", {}).get("display", "24-Hour Monitoring Interval")
    meta = [
        f"<b>Report ID:</b> {sanitize_text(report.get('report_id', 'N/A'))}",
        f"<b>Generated:</b> {sanitize_text(report.get('generated_at', ''))[:19].replace('T', ' ')} UTC",
        "<b>Classification:</b> TLP:AMBER | SOC DAILY SUMMARY",
    ]
    banner = create_banner(
        title="DAILY SOC INCIDENT & THREAT SUMMARY",
        subtitle=f"Monitoring Window: {period_str}",
        meta_lines=meta,
        styles=styles,
    )
    story.append(banner)
    story.append(Spacer(1, 10))

    # 2. Key Metrics Bar
    stats = report.get("statistics", {})
    sev_counts = stats.get("severity_counts", {})
    total_alerts = stats.get("total_alerts", 0)
    total_incidents = stats.get("total_incidents", 0)
    peak_risk = stats.get("peak_risk", 0)
    distinct_hosts = stats.get("distinct_hosts_count", 0)

    stats_bar = [
        [
            Paragraph("<b>Total Correlated Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{total_incidents}</b>", styles["TableCellBold"]),
            Paragraph("<b>Total Processed Alerts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{total_alerts}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Critical Severity Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('critical', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>High Severity Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('high', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Medium Severity Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('medium', 0)}</b>", styles["TableCellBold"]),
            Paragraph("<b>Low Severity Incidents:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sev_counts.get('low', 0)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Peak Incident Risk Score:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{peak_risk}/100</b>", styles["TableCellBold"]),
            Paragraph("<b>Distinct Affected Hosts:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{distinct_hosts}</b>", styles["TableCellBold"]),
        ],
    ]
    t_stats = Table(stats_bar, colWidths=[140, 130, 140, 130])
    t_stats.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(t_stats)
    story.append(Spacer(1, 10))

    # 3. Section A: Executive Risk Summary
    story.extend(create_section_header("A. 24-HOUR EXECUTIVE RISK SUMMARY", styles))
    exec_summary = report.get("overall_risk_summary", "")
    story.append(create_callout_box(exec_summary, styles, bg_color=HexColor("#f8fafc"), border_color=COLOR_BORDER))
    story.append(Spacer(1, 10))

    # 4. Section B: Incident Register & Detailed Dossiers
    story.extend(create_section_header("B. CORRELATED INCIDENT DOSSIERS & RESPONSE ACTIONS", styles))
    incidents = report.get("incidents", [])
    if incidents:
        table_rows = [
            [
                Paragraph("<b>Incident ID</b>", styles["TableHeader"]),
                Paragraph("<b>Severity</b>", styles["TableHeader"]),
                Paragraph("<b>Risk</b>", styles["TableHeader"]),
                Paragraph("<b>Confidence</b>", styles["TableHeader"]),
                Paragraph("<b>Affected Hosts</b>", styles["TableHeader"]),
                Paragraph("<b>Recommended Response</b>", styles["TableHeader"]),
            ]
        ]
        for inc in incidents:
            s_bg, s_fg = get_severity_badge_style(inc.get("severity", "LOW"))
            table_rows.append([
                Paragraph(sanitize_text(inc.get("incident_id", "")), styles["TableCellMono"]),
                Paragraph(f"<font color='{s_fg.hexval()}'><b>{sanitize_text(inc.get('severity', '').upper())}</b></font>", styles["TableCell"]),
                Paragraph(f"{inc.get('risk_score', 0)}/100", styles["TableCellBold"]),
                Paragraph(f"{int(float(inc.get('confidence', 0.0)) * 100)}%", styles["TableCell"]),
                Paragraph(sanitize_text(", ".join(inc.get("affected_hosts", [])) or "N/A"), styles["TableCell"]),
                Paragraph(sanitize_text(inc.get("recommended_action", "Analyst review")), styles["TableCell"]),
            ])
        t_inc = Table(table_rows, colWidths=[80, 65, 55, 60, 110, 170], repeatRows=1)
        t_inc.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(t_inc)
        story.append(Spacer(1, 12))

        for i, inc in enumerate(incidents, 1):
            s_bg, s_fg = get_severity_badge_style(inc.get("severity", "LOW"))
            badge_text = inc.get("severity", "").upper()

            card_hdr = [
                [
                    Paragraph(f"<b>Incident #{i}: {sanitize_text(inc.get('incident_id', ''))}</b>", styles["TableCellBold"]),
                    Paragraph(f"<font color='{s_fg.hexval()}'><b>[ {badge_text} ]</b></font>", styles["TableCell"]),
                    Paragraph(f"<b>Risk:</b> {inc.get('risk_score', 0)}/100", styles["TableCellBold"]),
                    Paragraph(f"<b>Confidence:</b> {int(float(inc.get('confidence', 0.0)) * 100)}%", styles["TableCell"]),
                ]
            ]
            t_hdr = Table(card_hdr, colWidths=[180, 120, 120, 120])
            t_hdr.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_SECONDARY_NAVY),
                    ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_TEXT_LIGHT),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ])
            )

            approval_str = "YES — Pre-execution approval required" if inc.get("requires_approval", True) else "NO — Automated action permitted"
            iocs_str = ", ".join(inc.get("iocs", [])) or "None identified"
            mitre_str = ", ".join(inc.get("mitre_techniques", [])) or "None identified"
            hosts_str = ", ".join(inc.get("affected_hosts", [])) or "N/A"

            card_body = [
                [
                    Paragraph("<b>Affected Host(s):</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(hosts_str), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Associated IOCs:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(iocs_str), styles["TableCellMono"]),
                ],
                [
                    Paragraph("<b>MITRE ATT&CK:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(mitre_str), styles["TableCellMono"]),
                ],
                [
                    Paragraph("<b>Executive Summary:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(inc.get("summary", "")), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Response Recommendation:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(inc.get("recommended_action", "")), styles["TableCellBold"]),
                ],
                [
                    Paragraph("<b>Approval Status:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(approval_str), styles["TableCellBold"]),
                ],
            ]
            t_body = Table(card_body, colWidths=[140, 400])
            t_body.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )

            story.append(t_hdr)
            story.append(t_body)
            story.append(Spacer(1, 8))
    else:
        story.append(Paragraph("Zero incidents were recorded during this 24-hour monitoring period.", styles["Body"]))
        story.append(Spacer(1, 10))

    # 5. Section C: Strategic Observations & Recommendations
    story.extend(create_section_header("C. STRATEGIC OBSERVATIONS & SOC RECOMMENDATIONS", styles))
    recs = report.get("overall_recommendations", [])
    if recs:
        rec_rows = [
            [
                Paragraph("<b>#</b>", styles["TableHeader"]),
                Paragraph("<b>Recommended Containment & Hardening Measure</b>", styles["TableHeader"]),
            ]
        ]
        for idx, r in enumerate(recs, 1):
            rec_rows.append([
                Paragraph(str(idx), styles["TableCellBold"]),
                Paragraph(sanitize_text(r), styles["TableCell"]),
            ])
        t_recs = Table(rec_rows, colWidths=[30, 510])
        t_recs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_recs)
    else:
        story.append(Paragraph("No strategic action items pending at this time.", styles["Body"]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()


# ==============================================================================
# 9. FEATURE FOUR: RUN CORRELATION INVESTIGATION REPORT BUILDER
# ==============================================================================

def build_correlation_report_pdf(correlation_result: Dict[str, Any]) -> bytes:
    """
    Build a publication-quality PDF report for a Run Correlation execution.
    Summarizes all analyzed alerts, correlation groups, extracted IOCs,
    VirusTotal threat intelligence, RAG findings, and Qwen3 correlated security assessment.
    """
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=48,
        bottomMargin=48,
    )

    styles = get_report_styles()
    story: List[Any] = []

    run_id = correlation_result.get("correlation_run_id", "N/A")
    raw_ts = correlation_result.get("timestamp", "")
    ts_str = str(raw_ts)[:19].replace("T", " ") + " UTC"
    status = str(correlation_result.get("status", "correlated")).lower()
    is_no_relation = status == "no_relation"

    classification_str = "TLP:AMBER | RUN CORRELATION REPORT"
    status_display = "INDEPENDENT EVENTS (NO RELATION)" if is_no_relation else "CORRELATED THREATS IDENTIFIED"
    meta = [
        f"<b>Correlation Run ID:</b> {sanitize_text(run_id)}",
        f"<b>Analysis Timestamp:</b> {sanitize_text(ts_str)}",
        f"<b>Status:</b> {sanitize_text(status_display)}",
        f"<b>Classification:</b> {classification_str}",
    ]
    banner = create_banner(
        title="ITTC-AI CORRELATION INVESTIGATION REPORT",
        subtitle="Automated Multi-Source Event & IOC Correlation Analysis",
        meta_lines=meta,
        styles=styles,
    )
    story.append(banner)
    story.append(Spacer(1, 10))

    total_alerts = correlation_result.get("alerts_analyzed", 0)
    related_groups = correlation_result.get("related_groups", [])
    total_groups = len(related_groups)
    iocs = correlation_result.get("iocs", [])
    total_iocs = len(iocs)
    risk_score = correlation_result.get("risk", 50)
    severity_val = str(correlation_result.get("severity", "MEDIUM")).upper()

    s_bg, s_fg = get_severity_badge_style(severity_val)

    stats_bar = [
        [
            Paragraph("<b>Alerts Analyzed:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{total_alerts}</b>", styles["TableCellBold"]),
            Paragraph("<b>Correlated Groups:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{total_groups}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Extracted IOCs:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{total_iocs}</b>", styles["TableCellBold"]),
            Paragraph("<b>Correlation Status:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{sanitize_text(status_display)}</b>", styles["TableCellBold"]),
        ],
        [
            Paragraph("<b>Correlated Risk Score:</b>", styles["TableCellBold"]),
            Paragraph(f"<b>{risk_score}/100</b>", styles["TableCellBold"]),
            Paragraph("<b>Lead Severity:</b>", styles["TableCellBold"]),
            Paragraph(f"<font color='{s_fg.hexval()}'><b>{severity_val}</b></font>", styles["TableCellBold"]),
        ],
    ]
    t_stats = Table(stats_bar, colWidths=[140, 130, 140, 130])
    t_stats.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
            ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
            ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 6),
            ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ])
    )
    story.append(t_stats)
    story.append(Spacer(1, 10))

    story.extend(create_section_header("A. EXECUTIVE CORRELATION SUMMARY & REASONING", styles))
    qwen = correlation_result.get("qwen_analysis") or {}
    exec_summary = qwen.get("summary") or correlation_result.get("message", "Correlation analysis complete.")
    story.append(create_callout_box(exec_summary, styles, bg_color=HexColor("#f8fafc"), border_color=COLOR_BORDER))
    story.append(Spacer(1, 6))

    reasoning_text = correlation_result.get("correlation_reasoning") or qwen.get("correlation_reasoning") or ""
    if reasoning_text:
        reasoning_html = f"<b>Correlation Methodology & Relationship Reasoning:</b><br/>{sanitize_text(reasoning_text)}"
        story.append(create_callout_box(reasoning_html, styles, bg_color=HexColor("#f1f5f9"), border_color=COLOR_BORDER_LIGHT))
        story.append(Spacer(1, 10))

    story.extend(create_section_header("B. CORRELATED INCIDENT CLUSTERS & RELATIONSHIPS", styles))
    if related_groups:
        for grp in related_groups:
            grp_id = grp.get("group_id", "GROUP-1")
            lead_sev = str(grp.get("lead_severity", "MEDIUM")).upper()
            grp_risk = grp.get("lead_risk_score", 50)
            hosts_str = ", ".join(grp.get("hosts", [])) or "N/A"
            users_str = ", ".join(grp.get("users", [])) or "N/A"
            rel_types = ", ".join(grp.get("relationship_types", [])) or "Temporal & Contextual"
            grp_reasoning = grp.get("reasoning", "")
            alert_ids = grp.get("alert_ids", [])

            card_hdr = [
                [
                    Paragraph(f"<b>Group ID: {sanitize_text(grp_id)}</b>", styles["TableHeader"]),
                    Paragraph(f"<b>Severity: {lead_sev} | Risk: {grp_risk}/100</b>", styles["TableHeader"]),
                ]
            ]
            t_hdr = Table(card_hdr, colWidths=[270, 270])
            t_hdr.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_SECONDARY_NAVY),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ])
            )

            card_body = [
                [
                    Paragraph("<b>Affected Hosts:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(hosts_str), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Observed Users:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(users_str), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Relationship Types:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(rel_types), styles["TableCellBold"]),
                ],
                [
                    Paragraph("<b>Correlation Basis:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(grp_reasoning), styles["TableCell"]),
                ],
                [
                    Paragraph("<b>Correlated Alerts:</b>", styles["TableCellBold"]),
                    Paragraph(sanitize_text(", ".join(alert_ids)), styles["TableCellMono"]),
                ],
            ]

            alert_details = grp.get("alert_details", [])
            if alert_details:
                detail_rows = []
                for a in alert_details:
                    aid = a.get("alert_id", "")
                    asev = str(a.get("severity", "")).upper()
                    ahost = a.get("host", "")
                    aev = a.get("event", "")[:120]
                    detail_rows.append(f"• <b>[{aid}]</b> ({asev} on {ahost}): {aev}")
                card_body.append([
                    Paragraph("<b>Alert Details:</b>", styles["TableCellBold"]),
                    Paragraph("<br/>".join(sanitize_text(r) for r in detail_rows), styles["TableCell"]),
                ])

            t_body = Table(card_body, colWidths=[140, 400])
            t_body.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, -1), COLOR_BG_CARD),
                    ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                    ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                    ("TOPPADDING", (0, 0), (-1, -1), 2.5),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 2.5),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ])
            )
            story.append(t_hdr)
            story.append(t_body)
            story.append(Spacer(1, 8))
    else:
        no_rel_box = (
            "<b>No related alerts found.</b><br/>"
            "All analyzed alerts appear to be independent events based on IOC, temporal window, "
            "host context, and security relationship evaluation. No shared lateral movement, command-and-control "
            "channels, or coordinated multi-stage adversary campaigns were observed across the current alert set."
        )
        story.append(create_callout_box(no_rel_box, styles, bg_color=HexColor("#eff6ff"), border_color=COLOR_BORDER))
        story.append(Spacer(1, 10))

    story.extend(create_section_header("C. EXTRACTED IOCS & VIRUSTOTAL THREAT INTELLIGENCE", styles))
    ti_list = correlation_result.get("threat_intelligence", [])
    if ti_list:
        ti_rows = [
            [
                Paragraph("<b>Indicator (IOC)</b>", styles["TableHeader"]),
                Paragraph("<b>Type</b>", styles["TableHeader"]),
                Paragraph("<b>Reputation</b>", styles["TableHeader"]),
                Paragraph("<b>Detections</b>", styles["TableHeader"]),
                Paragraph("<b>Provider Status</b>", styles["TableHeader"]),
                Paragraph("<b>Source</b>", styles["TableHeader"]),
            ]
        ]
        for ti in ti_list:
            ioc_val = ti.get("ioc", "")
            ioc_type = ti.get("ioc_type", "").upper()
            rep = ti.get("reputation", "unknown").upper()
            det_count = ti.get("malicious_count")
            tot_eng = ti.get("total_engines")
            det_str = f"{det_count}/{tot_eng}" if det_count is not None and tot_eng is not None else "N/A"
            prov_status = ti.get("provider_status", "available")
            source_str = ti.get("source", "VirusTotal")
            rep_color = "#991b1b" if rep == "MALICIOUS" else ("#92400e" if rep == "SUSPICIOUS" else "#475569")

            ti_rows.append([
                Paragraph(sanitize_text(ioc_val), styles["TableCellMono"]),
                Paragraph(sanitize_text(ioc_type), styles["TableCellBold"]),
                Paragraph(f"<font color='{rep_color}'><b>{sanitize_text(rep)}</b></font>", styles["TableCell"]),
                Paragraph(sanitize_text(det_str), styles["TableCell"]),
                Paragraph(sanitize_text(prov_status), styles["TableCell"]),
                Paragraph(sanitize_text(source_str), styles["TableCell"]),
            ])
        t_ti = Table(ti_rows, colWidths=[160, 60, 80, 75, 85, 80], repeatRows=1)
        t_ti.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_ti)
        story.append(Spacer(1, 10))
    elif iocs:
        ioc_rows = [
            [
                Paragraph("<b>Indicator (IOC)</b>", styles["TableHeader"]),
                Paragraph("<b>Type</b>", styles["TableHeader"]),
                Paragraph("<b>Threat Intelligence Status</b>", styles["TableHeader"]),
            ]
        ]
        for ioc in iocs:
            ioc_rows.append([
                Paragraph(sanitize_text(ioc.get("value", "")), styles["TableCellMono"]),
                Paragraph(sanitize_text(str(ioc.get("type", "")).upper()), styles["TableCellBold"]),
                Paragraph("VirusTotal lookup completed (unrated / offline fallback)", styles["TableCell"]),
            ])
        t_iocs = Table(ioc_rows, colWidths=[240, 100, 200], repeatRows=1)
        t_iocs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_iocs)
        story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("No external indicators of compromise (IOCs) detected across analyzed alerts.", styles["Body"]))
        story.append(Spacer(1, 10))

    story.extend(create_section_header("D. RAG INVESTIGATION FINDINGS & MITRE ATT&CK CONTEXT", styles))
    rag_findings = correlation_result.get("rag_findings", [])
    if rag_findings:
        rag_rows = [
            [
                Paragraph("<b>Topic / Technique</b>", styles["TableHeader"]),
                Paragraph("<b>Category</b>", styles["TableHeader"]),
                Paragraph("<b>Similarity</b>", styles["TableHeader"]),
                Paragraph("<b>Knowledge Base Context & Playbook Guidance</b>", styles["TableHeader"]),
            ]
        ]
        for rf in rag_findings:
            title_str = rf.get("title") or rf.get("topic") or "Security Playbook"
            cat_str = rf.get("category", "MITRE ATT&CK")
            score_str = f"{rf.get('similarity_score', 0.0):.2f}"
            text_str = rf.get("text", "")[:280]
            rag_rows.append([
                Paragraph(sanitize_text(title_str), styles["TableCellBold"]),
                Paragraph(sanitize_text(cat_str), styles["TableCell"]),
                Paragraph(sanitize_text(score_str), styles["TableCell"]),
                Paragraph(sanitize_text(text_str), styles["TableCell"]),
            ])
        t_rag = Table(rag_rows, colWidths=[130, 80, 50, 280], repeatRows=1)
        t_rag.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ])
        )
        story.append(t_rag)
        story.append(Spacer(1, 10))
    else:
        story.append(Paragraph("Standard RAG baseline referenced; no specialized MITRE playbook overrides triggered.", styles["Body"]))
        story.append(Spacer(1, 10))

    story.extend(create_section_header("E. QWEN3 CORRELATED ANALYSIS & DEFENSIVE RECOMMENDATIONS", styles))
    evidence_list = qwen.get("evidence") or correlation_result.get("evidence", [])
    if evidence_list:
        story.append(Paragraph("<b>Observed Correlated Evidence:</b>", styles["TableCellBold"]))
        for ev in evidence_list[:6]:
            story.append(Paragraph(f"• {sanitize_text(ev)}", styles["Body"]))
        story.append(Spacer(1, 6))

    recs = qwen.get("recommendations", [])
    if recs:
        rec_rows = [
            [
                Paragraph("<b>#</b>", styles["TableHeader"]),
                Paragraph("<b>Recommended SOC Incident Containment & Hardening Action</b>", styles["TableHeader"]),
            ]
        ]
        for idx, r in enumerate(recs, 1):
            rec_rows.append([
                Paragraph(str(idx), styles["TableCellBold"]),
                Paragraph(sanitize_text(r), styles["TableCell"]),
            ])
        t_recs = Table(rec_rows, colWidths=[30, 510])
        t_recs.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_SECONDARY_NAVY),
                ("BOX", (0, 0), (-1, -1), 0.5, COLOR_BORDER),
                ("INNERGRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_LIGHT),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_TEXT_LIGHT, COLOR_BG_ZEBRA]),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
            ])
        )
        story.append(t_recs)
    else:
        story.append(Paragraph("No immediate containment actions required. Maintain standard continuous monitoring.", styles["Body"]))

    doc.build(story, canvasmaker=NumberedCanvas)
    return buf.getvalue()
