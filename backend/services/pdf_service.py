"""
backend/services/pdf_service.py
===============================
Service for generating PDFs from query results and incidents.
"""

import io
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak, Image
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


class PDFService:
    """Service for generating PDF reports"""

    def __init__(self):
        self.reportlab_available = HAS_REPORTLAB

    def generate_query_report(
        self,
        query: str,
        results: List[Dict[str, Any]],
        collection: str,
        timestamp: Optional[datetime] = None,
    ) -> bytes:
        """
        Generate a PDF report for RAG query results.

        Args:
            query: The original query string
            results: List of result dicts with 'content', 'metadata', 'similarity'
            collection: Collection name
            timestamp: Report generation timestamp

        Returns:
            PDF file as bytes
        """
        if not self.reportlab_available:
            raise RuntimeError("ReportLab not installed. Run: pip install reportlab")

        timestamp = timestamp or datetime.now()
        buffer = io.BytesIO()

        # Create PDF
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"Query Report - {timestamp.strftime('%Y-%m-%d')}",
        )

        # Styles
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#1e3a8a"),
            spaceAfter=12,
            fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=14,
            textColor=colors.HexColor("#1e40af"),
            spaceAfter=8,
            spaceBefore=12,
            fontName="Helvetica-Bold",
        )
        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        )
        meta_style = ParagraphStyle(
            "Metadata",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#666666"),
            spaceAfter=4,
        )

        story = []

        # Title
        story.append(Paragraph("🔍 Security Query Report", title_style))
        story.append(Spacer(1, 0.2 * inch))

        # Header info table
        header_data = [
            ["Query:", query],
            ["Collection:", collection],
            ["Generated:", timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")],
            ["Results Found:", str(len(results))],
        ]

        header_table = Table(header_data, colWidths=[1.5 * inch, 4 * inch])
        header_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e0e7ff")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                ]
            )
        )
        story.append(header_table)
        story.append(Spacer(1, 0.3 * inch))

        # Results
        story.append(Paragraph("Query Results", heading_style))

        if not results:
            story.append(Paragraph("No results found for this query.", normal_style))
        else:
            for i, result in enumerate(results, 1):
                # Result number and similarity
                content = result.get("content", "No content")
                metadata = result.get("metadata", {})
                similarity = result.get("similarity", 0)

                # Result heading with number and score
                result_title = f"Result #{i} - Relevance: {similarity * 100:.1f}%"
                story.append(Paragraph(result_title, heading_style))

                # Metadata
                if metadata:
                    meta_items = []
                    if "source" in metadata:
                        meta_items.append(f"<b>Source:</b> {metadata['source']}")
                    if "collection" in metadata:
                        meta_items.append(f"<b>Collection:</b> {metadata['collection']}")
                    if "date" in metadata or "timestamp" in metadata:
                        date_val = metadata.get("date") or metadata.get("timestamp")
                        meta_items.append(f"<b>Date:</b> {date_val}")
                    if "incident_type" in metadata:
                        meta_items.append(f"<b>Type:</b> {metadata['incident_type']}")

                    if meta_items:
                        story.append(Paragraph(" | ".join(meta_items), meta_style))

                # Content
                # Truncate very long content for readability
                display_content = content
                if len(content) > 1000:
                    display_content = content[:1000] + "...[content truncated]"

                story.append(Paragraph(display_content, normal_style))
                story.append(Spacer(1, 0.15 * inch))

                # Page break every 3 results
                if (i % 3 == 0) and (i < len(results)):
                    story.append(PageBreak())

        # Footer
        story.append(Spacer(1, 0.3 * inch))
        footer_text = (
            f"<i>Generated by Cloud SOC Dashboard on {timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC</i>"
        )
        story.append(Paragraph(footer_text, meta_style))

        # Build PDF
        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()

    def generate_incident_report(
        self,
        user_name: str,
        window: str,
        alert: Dict[str, Any],
        enrichment: Dict[str, Any],
        timestamp: Optional[datetime] = None,
    ) -> bytes:
        """
        Generate a PDF report for an incident enrichment.

        Args:
            user_name: User involved in incident
            window: Time window
            alert: Alert data
            enrichment: Enrichment context
            timestamp: Report generation timestamp

        Returns:
            PDF file as bytes
        """
        if not self.reportlab_available:
            raise RuntimeError("ReportLab not installed. Run: pip install reportlab")

        timestamp = timestamp or datetime.now()
        buffer = io.BytesIO()

        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=0.75 * inch,
            leftMargin=0.75 * inch,
            topMargin=0.75 * inch,
            bottomMargin=0.75 * inch,
            title=f"Incident Report - {user_name}",
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CustomTitle",
            parent=styles["Heading1"],
            fontSize=24,
            textColor=colors.HexColor("#991b1b"),
            spaceAfter=12,
            fontName="Helvetica-Bold",
        )
        heading_style = ParagraphStyle(
            "CustomHeading",
            parent=styles["Heading2"],
            fontSize=12,
            textColor=colors.HexColor("#b91c1c"),
            spaceAfter=8,
            spaceBefore=10,
            fontName="Helvetica-Bold",
        )
        normal_style = ParagraphStyle(
            "CustomNormal",
            parent=styles["Normal"],
            fontSize=10,
            alignment=TA_JUSTIFY,
            spaceAfter=6,
        )

        story = []

        # Title
        story.append(Paragraph("🚨 Security Incident Report", title_style))
        story.append(Spacer(1, 0.2 * inch))

        # Alert summary
        story.append(Paragraph("Incident Summary", heading_style))
        summary_data = [
            ["User:", user_name],
            ["Time Window:", window],
            ["Attack Type:", alert.get("attack_name", "Unknown")],
            ["Ensemble Score:", f"{alert.get('ensemble_score', 0):.4f}"],
            ["Confirmed Threat:", "Yes" if alert.get("is_attack") else "No"],
        ]

        summary_table = Table(summary_data, colWidths=[1.5 * inch, 4 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#fee2e2")),
                    ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 1, colors.grey),
                ]
            )
        )
        story.append(summary_table)
        story.append(Spacer(1, 0.2 * inch))

        # Detection details
        detection = enrichment.get("detection", {})
        if detection:
            story.append(Paragraph("Detection Details", heading_style))

            techniques = detection.get("techniques", [])
            if techniques:
                story.append(
                    Paragraph(
                        f"<b>MITRE ATT&CK Techniques:</b> {', '.join(techniques)}",
                        normal_style,
                    )
                )

            patterns = detection.get("matched_patterns", [])
            if patterns:
                story.append(
                    Paragraph(
                        f"<b>Matched Patterns:</b> {', '.join(patterns)}",
                        normal_style,
                    )
                )

            playbooks = detection.get("primary_playbooks", [])
            if playbooks:
                story.append(
                    Paragraph(
                        f"<b>Recommended Playbooks:</b> {', '.join(playbooks)}",
                        normal_style,
                    )
                )

            story.append(Spacer(1, 0.1 * inch))

        # Behavioral context
        behavior = enrichment.get("behavioral_context", {})
        if behavior:
            story.append(Paragraph("Behavioral Context", heading_style))
            story.append(
                Paragraph(
                    f"Total Events: {behavior.get('total_events', 0)} | "
                    f"IAM Write Events: {behavior.get('iam_write_events', 0)}",
                    normal_style,
                )
            )
            story.append(Spacer(1, 0.1 * inch))

        # RAG retrieval
        rag = enrichment.get("rag_retrieval", {})
        if rag and rag.get("similar_past_incidents"):
            story.append(Paragraph("Similar Past Incidents", heading_style))
            for incident in rag.get("similar_past_incidents", [])[:3]:
                story.append(Paragraph(f"• {incident}", normal_style))
            story.append(Spacer(1, 0.1 * inch))

        # Footer
        story.append(Spacer(1, 0.3 * inch))
        footer_text = (
            f"<i>Generated by Cloud SOC Dashboard on {timestamp.strftime('%Y-%m-%d %H:%M:%S')} UTC</i>"
        )
        story.append(Paragraph(footer_text, normal_style))

        doc.build(story)
        buffer.seek(0)
        return buffer.getvalue()


def get_pdf_service() -> PDFService:
    """Dependency injection for PDF service"""
    return PDFService()
