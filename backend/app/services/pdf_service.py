from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf(report_data: dict) -> bytes:
    buffer = BytesIO()
    
    # Establish document template
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    story = []
    
    # Custom styles
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        name="TitleStyle",
        parent=styles["Heading1"],
        fontSize=24,
        leading=28,
        textColor=colors.HexColor("#1E3A8A"),
        spaceAfter=15
    )
    
    section_style = ParagraphStyle(
        name="SectionStyle",
        parent=styles["Heading2"],
        fontSize=16,
        leading=20,
        textColor=colors.HexColor("#0D9488"),
        spaceBefore=12,
        spaceAfter=8
    )
    
    body_style = ParagraphStyle(
        name="BodyStyle",
        parent=styles["BodyText"],
        fontSize=10,
        leading=14,
        textColor=colors.HexColor("#374151")
    )
    
    code_style = ParagraphStyle(
        name="CodeStyle",
        parent=styles["Code"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#0F766E"),
        backColor=colors.HexColor("#F3F4F6"),
        borderColor=colors.HexColor("#E5E7EB"),
        borderWidth=1,
        borderPadding=5,
        spaceAfter=5
    )
    
    # Title
    story.append(Paragraph("MCP Shield Security Report", title_style))
    story.append(Spacer(1, 10))
    
    # Metadata Info
    story.append(Paragraph(f"<b>Target URL:</b> {report_data.get('target_url', 'Unknown')}", body_style))
    story.append(Paragraph(f"<b>Scanned At:</b> {report_data.get('scanned_at', 'Just now')}", body_style))
    story.append(Paragraph(f"<b>Security Risk Score:</b> {report_data.get('risk_score', 0)}/100 ({report_data.get('risk_level', 'SAFE')})", body_style))
    story.append(Spacer(1, 15))
    
    # Vulnerabilities Table
    story.append(Paragraph("Security Assessment Summary", section_style))
    
    table_data = [["ID", "Attack Vector", "Severity", "Status", "CVSS"]]
    for vuln in report_data.get("vulnerabilities", []):
        table_data.append([
            vuln.get("attack_id", vuln.get("id", "")),
            vuln.get("attack_name", vuln.get("name", "")),
            vuln.get("severity") or "SAFE",
            vuln.get("status", ""),
            str(vuln.get("cvss_score") or "0.0")
        ])
        
    t = Table(table_data, colWidths=[40, 240, 70, 90, 40])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#1F2937")),
        ('TEXTCOLOR', (0,0), (-1,0), colors.whitesmoke),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('BOTTOMPADDING', (0,0), (-1,0), 6),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor("#F9FAFB"), colors.white]),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#E5E7EB")),
        ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
        ('FONTSIZE', (0,0), (-1,0), 9),
        ('FONTSIZE', (0,1), (-1,-1), 8),
    ]))
    
    story.append(t)
    story.append(Spacer(1, 15))
    
    # Vulnerability Details
    story.append(Paragraph("Detailed Findings & Fix Recommendations", section_style))
    
    vulns = [v for v in report_data.get("vulnerabilities", []) if v.get("status") == "VULNERABLE"]
    if not vulns:
        story.append(Paragraph("No vulnerabilities were detected on this server.", body_style))
    else:
        for idx, vuln in enumerate(vulns):
            name = vuln.get("attack_name", vuln.get("name", ""))
            severity = vuln.get("severity", "LOW")
            cvss = vuln.get("cvss_score", "0.0")
            desc = vuln.get("description", "")
            evidence = vuln.get("evidence", "")
            fix = vuln.get("fix_suggestion", vuln.get("fix", ""))
            
            story.append(Paragraph(f"<b>{idx+1}. {name} — {severity} (CVSS: {cvss})</b>", body_style))
            story.append(Paragraph(f"Description: {desc}", body_style))
            if evidence:
                story.append(Paragraph(f"Evidence:", body_style))
                story.append(Paragraph(evidence, code_style))
            if fix:
                story.append(Paragraph(f"<b>Fix Recommendation:</b> {fix}", body_style))
            story.append(Spacer(1, 10))
            
    doc.build(story)
    
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
