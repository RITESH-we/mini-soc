import os
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

def generate_pdf_report(incident_id, title, severity, analyst, created_at, summary, alerts, output_path):
    doc = SimpleDocTemplate(
        output_path,
        pagesize=letter,
        rightMargin=40,
        leftMargin=40,
        topMargin=40,
        bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=20,
        leading=24,
        textColor=colors.HexColor('#0f172a'),
        spaceAfter=6
    )
    
    subtitle_style = ParagraphStyle(
        'DocSubTitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor('#64748b'),
        spaceAfter=15
    )
    
    h2_style = ParagraphStyle(
        'H2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=13,
        leading=16,
        textColor=colors.HexColor('#1e293b'),
        spaceBefore=12,
        spaceAfter=6
    )
    
    body_style = ParagraphStyle(
        'Body',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        leading=14,
        textColor=colors.HexColor('#334155')
    )

    elements = []

    # Title & Header
    elements.append(Paragraph("MiniSOC — Incident Investigation Report", title_style))
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')} | Classification: TLP:AMBER", subtitle_style))
    elements.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor('#2563eb'), spaceAfter=15))

    # Incident Overview Table
    sev_color = colors.HexColor('#dc2626') if severity == 'CRITICAL' else (
        colors.HexColor('#ea580c') if severity == 'HIGH' else (
            colors.HexColor('#2563eb') if severity == 'MEDIUM' else colors.HexColor('#16a34a')
        )
    )
    
    overview_data = [
        [Paragraph("<b>Incident ID:</b>", body_style), Paragraph(f"#{incident_id}", body_style),
         Paragraph("<b>Severity:</b>", body_style), Paragraph(f"<font color='{sev_color.hexval()}'><b>{severity}</b></font>", body_style)],
        [Paragraph("<b>Title:</b>", body_style), Paragraph(title, body_style),
         Paragraph("<b>Assigned Analyst:</b>", body_style), Paragraph(analyst or "rites", body_style)],
        [Paragraph("<b>Created Date:</b>", body_style), Paragraph(created_at[:19] if created_at else "N/A", body_style),
         Paragraph("<b>Framework:</b>", body_style), Paragraph("NIST SP 800-61 Rev. 2", body_style)]
    ]
    
    t = Table(overview_data, colWidths=[90, 180, 100, 160])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor('#f8fafc')),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 15))

    # Executive Summary
    elements.append(Paragraph("1. Executive Summary", h2_style))
    elements.append(Paragraph(summary or "No analyst summary provided at the time of report compilation.", body_style))
    elements.append(Spacer(1, 15))

    # Associated Alerts & Evidence
    elements.append(Paragraph("2. Correlated Telemetry & Alert Evidence", h2_style))
    
    headers = [Paragraph("<b>Time</b>", body_style),
               Paragraph("<b>Severity</b>", body_style),
               Paragraph("<b>Detection Rule</b>", body_style),
               Paragraph("<b>MITRE ATT&CK</b>", body_style),
               Paragraph("<b>Source / Artifact</b>", body_style)]
    
    alert_rows = [headers]
    if alerts:
        for a in alerts:
            alert_rows.append([
                Paragraph(a['timestamp'][:16] if 'timestamp' in a else 'N/A', body_style),
                Paragraph(a.get('severity', 'LOW'), body_style),
                Paragraph(a.get('rule_name', 'Rule'), body_style),
                Paragraph(a.get('mitre_technique', 'T1059'), body_style),
                Paragraph(f"User: {a.get('src_user') or '-'}<br/>IP: {a.get('src_ip') or '-'}", body_style)
            ])
    else:
        alert_rows.append([Paragraph("No correlated alerts linked directly to this ticket.", body_style),
                           Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])

    alert_table = Table(alert_rows, colWidths=[90, 65, 150, 105, 120])
    alert_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0f172a')),
        ('TEXTCOLOR', (0,0), (-1,0), colors.white),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor('#cbd5e1')),
        ('INNERGRID', (0,0), (-1,-1), 0.5, colors.HexColor('#e2e8f0')),
        ('TOPPADDING', (0,0), (-1,-1), 5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 5),
    ]))
    elements.append(alert_table)
    elements.append(Spacer(1, 15))

    # Containment & Remediation Recommendations
    elements.append(Paragraph("3. Containment & Remediation Actions (NIST Phase 3 & 4)", h2_style))
    remediation_text = """
    • <b>Identity Isolation:</b> Invalidate active Kerberos/NTLM tokens for targeted account(s) and enforce mandatory password rotation.<br/>
    • <b>Network Segmentation:</b> Block correlated C2 / external adversary IP address at perimeter firewall and EDR boundary.<br/>
    • <b>Host Forensics:</b> Perform memory analysis with Volatility 3 and inspect Sysmon Event ID 1 (Process Execution) for persistence artifacts.<br/>
    • <b>Post-Incident Review:</b> Update detection engineering rules to adjust behavioral threshold metrics and lower false-positive margin.
    """
    elements.append(Paragraph(remediation_text, body_style))
    elements.append(Spacer(1, 20))

    # Sign-off footer
    elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor('#94a3b8'), spaceAfter=8))
    elements.append(Paragraph(f"Report authorized by Security Operations Center Tier 1 Analyst: <b>{analyst or 'rites'}</b> | MiniSOC Internal Audit", subtitle_style))

    doc.build(elements)
    return output_path
