from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from datetime import datetime

def generate_pdf_report(results, target_ip, owner_name, phone_number):

    file_name = "vulnerability_report.pdf"

    doc = SimpleDocTemplate(
        file_name,
        pagesize=A4
    )

    styles = getSampleStyleSheet()
    elements = []

    scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # -----------------------
    # PAGE 1 - COVER PAGE
    # -----------------------

    elements.append(Paragraph("Network Vulnerability Assessment Report", styles["Title"]))
    elements.append(Spacer(1,40))

    elements.append(Paragraph("Prepared For:", styles["Heading2"]))
    elements.append(Paragraph(owner_name, styles["Normal"]))
    elements.append(Spacer(1,20))

    elements.append(Paragraph("Contact Number:", styles["Heading3"]))
    elements.append(Paragraph(phone_number, styles["Normal"]))
    elements.append(Spacer(1,20))

    elements.append(Paragraph("Target IP Address:", styles["Heading3"]))
    elements.append(Paragraph(target_ip, styles["Normal"]))
    elements.append(Spacer(1,20))

    elements.append(Paragraph(f"Scan Date: {scan_date}", styles["Normal"]))
    elements.append(Spacer(1,50))

    elements.append(Paragraph(
        "This report contains confidential security assessment results. "
        "Unauthorized distribution is prohibited.",
        styles["Italic"]
    ))

    elements.append(PageBreak())

    # -----------------------
    # PAGE 2 - EXECUTIVE SUMMARY
    # -----------------------

    elements.append(Paragraph("Executive Summary", styles["Title"]))
    elements.append(Spacer(1,20))

    summary_text = """
    This security assessment evaluates the exposed services and vulnerabilities
    detected on the target host. The scan identifies potential weaknesses that
    could allow attackers to gain unauthorized access or disrupt services.

    Critical and high-risk vulnerabilities should be remediated immediately.
    """

    elements.append(Paragraph(summary_text, styles["Normal"]))

    elements.append(PageBreak())

    # -----------------------
    # PAGE 3 - SCAN INFORMATION
    # -----------------------

    elements.append(Paragraph("Scan Information", styles["Title"]))
    elements.append(Spacer(1,20))

    info_table = [
        ["Target IP", target_ip],
        ["Owner Name", owner_name],
        ["Phone Number", phone_number],
        ["Scan Date", scan_date],
        ["Scanner Tool", "Python Nmap Vulnerability Scanner"]
    ]

    table = Table(info_table, colWidths=[200,250])

    table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,0),(0,-1),colors.lightgrey)
    ]))

    elements.append(table)

    elements.append(PageBreak())

    # -----------------------
    # PAGE 4 - VULNERABILITY SUMMARY
    # -----------------------

    elements.append(Paragraph("Vulnerability Summary", styles["Title"]))
    elements.append(Spacer(1,20))

    critical = len([r for r in results if r["severity"]=="Critical"])
    high = len([r for r in results if r["severity"]=="High"])
    medium = len([r for r in results if r["severity"]=="Medium"])
    low = len([r for r in results if r["severity"]=="Low"])

    summary_table = [
        ["Severity","Count"],
        ["Critical",critical],
        ["High",high],
        ["Medium",medium],
        ["Low",low]
    ]

    table = Table(summary_table, colWidths=[200,100])

    table.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,0),(-1,0),colors.grey),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white)
    ]))

    elements.append(table)

    elements.append(PageBreak())

    # -----------------------
    # PAGE 5+ DETAILED FINDINGS
    # -----------------------

    elements.append(Paragraph("Detailed Vulnerability Findings", styles["Title"]))
    elements.append(Spacer(1,20))

    table_data = [[
        "Port",
        "Service",
        "Vulnerability",
        "CVE",
        "Severity",
        "Remediation"
    ]]

    for r in results:
        table_data.append([
            str(r["port"]),
            r["service"],
            r["vulnerability"],
            r["cve"],
            r["severity"],
            r["remediation"]
        ])

    findings = Table(
        table_data,
        colWidths=[50,80,140,80,70,160]
    )

    findings.setStyle(TableStyle([
        ("GRID",(0,0),(-1,-1),1,colors.black),
        ("BACKGROUND",(0,0),(-1,0),colors.grey),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),
        ("FONTSIZE",(0,0),(-1,-1),8)
    ]))

    elements.append(findings)

    elements.append(PageBreak())

    # -----------------------
    # LAST PAGE - RECOMMENDATIONS
    # -----------------------

    elements.append(Paragraph("Security Recommendations", styles["Title"]))
    elements.append(Spacer(1,20))

    rec_text = """
    • Disable unnecessary services and close unused ports.<br/>
    • Keep operating systems and applications updated.<br/>
    • Implement firewall rules to restrict unauthorized access.<br/>
    • Use strong passwords and multi-factor authentication.<br/>
    • Perform regular vulnerability scans and penetration testing.
    """

    elements.append(Paragraph(rec_text, styles["Normal"]))

    doc.build(elements)