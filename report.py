from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
import io

def create_pdf(target, result, created_at):
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm)
    styles = getSampleStyleSheet()
    story = [Paragraph("WebGuard Security Assessment", styles["Title"]),
             Paragraph(f"<b>Target:</b> {target}", styles["BodyText"]),
             Paragraph(f"<b>Scan date:</b> {created_at}", styles["BodyText"]),
             Spacer(1, 10),
             Paragraph(f"<b>Security score:</b> {result['score']}/100", styles["Heading2"]),
             Paragraph(f"<b>HTTP status:</b> {result['status_code']} &nbsp;&nbsp; <b>HTTPS:</b> {'Yes' if result['https'] else 'No'}", styles["BodyText"]),
             Spacer(1, 10)]
    rows = [["Severity", "Count"]] + [[k, str(v)] for k,v in result["counts"].items()]
    table = Table(rows, colWidths=[75*mm, 35*mm])
    table.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#18243b")),
        ("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey),
        ("PADDING",(0,0),(-1,-1),7)]))
    story += [table, Spacer(1, 14), Paragraph("Findings", styles["Heading2"])]
    if not result["findings"]:
        story.append(Paragraph("No issues were detected by the configured checks.", styles["BodyText"]))
    for item in result["findings"]:
        story += [Paragraph(f"<b>{item['severity']}: {item['title']}</b>", styles["Heading3"]),
                  Paragraph(item["details"], styles["BodyText"]),
                  Paragraph(f"<b>Recommendation:</b> {item['recommendation']}", styles["BodyText"]),
                  Spacer(1, 8)]
    story += [Spacer(1, 10), Paragraph(result["note"], styles["Italic"])]
    doc.build(story)
    return buffer.getvalue()
