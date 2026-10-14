from __future__ import annotations
import csv
import io
from xml.sax.saxutils import escape


def csv_report(report):
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(['target', 'id', 'severity', 'confidence', 'title', 'evidence', 'remediation'])
    def safe(value):
        value = str(value)
        return "'" + value if value.lstrip().startswith(('=', '+', '-', '@')) else value
    for f in report['findings']:
        writer.writerow([safe(x) for x in [report['target'], f['id'], f['severity'], f['confidence'], f['title'], ' | '.join(f['evidence']), f['remediation']]])
    return stream.getvalue().encode('utf-8-sig')


def pdf_report(report):
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
    stream = io.BytesIO()
    styles = getSampleStyleSheet()
    doc = SimpleDocTemplate(stream, title='External Surface Auditor report', author='External Surface Auditor')
    story = []
    def paragraph(text, style='BodyText'):
        story.append(Paragraph(escape(str(text)), styles[style]))
        story.append(Spacer(1, 8))
    paragraph('External Surface Auditor', 'Title')
    paragraph(report['target'], 'Heading1')
    paragraph(f"Environment: {report['environment']} | Completed: {report['completed_at']}")
    paragraph('Scoped observations for analyst review. These checks do not establish that an asset is exploitable.')
    paragraph('Summary: ' + ', '.join(f'{k}: {v}' for k, v in report['summary'].items()))
    for finding in report['findings']:
        paragraph(f"{finding['severity'].upper()}: {finding['title']}", 'Heading2')
        paragraph(f"Confidence: {finding['confidence']} | Category: {finding['category']}")
        paragraph(finding['summary'])
        for evidence in finding['evidence']:
            paragraph('Evidence: ' + evidence)
        paragraph('Remediation: ' + finding['remediation'])
    paragraph('Assessment limits', 'Heading2')
    for note in report['notes']:
        paragraph(note)
    paragraph('Approved scope snapshot: ' + str(report.get('scope_snapshot', {})))
    doc.build(story)
    return stream.getvalue()


def compare_reports(current, previous):
    old = {f['id']: f for f in previous['findings']}
    new = {f['id']: f for f in current['findings']}
    return {'new': sorted(new.keys() - old.keys()), 'not_observed': sorted(old.keys() - new.keys()), 'unchanged': sorted(k for k in new.keys() & old.keys() if new[k] == old[k]), 'changed': sorted(k for k in new.keys() & old.keys() if new[k] != old[k]), 'note': 'Not observed does not prove a fix; verify identical scope, connectivity and application state.'}
