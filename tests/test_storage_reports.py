import csv
import io
from app.storage import Store
from app.reports import compare_reports, csv_report

def test_interrupted_jobs_persist(tmp_path):
    path=tmp_path/'data'/'test.db'; store=Store(path)
    store.create('job','a.test'); store.update('job','running','Checking DNS')
    restarted=Store(path)
    assert restarted.get('job')['state']=='interrupted'
    assert restarted.list()[0]['id']=='job'


def test_comparison_does_not_claim_fix(sample_report):
    current={**sample_report,'findings':[]}
    result=compare_reports(current,sample_report)
    assert result['not_observed']==['header']
    assert 'does not prove a fix' in result['note']


def test_csv_formula_neutralized(sample_report):
    sample_report['findings'][0]['title']=' =HYPERLINK("https://example.test")'
    rows=list(csv.reader(io.StringIO(csv_report(sample_report).decode('utf-8-sig'))))
    assert rows[1][4].startswith("'")
