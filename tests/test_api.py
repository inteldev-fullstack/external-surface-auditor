import copy
import threading
import time
import pytest
from app import main
from app.scanner import ScanCancelled

TARGET={'host':'staging.example.test','environment':'staging','paths':['/health'],'authorization_confirmed':True}

def approve(client):
    assert client.put('/api/scope/staging.example.test',json=TARGET).status_code==200

def wait(client,job_id):
    for _ in range(200):
        job=client.get('/api/scans/'+job_id).json()
        if job['state'] in {'completed','failed','cancelled'}: return job
        time.sleep(.01)
    pytest.fail('Job did not terminate')


def test_local_boundary(client):
    assert client.get('/api/health').status_code==200
    assert client.get('/',headers={'Host':'evil.test'}).status_code==400
    assert client.get('/api/scope',headers={'Origin':'https://evil.test'}).status_code==403
    assert client.get('/api/scope',headers={'Sec-Fetch-Site':'cross-site'}).status_code==403
    assert "script-src 'self'" in client.get('/').headers['content-security-policy']
    assert client.get('/static/unknown').status_code==404


def test_scope_crud_and_authorization(client):
    assert client.get('/api/scope').json()['targets']==[]
    assert client.put('/api/scope/staging.example.test',json={**TARGET,'authorization_confirmed':False}).status_code==400
    assert client.put('/api/scope/staging.example.test',json={**TARGET,'environment':'production'}).status_code==400
    approve(client)
    assert client.get('/api/scope').json()['targets'][0]['paths']==['/health']
    assert client.delete('/api/scope/staging.example.test').status_code==200
    assert not client.get('/api/scope').json()['targets']
    assert client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).status_code==403


def test_openapi_import_lists_only_concrete_read_only_paths(client):
    workspace=client.post('/api/workspaces',json={'name':'Customer A'}).json()
    response=client.post(f"/api/workspaces/{workspace['id']}/openapi/paths",json={'document_json':'''{
      "openapi":"3.1.0","paths":{
        "/health":{"get":{}},"/status":{"head":{}},
        "/users/{userId}":{"get":{}},"/mutate":{"post":{}},
        "//other-host/health":{"get":{}},"/bad/../path":{"get":{}}
      }
    }'''})
    assert response.status_code==200
    assert response.json()['paths']==['/health','/status']
    assert 'does not fetch' in response.json()['note']


@pytest.mark.parametrize('document', ['not-json', '{"openapi":"2.0","paths":{}}', '{"openapi":"3.0.0"}'])
def test_openapi_import_rejects_invalid_documents(client,document):
    workspace=client.post('/api/workspaces',json={'name':'Customer A'}).json()
    response=client.post(f"/api/workspaces/{workspace['id']}/openapi/paths",json={'document_json':document})
    assert response.status_code==400


def test_complete_export_compare_delete(client,monkeypatch,sample_report):
    def scan(entry,progress,cancelled):
        progress('Mock fixture checks')
        return copy.deepcopy(sample_report)
    monkeypatch.setattr(main,'scan_target',scan); approve(client)
    assert client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':False}).status_code==400
    first=client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True})
    assert first.status_code==202
    job_id=first.json()['id']; job=wait(client,job_id)
    assert job['state']=='completed'
    assert job['report']['scope_snapshot']['host']==TARGET['host']
    assert client.get(f'/api/scans/{job_id}/report/pdf').content.startswith(b'%PDF-')
    assert b'Header absent' in client.get(f'/api/scans/{job_id}/report/csv').content
    assert client.get(f'/api/scans/{job_id}/report/json').json()['job_id']==job_id
    assert client.get(f'/api/scans/{job_id}/report/invalid').status_code==400
    assert client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).status_code==429
    main._last.clear()
    second=client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).json()['id']
    retest=wait(client,second)
    assert retest['report']['comparison']['unchanged']==['header']
    assert client.delete('/api/scans/'+job_id).status_code==200
    assert client.get('/api/scans/'+job_id).status_code==404


def test_single_job_and_cancel(client,monkeypatch):
    entered=threading.Event()
    def scan(entry,progress,cancelled):
        entered.set()
        for _ in range(300):
            if cancelled(): raise ScanCancelled()
            time.sleep(.01)
        raise RuntimeError('test fixture timed out')
    monkeypatch.setattr(main,'scan_target',scan); approve(client)
    job_id=client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).json()['id']
    assert entered.wait(2)
    assert client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).status_code==409
    assert client.delete('/api/scans/'+job_id).status_code==409
    assert client.get(f'/api/scans/{job_id}/report/pdf').status_code==409
    assert client.post(f'/api/scans/{job_id}/cancel').status_code==200
    assert wait(client,job_id)['state']=='cancelled'


def test_scope_error_is_a_failed_job(client,monkeypatch):
    from app.scope import ScopeError
    def scan(*args): raise ScopeError('Special-use address blocked.')
    monkeypatch.setattr(main,'scan_target',scan); approve(client)
    job_id=client.post('/api/scans',json={'target':TARGET['host'],'authorization_confirmed':True}).json()['id']
    assert wait(client,job_id)['error']=='Special-use address blocked.'
