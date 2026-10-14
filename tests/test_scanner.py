import pytest
from app import scanner
from app.scope import ScopeEntry, ScopeError


def test_pins_single_address_and_checks_only_approved_paths(monkeypatch):
    monkeypatch.setattr(scanner, '_resolve', lambda *args: (['93.184.216.34','93.184.216.35'], {'A':['93.184.216.34']}, []))
    monkeypatch.setattr(scanner, 'REQUEST_DELAY', 0)
    calls=[]
    def head(host,address,path,use_tls):
        calls.append((host,address,path,use_tls))
        return {'scheme':'https' if use_tls else 'http','path':path,'status':503 if path=='/health' else 200,'headers':{'content-type':'text/html'},'tls':None,'error':None,'redirect_host':'other.test','redirect_scheme':'https'}
    monkeypatch.setattr(scanner,'_request_head',head)
    report=scanner.scan_target(ScopeEntry('staging.example.test','lab',('/health',),False))
    assert calls==[('staging.example.test','93.184.216.34','/',False),('staging.example.test','93.184.216.34','/',True),('staging.example.test','93.184.216.34','/health',True)]
    assert {'browser-security-headers','http-5xx-https-/health'} <= {f['id'] for f in report['findings']}


def test_cancel_sends_no_more_requests(monkeypatch):
    sent=[]
    monkeypatch.setattr(scanner,'_request_head',lambda *a,**k: sent.append(a))
    with pytest.raises(scanner.ScanCancelled):
        scanner.scan_target(ScopeEntry('a.test','lab',(),False),cancelled=lambda:True)
    assert not sent


def test_tls_metadata_survives_connection_close(monkeypatch):
    class Sock:
        def getpeercert(self): return {'notAfter':'Dec 31 23:59:59 2030 GMT'}
        def version(self): return 'TLSv1.3'
    class Response:
        status=200; reason='OK'
        def getheaders(self): return [('Content-Type','text/html'),('Set-Cookie','secret'),('Location','https://outside.test/token?secret=x')]
        def getheader(self,key): return 'https://outside.test/token?secret=x' if key=='Location' else None
    class Connection:
        def __init__(self,*args): self.sock=None
        def connect(self): self.sock=Sock()
        def request(self,*args,**kwargs): assert args[0]=='HEAD'
        def getresponse(self): self.sock=None; return Response()
        def close(self): pass
    monkeypatch.setattr(scanner,'PinnedHTTPSConnection',Connection)
    result=scanner._request_head('a.test','93.184.216.34','/',True)
    assert result['tls']['version']=='TLSv1.3'
    assert result['tls']['certificate_verified'] is True
    assert 'set-cookie' not in result['headers']
    assert 'secret' not in str(result)
    assert result['redirect_host']=='outside.test'
