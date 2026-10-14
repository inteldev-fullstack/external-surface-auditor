import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from app import scanner


def test_real_http_transport_pinned_head_no_redirect_or_cookie(monkeypatch):
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            seen.append((self.command,self.path,self.headers['Host']))
            self.send_response(302)
            self.send_header('Location','https://outside.test/secret?token=hidden')
            self.send_header('Set-Cookie','session=hidden')
            self.send_header('Server','synthetic-lab')
            self.send_header('Connection','close')
            self.end_headers()
        def do_GET(self):
            seen.append(('GET',self.path,self.headers['Host']))
            self.send_response(500); self.end_headers()
        def log_message(self,*args): pass
    server=ThreadingHTTPServer(('127.0.0.1',0),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    connection=scanner.PinnedHTTPConnection
    monkeypatch.setattr(scanner,'PinnedHTTPConnection',lambda host,address,port,timeout: connection(host,address,server.server_port,timeout))
    try:
        result=scanner._request_head('staging.example.test','127.0.0.1','/health',False)
        assert seen==[('HEAD','/health','staging.example.test')]
        assert result['status']==302
        assert result['redirect_host']=='outside.test'
        assert result['elapsed_ms'] >= 0
        assert 'hidden' not in str(result)
        assert 'set-cookie' not in result['headers']
    finally:
        server.shutdown(); server.server_close(); thread.join(timeout=2)
