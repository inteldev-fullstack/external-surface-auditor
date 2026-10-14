import json
import pytest
from app.scope import ScopeError, normalize_host, parse_scope, save_scope, load_scope, validate_resolved_address, validate_path

@pytest.mark.parametrize('host', ['https://example.test', '*.example.test', '127.0.0.1/24', 'localhost', 'example.test@other.test'])
def test_reject_invalid_target(host):
    with pytest.raises(ScopeError): normalize_host(host)

@pytest.mark.parametrize('ip', ['127.0.0.1', '::1', '169.254.169.254', '0.0.0.0', '224.0.0.1', '::ffff:127.0.0.1'])
def test_special_addresses_always_blocked(ip):
    with pytest.raises(ScopeError): validate_resolved_address(ip, True)

def test_private_requires_explicit_approval():
    with pytest.raises(ScopeError): validate_resolved_address('10.20.30.40', False)
    assert str(validate_resolved_address('10.20.30.40', True)) == '10.20.30.40'

@pytest.mark.parametrize('path', ['//other.test', '/a/../b', '/health?token=x', '/health#x', '/x\r\nHost: evil', '/x\\y'])
def test_invalid_paths(path):
    with pytest.raises(ScopeError): validate_path(path)

def test_invalid_update_does_not_replace_scope(tmp_path, monkeypatch):
    path=tmp_path/'scope.json'; monkeypatch.setenv('ESA_SCOPE_FILE',str(path))
    save_scope([{'host':'STAGING.Example.test.', 'environment':'staging', 'paths':['/health']}])
    before=path.read_bytes()
    with pytest.raises(ScopeError): save_scope([{'host':'example.test','environment':'production'}])
    assert path.read_bytes()==before
    assert load_scope()[0].host=='staging.example.test'
    with pytest.raises(ScopeError): parse_scope({'targets':[{'host':'a.test','environment':'lab'},{'host':'A.test','environment':'lab'}]})
