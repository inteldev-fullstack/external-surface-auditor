import sys
from app.paths import data_directory, default_scope_file, resource_root

def test_frozen_state_separate_from_resources(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, '_MEIPASS', str(tmp_path/'bundle'), raising=False)
    monkeypatch.setenv('LOCALAPPDATA', str(tmp_path/'user'))
    monkeypatch.delenv('ESA_DATA_DIR', raising=False)
    assert resource_root()==tmp_path/'bundle'
    assert default_scope_file()==tmp_path/'user'/'ExternalSurfaceAuditor'/'config'/'approved_targets.json'
    assert data_directory()==tmp_path/'user'/'ExternalSurfaceAuditor'/'data'
