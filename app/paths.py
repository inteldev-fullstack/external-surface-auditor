"""Separate packaged read-only resources from writable local user state."""
import os
import sys
from pathlib import Path


def resource_root():
    return Path(getattr(sys, '_MEIPASS', Path(__file__).resolve().parents[1]))


def user_state_root():
    if getattr(sys, 'frozen', False):
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / '.local' / 'share')) / 'ExternalSurfaceAuditor'
    return resource_root()


def data_directory():
    return Path(os.environ.get('ESA_DATA_DIR', user_state_root() / 'data'))


def default_scope_file():
    return user_state_root() / 'config' / 'approved_targets.json'
