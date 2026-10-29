import importlib
import secrets
import sys

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv('ALGV_DATA_DIR', str(tmp_path))
    monkeypatch.setenv('ALGV_SETTINGS_PATH', str(tmp_path / 'settings.json'))
    monkeypatch.setenv('ALGV_ALIASES_PATH', str(tmp_path / 'aliases.json'))
    monkeypatch.setenv('ALGV_ADMIN_TOKEN', secrets.token_urlsafe(32))
    monkeypatch.delenv('ALGV_PIN_GATE', raising=False)
    sys.modules.pop('algovoi_keystone_control.api', None)
    module = importlib.import_module('algovoi_keystone_control.api')
    return module


@pytest.fixture
def client(api):
    with TestClient(api.app, base_url='https://panel.test', follow_redirects=False) as client:
        yield client


@pytest.fixture
def bearer(api):
    return {'Authorization': 'Bearer ' + api._TOKEN}


def login(client, api):
    r = client.post('/login', data={'password': api._TOKEN})
    assert r.status_code == 303, r.text
    return client.cookies.get(api._COOKIE)


def csrf_of(api, token):
    """Read the per-session CSRF token from the api module's session store."""
    return api._SESSIONS[token]['csrf']


@pytest.fixture
def session_client(api):
    """A client holding a cookie session plus its CSRF token."""
    import types
    with TestClient(api.app, base_url='https://panel.test', follow_redirects=False) as client:
        login(client, api)
        token = client.cookies.get(api._COOKIE)
        yield types.SimpleNamespace(client=client, csrf=csrf_of(api, token))


def write_fake_dist(root, package, entry_point_group, entry_point_name, descriptor_src,
                    version='1.0.0'):
    """Create an importable fake distribution that registers an entry point.

    This is how an untrusted third-party bolt-on reaches ``detect()``: it ships a
    ``.dist-info`` directory plus an entry point callable. Nothing about it is vetted
    by the panel, so the descriptor it returns is attacker-controlled input.
    """
    root.mkdir(parents=True, exist_ok=True)
    module_name = 'bolt_' + entry_point_name.replace('-', '_')
    (root / f'{module_name}.py').write_text(descriptor_src, encoding='utf-8')
    dist_info = root / f"{package.replace('-', '_')}-{version}.dist-info"
    dist_info.mkdir(exist_ok=True)
    (dist_info / 'METADATA').write_text(
        f'Metadata-Version: 2.1\nName: {package}\nVersion: {version}\n', encoding='utf-8')
    (dist_info / 'entry_points.txt').write_text(
        f'[{entry_point_group}]\n{entry_point_name} = {module_name}:describe\n',
        encoding='utf-8')
    return root


@pytest.fixture
def malicious_bolt(tmp_path, monkeypatch):
    """A bolt-on whose descriptor is hostile but structurally valid."""
    root = write_fake_dist(
        tmp_path / 'evil_site', 'algovoi-bolt-evil', 'algovoi.keystone.steps', 'evil',
        'def describe():\n'
        '    return {\n'
        "        'step': 'decision', 'ref': 'decision_ref', 'posture': 'Bolt-on',\n"
        "        'package': 'algovoi-bolt-evil',\n"
        "        'order': 1,\n"
        "        'packages': ['algovoi-bolt-evil'],\n"
        "        'default': {},\n"
        '    }\n')
    monkeypatch.syspath_prepend(str(root))
    importlib.invalidate_caches()
    yield root
    importlib.invalidate_caches()
