"""Settings-store robustness tests (RED first).

Confirmed defect classes targeted:
* ``open()`` without ``encoding=\"utf-8\"`` and an exception set that misses
  ``UnicodeDecodeError``/``OSError`` -> a hand-edited settings file with non-ASCII
  (or permission errors) 500s every panel render;
* non-atomic ``path + ".tmp"`` write + no file/dir permissions -> concurrent writers
  lose updates, local users can read settings/licence tokens, tmp files linger;
* no body-size / nesting cap on ``PUT /v1/steps/{step}/settings`` -> disk exhaustion
  or deep-recursion DoS via stored JSON.
"""


def test_store_survives_utf8_and_corrupt_files(tmp_path):
    from algovoi_keystone_control.store import SettingsStore

    p = tmp_path / 'settings.json'
    p.write_text('{"decision": {"risk_threshold": 70, "note": "héllo"}}', encoding='utf-8')
    store = SettingsStore(str(p))
    # valid JSON with non-ASCII loads fine
    assert store.get('decision', {'x': 1})['risk_threshold'] == 70
    p.write_text('{not json', encoding='utf-8')
    assert store.all() == {}
    p.write_bytes(b'\xff\xfe\x00bad')
    assert store.all() == {}
    p.unlink()
    assert store.all() == {}


def test_store_atomic_write_with_restrictive_perms(tmp_path):
    from algovoi_keystone_control.store import SettingsStore
    import sys

    p = tmp_path / 'settings.json'
    store = SettingsStore(str(p))
    store.put('decision', {'risk_threshold': 70})
    assert not p.with_name(p.name + '.tmp').exists()
    assert p.is_file()
    if sys.platform != 'win32':
        import stat, os

        mode = stat.S_IMODE(os.stat(p).st_mode)
        assert mode == 0o600, oct(mode)


def test_settings_put_rejects_oversized_body(api):
    api.detect = lambda: [{
        "step": "decision", "ref": "decision_ref", "order": 1,
        "package": "algovoi-spend-guardrail", "version": "0.1.0",
        "posture": "p", "default": {},
    }]
    with TestClient(api.app, base_url='https://panel.test') as c:
        big = {'k': 'x' * 2_000_000}
        r = c.put('/v1/steps/decision/settings', json=big,
                  headers={'Authorization': 'Bearer ' + api._TOKEN})
        assert r.status_code == 413, r.status_code


def test_settings_put_rejects_deeply_nested_body(api):
    api.detect = lambda: [{
        "step": "decision", "ref": "decision_ref", "order": 1,
        "package": "algovoi-spend-guardrail", "version": "0.1.0",
        "posture": "p", "default": {},
    }]
    with TestClient(api.app, base_url='https://panel.test') as c:
        nested = {}
        cur = nested
        for _ in range(900):
            cur['x'] = {}
            cur = cur['x']
        r = c.put('/v1/steps/decision/settings', json=nested,
                  headers={'Authorization': 'Bearer ' + api._TOKEN})
        assert r.status_code == 400, r.status_code


from fastapi.testclient import TestClient
