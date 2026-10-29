"""Auth + CSRF hardening tests (RED first).

Confirmed defect classes targeted:
* state-changing endpoints authenticated solely by cookie with no CSRF defence;
* bearer-authenticated requests exempt from CSRF (stateless);
* unauthenticated /pin has no rate limit (Falcоn-verify DoS) and pin sessions are
  never pruned;
* logout is an unauthenticated GET (CSRF logout);
* ALGV_PIN_GATE truthiness (any non-empty value enables the gate).
"""

from fastapi.testclient import TestClient


def test_login_issues_session_and_csrf_token(session_client):
    assert session_client.csrf, 'every session must carry a per-session CSRF token'


def test_put_settings_requires_csrf_header_when_cookie_authenticated(
    session_client, api, bearer
):
    c = session_client.client
    headers = {'Cookie': f'{api._COOKIE}={c.cookies[api._COOKIE]}'}
    r = c.put(
        '/v1/steps/decision/settings',
        json={'risk_threshold': 90},
        headers={**headers, 'Origin': 'https://evil.test', 'Sec-Fetch-Site': 'cross-site'},
    )
    assert r.status_code == 403


def test_cross_site_origin_blocked_on_state_changing_methods(session_client, bearer, api):
    c = session_client.client
    cookie = c.cookies[api._COOKIE]
    cases = [
        ('PUT', '/v1/steps/decision/settings', {'risk_threshold': 1}),
        ('DELETE', '/v1/steps/decision/settings', None),
        ('POST', '/logout', None),
    ]
    for method, path, json_body in cases:
        r = c.request(
            method, path,
            json=json_body,
            headers={
                'Cookie': f'{api._COOKIE}={cookie}',
                'Origin': 'https://evil.test',
                'Sec-Fetch-Site': 'cross-site',
                'X-Algv-Csrf': session_client.csrf,
            },
        )
        assert r.status_code == 403, f'{method} {path}: {r.status_code} {r.text}'


def test_bearer_request_not_blocked_by_csrf(client, api, bearer):
    api.detect = lambda: [{
        "step": "decision", "ref": "decision_ref", "order": 1,
        "package": "algovoi-spend-guardrail", "version": "0.1.0",
        "posture": "p", "default": {},
    }]
    c = client
    r = c.put(
        '/v1/steps/decision/settings',
        json={'risk_threshold': 1},
        headers={**bearer, 'Origin': 'https://evil.test', 'Sec-Fetch-Site': 'cross-site'},
    )
    assert r.status_code == 200, r.text


def test_same_origin_request_with_valid_csrf_passes(session_client, api):
    api.detect = lambda: [{
        "step": "decision", "ref": "decision_ref", "order": 1,
        "package": "algovoi-spend-guardrail", "version": "0.1.0",
        "posture": "p", "default": {},
    }]
    c = session_client.client
    r = c.put(
        '/v1/steps/decision/settings',
        json={'risk_threshold': 1},
        headers={
            'Cookie': f'{api._COOKIE}={c.cookies[api._COOKIE]}',
            'X-Algv-Csrf': session_client.csrf,
        },
    )
    assert r.status_code == 200, r.text


def test_invalid_csrf_header_rejected(session_client, api):
    c = session_client.client
    r = c.put(
        '/v1/steps/decision/settings',
        json={'risk_threshold': 1},
        headers={
            'Cookie': f'{api._COOKIE}={c.cookies[api._COOKIE]}',
            'X-Algv-Csrf': 'wrong-token',
        },
    )
    assert r.status_code == 403


def test_pin_endpoint_rate_limited(api):
    with TestClient(api.app, base_url='https://panel.test') as c:
        statuses = [c.post('/pin', data={'pin': 'bogus'}).status_code for _ in range(12)]
        assert 429 in statuses, statuses


def test_logout_is_post_only(session_client, api):
    c = session_client.client
    r_get = c.get('/logout', headers={'Cookie': f'{api._COOKIE}={c.cookies[api._COOKIE]}'})
    assert r_get.status_code == 405
    r_post = c.post('/logout', headers={'Cookie': f'{api._COOKIE}={c.cookies[api._COOKIE]}',
                                        'X-Algv-Csrf': session_client.csrf})
    assert r_post.status_code in (200, 303), r_post.text


def test_pin_gate_truthiness(api, monkeypatch):
    assert api._PIN_GATE is False
    monkeypatch.setenv('ALGV_PIN_GATE', '0')
    import importlib

    importlib.reload(api)
    assert api._PIN_GATE is False, 'ALGV_PIN_GATE=0 must disable the gate'
