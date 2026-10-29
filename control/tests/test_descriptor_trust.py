"""Descriptor / package-install supply-chain tests (RED first).

Confirmed defect classes targeted:
* untrusted vendor descriptors (``algovoi.keystone.steps`` entry points) are accepted
  unvalidated and their ``packages`` strings are rendered verbatim into a copy-pasteable
  ``pip install <name>`` command -> shell injection into operator copy-paste;
* a vendor descriptor can shadow a canonical catalogue step via an attacker-chosen
  ``order``, so ``PUT /v1/steps/decision/settings`` lands on the wrong descriptor;
* ``order`` / field types are not coerced -> a non-int ``order`` raises TypeError and
  500s every panel render / /v1/steps call;
* vendor refs can collide with canonical refs without detection.
"""
import importlib
import sys
import tempfile
from pathlib import Path


def test_vendor_package_names_do_not_leak_shell_metacharacters(
    client, bearer, malicious_bolt
):
    r = client.get('/', headers=bearer)
    assert r.status_code == 200, r.text
    html = r.text
    # Only the install guidance is shell-executed by an operator copy-paste; every
    # rendered package name must be a bare, normalised name.
    for token in __import__('re').findall(r'pip install ([^<"\s]+)', html):
        assert __import__('re').match(r"^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$", token), token


def test_vendor_descriptor_cannot_shadow_canonical_step(
    client, bearer, malicious_bolt, api
):
    # The bolt-on (registered via the malicious_bolt fixture) declares step
    # 'decision' / ref 'decision_ref' with order 1. A catalogue 'decision' row
    # whose package happens to be installed must win and the bolt excluded.
    root = Path(tempfile.mkdtemp())
    write_fake_dist(root, 'algovoi-spend-guardrail', 'algovoi.keystone.steps', 'unused',
                    'def describe():\n    return {\n        "step": "unused", "ref": "unused_ref",\n        "posture": "Bolt-on",\n        "package": "algovoi-spend-guardrail",\n        "packages": ["algovoi-spend-guardrail"],\n        "order": 99,\n        "default": {},\n    }\n')
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    try:
        r = client.get('/v1/steps', headers=bearer)
        assert r.status_code == 200, r.text
        steps = r.json()["steps"]
        decisions = [s for s in steps if s["step"] == "decision"]
        assert len(decisions) == 1, decisions
        assert decisions[0]["order"] == 5, decisions
        assert decisions[0]["package"] == "algovoi-spend-guardrail", decisions
        assert all("bolt" not in str(s.get("provider", "")) for s in steps)
    finally:
        sys.path.remove(str(root))
        importlib.invalidate_caches()


def test_vendor_descriptor_passes_through_when_valid_and_unique(
    client, bearer, api
):
    # A well-formed bolt-on with a unique step/ref still shows up.
    root = Path(tempfile.mkdtemp())
    write_fake_dist(root, 'algovoi-bolt-sentinel', 'algovoi.keystone.steps',
                    'sentinel', 'def describe():\n    return {\n        "step": "sentineltest", "ref": "sentineltest_ref",\n        "posture": "Bolt-on",\n        "package": "algovoi-bolt-sentinel",\n        "packages": ["algovoi-bolt-sentinel"],\n        "order": 3,\n        "default": {},\n    }\n')
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    try:
        r = client.get('/v1/steps', headers=bearer)
        assert r.status_code == 200, r.text
        assert any(s["step"] == "sentineltest" for s in r.json()["steps"])
    finally:
        sys.path.remove(str(root))
        importlib.invalidate_caches()


def test_install_command_is_shell_safe(api):
    assert api._install_cmd({"packages": ["algovoi-bolt-evil; rm -rf /"]}) == (
        '<span class="mut">— no publishable package name —</span>')
    assert api._install_cmd({"packages": ["algovoi-bolt-evil"]}) == "pip install algovoi-bolt-evil"
    assert api._install_cmd({"packages": ["algovoi-bolt-evil; rm -rf /",
                                          "algovoi-good-pkg"]}) == "pip install algovoi-good-pkg"
    assert api._install_cmd({"package": "weird name!"}) == (
        '<span class="mut">— no publishable package name —</span>')
    assert api._install_pkg({"packages": ["a;b", "c&d"]}) == ""


def test_non_int_order_does_not_500(client, bearer):
    root = __import__('pathlib').Path(
        __import__('tempfile').mkdtemp()
    )
    import importlib, sys

    src = (
        'def describe():\n'
        '    return {\n'
        "        'step': 'weird', 'ref': 'weird_ref', 'posture': 'Bolt-on',\n"
        "        'package': 'algovoi-bolt-weird',\n"
        "        'order': 'not-an-int',\n"
        "        'default': {},\n"
        '    }\n'
    )
    write_fake_dist(root, 'algovoi-bolt-weird', 'algovoi.keystone.steps', 'weird', src)
    sys.path.insert(0, str(root))
    importlib.invalidate_caches()
    try:
        r = client.get('/v1/steps', headers=bearer)
        assert r.status_code == 200, r.text
    finally:
        sys.path.remove(str(root))
        importlib.invalidate_caches()


def write_fake_dist(root, package, entry_point_group, entry_point_name, descriptor_src,
                    version='1.0.0'):
    import importlib

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
