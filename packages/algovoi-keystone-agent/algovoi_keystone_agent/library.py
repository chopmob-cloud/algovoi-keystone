"""Starter behaviours for algovoi-keystone-agent.

Ready-made, stateless rules and behaviour factories for the common cases, so a
policy is one call rather than a lambda. Every rule here is a pure function of a
single event, so it drops straight into ``check_rule`` / ``check_behaviour`` and
recomputes cleanly.

Each rule reads a field from the event top level and, failing that, from a nested
``kwargs`` map, so the same rule works on a flat stage record (a spend_decision)
and on a guarded keystone-connect call (where parameters arrive under ``kwargs``).
"""
from . import behaviour, rule, trigger

__all__ = [
    "spend_cap", "flag_over", "allow_list", "deny_list", "scope_fence",
    "require_fields",
    "on_charge", "on_write",
    "cap_charges", "flag_large_charges", "deny_writes_to", "restrict_scope",
]


def _get(event, field):
    """Field lookup: event top level first, then a nested ``kwargs`` map."""
    if field in event:
        return event[field]
    kwargs = event.get("kwargs")
    if isinstance(kwargs, dict) and field in kwargs:
        return kwargs[field]
    return None


# --------------------------------------------------------------------------- #
# Rules -- pure predicates to a verdict.
# --------------------------------------------------------------------------- #

def spend_cap(limit, *, field="amount"):
    """BLOCK when ``event[field]`` exceeds `limit`, else ALLOW."""
    return rule("spend_cap<=%s" % limit,
                lambda ev: "BLOCK" if (_get(ev, field) or 0) > limit else "ALLOW")


def flag_over(limit, *, field="amount"):
    """FLAG (do not block) when ``event[field]`` exceeds `limit`, else ALLOW."""
    return rule("flag_over>%s" % limit,
                lambda ev: "FLAG" if (_get(ev, field) or 0) > limit else "ALLOW")


def deny_list(field, values, *, verdict="BLOCK"):
    """`verdict` when ``event[field]`` is one of `values`, else ALLOW."""
    vals = set(values)
    return rule("deny_%s" % field,
                lambda ev: verdict if _get(ev, field) in vals else "ALLOW")


def allow_list(field, values, *, verdict="BLOCK"):
    """ALLOW only when ``event[field]`` is one of `values`, else `verdict`."""
    vals = set(values)
    return rule("allow_%s" % field,
                lambda ev: "ALLOW" if _get(ev, field) in vals else verdict)


def scope_fence(allowed, *, field="scope"):
    """ALLOW only when ``event[field]`` starts with one of the `allowed` prefixes."""
    prefixes = tuple(allowed)
    return rule("scope_fence",
                lambda ev: "ALLOW" if str(_get(ev, field) or "").startswith(prefixes) else "BLOCK")


def require_fields(*fields, verdict="BLOCK"):
    """ALLOW only when every field in `fields` is present and non-null."""
    req = tuple(fields)
    return rule("require:" + ",".join(req),
                lambda ev: "ALLOW" if all(_get(ev, f) is not None for f in req) else verdict)


# --------------------------------------------------------------------------- #
# Triggers -- common wake conditions.
# --------------------------------------------------------------------------- #

def on_charge(*, stage="spend_decision", action_type="charge"):
    return trigger(stage=stage, where=lambda ev: ev.get("action_type") == action_type)


def on_write(*, method=None, stage="execution"):
    if method is None:
        return trigger(stage=stage)
    return trigger(stage=stage, where=lambda ev: ev.get("method") == method)


# --------------------------------------------------------------------------- #
# Behaviours -- trigger + rule bound, ready for Engine([...]).
# --------------------------------------------------------------------------- #

def cap_charges(limit, *, field="amount", stage="spend_decision", action=None, name=None):
    """Block any charge whose amount exceeds `limit`."""
    return behaviour(name or ("cap_charges<=%s" % limit),
                     on=on_charge(stage=stage), rule=spend_cap(limit, field=field), action=action)


def flag_large_charges(limit, *, field="amount", stage="spend_decision", action=None, name=None):
    """Flag (record but allow) any charge whose amount exceeds `limit`."""
    return behaviour(name or ("flag_large_charges>%s" % limit),
                     on=on_charge(stage=stage), rule=flag_over(limit, field=field), action=action)


def deny_writes_to(field, values, *, stage="execution", method=None, action=None, name=None):
    """Deny any write whose `field` is one of `values` (e.g. a locked bucket or table)."""
    return behaviour(name or ("deny_writes_%s" % field),
                     on=on_write(method=method, stage=stage),
                     rule=deny_list(field, values), action=action)


def restrict_scope(allowed, *, field="scope", stage="execution", method=None, action=None, name=None):
    """Allow a write only when its scope starts with one of the `allowed` prefixes."""
    return behaviour(name or "restrict_scope",
                     on=on_write(method=method, stage=stage),
                     rule=scope_fence(allowed, field=field), action=action)
