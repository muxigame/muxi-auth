"""Aggregate, read-only counts about QQ / WeChat bindings in production.

Runs inside the container (python -B -c). The repository is public, so it
prints counts only: no ids, names, subjects, timestamps finer than a day.
"""
import collections
import json
import re
import sqlite3
import sys

sys.path.insert(0, "/app")
from app.external_identity import upstream_subject  # noqa: E402

db = sqlite3.connect("file:/app/data/muxi-auth.db?mode=ro", uri=True)
db.row_factory = sqlite3.Row
q = lambda sql, *a: db.execute(sql, a).fetchall()


def show(title, rows):
    print(f"-- {title}")
    for r in rows:
        print("  ", tuple(r))


show("identities by provider", q("SELECT provider, COUNT(*) FROM external_identities GROUP BY provider"))
show("identities missing upstream_subject", q("SELECT provider, COUNT(*) FROM external_identities WHERE upstream_subject IS NULL GROUP BY provider"))
show("accounts by channel set", q("""SELECT chans, COUNT(*) FROM (SELECT account_id, GROUP_CONCAT(provider) chans
    FROM (SELECT account_id, provider FROM external_identities ORDER BY provider) GROUP BY account_id) GROUP BY chans"""))
show("accounts with password / without", q("""SELECT password_hash IS NOT NULL, COUNT(*) FROM accounts GROUP BY 1"""))
show("czl subject shared by >1 account", q("""SELECT COUNT(*) FROM (SELECT provider_subject FROM external_identities
    GROUP BY provider_subject HAVING COUNT(DISTINCT account_id) > 1)"""))
show("binding events", q("SELECT provider, action, COUNT(*) FROM external_binding_events GROUP BY provider, action"))
show("binding events by day", q("SELECT substr(created_at,1,10) d, provider, action, COUNT(*) FROM external_binding_events GROUP BY d, provider, action ORDER BY d"))
show("binding pending rows", q("SELECT provider, expected_id IS NOT NULL, COUNT(*) FROM external_binding_pending GROUP BY 1, 2"))
show("unconsumed oauth states", q("SELECT provider, purpose, COUNT(*) FROM external_oauth_states GROUP BY provider, purpose"))
show("signups waiting", q("SELECT provider, COUNT(*) FROM external_signups GROUP BY provider"))

# Upstream shapes CZL returns (keys and types only, never values).
shapes = collections.Counter()
recheck = collections.Counter()
for r in q("SELECT provider, raw_profile, upstream_subject FROM external_identities"):
    try:
        profile = json.loads(r["raw_profile"] or "{}")
    except ValueError:
        shapes[(r["provider"], "unparseable")] += 1
        continue
    ups = profile.get("upstreams") if isinstance(profile, dict) else None
    kinds = sorted(str(u.get("upstream_type") or u.get("provider") or u.get("type") or "?") for u in ups or [] if isinstance(u, dict))
    keys = sorted({k for u in ups or [] if isinstance(u, dict) for k in u})
    shapes[(r["provider"], ",".join(kinds), ",".join(keys))] += 1
    if r["provider"] in ("qq", "wechat"):
        now = upstream_subject(profile, r["provider"])
        kind = lambda s: (s or "none").split(":", 1)[0]
        recheck[(r["provider"], "stored=" + kind(r["upstream_subject"]), "now=" + kind(now), "same" if now == r["upstream_subject"] else "DIFF")] += 1
print("-- upstream shapes (provider, kinds, keys) -> count")
for k, v in sorted(shapes.items()):
    print("  ", k, v)
print("-- stored upstream subject vs re-derived today")
for k, v in sorted(recheck.items()):
    print("  ", k, v)
