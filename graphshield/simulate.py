"""Inject publish events into the graph for the demo."""
import random
import time

from graphshield import queries as Q
from graphshield.db import get_graph
from graphshield.seed import TARGET

# The attacker quietly gets co-maintainer rights here too, for a later strike.
SECOND_TARGET = "tiny-utf8"


def _next_patch() -> str:
    return f"1.9.{random.randint(1, 999)}"


def _publish(g, handle: str, pkg: str, install_script: bool) -> str:
    number = _next_patch()
    g.query(Q.PUBLISH_VERSION, {"handle": handle, "pkg": pkg, "id": f"{pkg}@{number}",
                                "number": number, "has_install_script": install_script})
    return f"{pkg}@{number}"


def simulate_attack(pkg: str = TARGET) -> str:
    """A 2-day-old, unverified account takes over `pkg` and pushes a version with an install script.

    It is also added to SECOND_TARGET without publishing: the staging the Investigator should find.
    """
    g = get_graph()
    handle = f"helpful-dev-{random.randint(1000, 9999)}"
    g.query(Q.UPSERT_MAINTAINER, {"handle": handle, "verified": False, "mfa": False,
                                  "created_at": int(time.time() * 1000) - 2 * Q.DAY_MS})
    for p in (pkg, SECOND_TARGET):
        g.query(Q.GRANT_MAINTAINER, {"handle": handle, "pkg": p})
    return _publish(g, handle, pkg, install_script=True)


def simulate_repeat_attack(pkg: str = SECOND_TARGET) -> str:
    """The most recent attacker account strikes again, on the package it was staged on."""
    g = get_graph()
    rows = g.ro_query(Q.LATEST_NEW_ACCOUNT).result_set
    if not rows:
        raise ValueError("No attacker account yet. Run the attack first.")
    return _publish(g, rows[0][0], pkg, install_script=True)


def simulate_takeover(pkg: str = TARGET) -> str:
    """Account takeover: the package's long-dormant, trusted maintainer suddenly ships an install script.

    No new account and no new maintainer, so the obvious signals stay quiet.
    """
    g = get_graph()
    owner = g.ro_query(
        "MATCH (m:Maintainer)-[:MAINTAINS]->(:Package {name: $pkg}) "
        "WHERE NOT m.handle STARTS WITH 'helpful-dev-' "
        "RETURN m.handle ORDER BY m.created_at LIMIT 1", {"pkg": pkg}).result_set[0][0]
    return _publish(g, owner, pkg, install_script=True)


def simulate_legit_release(pkg: str = "semver-check") -> str:
    """An existing long-standing maintainer ships a normal patch."""
    g = get_graph()
    owner = g.ro_query(
        "MATCH (m:Maintainer)-[:MAINTAINS]->(:Package {name: $pkg}) "
        "RETURN m.handle ORDER BY m.verified DESC, m.mfa DESC, m.created_at LIMIT 1", {"pkg": pkg}).result_set[0][0]
    return _publish(g, owner, pkg, install_script=False)
