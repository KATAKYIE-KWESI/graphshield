"""Seed a synthetic package registry: 5 core utils -> 15 libs -> 30 frameworks -> 100 apps.

Run:  python -m graphshield.seed
"""
import random
import time

from graphshield import queries as Q
from graphshield.db import get_graph

TARGET = "left-pad-core"

CORE = [TARGET, "is-buffer-lite", "tiny-utf8", "ms-parse", "kind-of-core"]
LIBS = [
    "str-utils", "path-normalize", "deep-merge", "arg-parse-mini", "color-convert-x",
    "semver-check", "glob-lite", "debounce-fn", "uuid-tiny", "json-safe",
    "url-join-plus", "env-loader", "log-format", "chalk-lite", "retry-promise",
]
FRAMEWORKS = [
    "webkit-router", "form-kit", "orm-lite", "auth-flow", "cli-builder", "test-runner-x",
    "bundle-pack", "css-in-js-mini", "state-store", "http-client-pro", "i18n-kit",
    "graphql-lite", "date-wizard", "upload-kit", "charts-core", "markdown-render",
    "mailer-kit", "queue-worker", "cache-layer", "validation-kit", "socket-hub",
    "image-resize", "pdf-maker", "crypto-helpers", "config-store", "event-bus",
    "rate-limiter", "feature-flags", "search-index", "payments-sdk",
]
APP_PREFIX = ["acme", "globex", "initech", "umbrella", "stark", "wayne", "hooli",
              "piedpiper", "vandelay", "soylent"]
APP_SUFFIX = ["checkout", "dashboard", "api", "mobile-bff", "admin", "billing",
              "search", "auth-svc", "notifications", "reports"]
APPS = [f"{p}-{s}" for p in APP_PREFIX for s in APP_SUFFIX]  # 100 apps


def build(rng: random.Random, now_ms: int):
    day = Q.DAY_MS
    packages, deps, maintainers, maintains, versions = [], [], [], [], []

    for tier, (names, kind) in enumerate(
        [(CORE, "library"), (LIBS, "library"), (FRAMEWORKS, "library"), (APPS, "app")]
    ):
        for n in names:
            packages.append({"name": n, "kind": kind, "tier": tier,
                             "weekly_downloads": rng.randint(5_000, 5_000_000) // (tier + 1)})

    # Dependency edges (dependent -> dependency). Most libs lean on left-pad-core.
    for lib in LIBS:
        picks = {TARGET} if rng.random() < 0.7 else set()
        picks |= set(rng.sample(CORE[1:], rng.randint(1, 2)))
        deps += [{"src": lib, "dst": d} for d in picks]
    for i, fw in enumerate(FRAMEWORKS):
        picks = set(rng.sample(LIBS, rng.randint(2, 3)))
        deps += [{"src": fw, "dst": d} for d in picks]
        if i > 0 and rng.random() < 0.3:  # framework-on-framework adds depth
            deps.append({"src": fw, "dst": rng.choice(FRAMEWORKS[:i])})
    for app in APPS:
        picks = set(rng.sample(FRAMEWORKS, rng.randint(2, 4)))
        deps += [{"src": app, "dst": d} for d in picks]

    # Established maintainers. left-pad-core's sole maintainer is old and inactive:
    # exactly the kind of account attackers go after.
    maintainers.append({"handle": "oldtimer-sam", "created_at": now_ms - 3200 * day,
                        "last_active_at": now_ms - 700 * day, "verified": True, "mfa": False})
    handles = [f"dev-{i:02d}" for i in range(40)]
    for h in handles:
        maintainers.append({"handle": h, "created_at": now_ms - rng.randint(400, 4000) * day,
                            "last_active_at": now_ms - rng.randint(0, 90) * day,
                            "verified": rng.random() < 0.85, "mfa": rng.random() < 0.8})

    created = {m["handle"]: m["created_at"] for m in maintainers}
    for p in packages:
        owners = ["oldtimer-sam"] if p["name"] == TARGET else rng.sample(handles, rng.randint(1, 2))
        for h in owners:
            since = created[h] + rng.randint(30, 300) * day
            maintains.append({"handle": h, "pkg": p["name"], "since": min(since, now_ms - 60 * day)})
        for minor in range(rng.randint(2, 3)):
            versions.append({
                "id": f"{p['name']}@1.{minor}.0", "number": f"1.{minor}.0", "pkg": p["name"],
                "handle": owners[0], "published_at": now_ms - (900 - minor * 200) * day,
                "has_install_script": False,
            })

    return packages, deps, maintainers, maintains, versions


def seed(seed_value: int = 42) -> dict:
    g = get_graph()
    try:
        g.delete()
    except Exception:
        pass  # graph did not exist yet
    for q in Q.INDEXES:
        g.query(q)

    packages, deps, maintainers, maintains, versions = build(
        random.Random(seed_value), int(time.time() * 1000))
    g.query(Q.SEED_PACKAGES, {"rows": packages})
    g.query(Q.SEED_MAINTAINERS, {"rows": maintainers})
    g.query(Q.SEED_DEPENDS_ON, {"rows": deps})
    g.query(Q.SEED_MAINTAINS, {"rows": maintains})
    g.query(Q.SEED_VERSIONS, {"rows": versions})
    return {"packages": len(packages), "depends_on": len(deps),
            "maintainers": len(maintainers), "versions": len(versions)}


if __name__ == "__main__":
    print("Seeded:", seed())
