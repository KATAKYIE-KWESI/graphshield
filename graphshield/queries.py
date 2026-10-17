"""Every Cypher query GraphShield depends on, in one place.

Graph model
-----------
(:Maintainer)-[:PUBLISHED]->(:Version)-[:PART_OF]->(:Package)
(:Maintainer)-[:MAINTAINS {since}]->(:Package)
(:Package)-[:DEPENDS_ON]->(:Package)          # dependent -> dependency
(:Decision)-[:EVALUATED]->(:Version)          # agent memory
(:Decision)-[:CITED]->(:Maintainer|:Package)  # evidence the decision used
(:Investigation)-[:INVESTIGATED]->(:Decision) # Investigator agent's report
(:Investigation)-[:FLAGGED]->(:Maintainer)    # accounts it flagged

Timestamps are epoch milliseconds so they compare directly with timestamp().
"""

DAY_MS = 86_400_000

# --- schema -----------------------------------------------------------------

INDEXES = [
    "CREATE INDEX FOR (p:Package) ON (p.name)",
    "CREATE INDEX FOR (m:Maintainer) ON (m.handle)",
    "CREATE INDEX FOR (v:Version) ON (v.id)",
    "CREATE INDEX FOR (d:Decision) ON (d.id)",
]

# --- seeding (batched with UNWIND) -------------------------------------------

SEED_MAINTAINERS = """
UNWIND $rows AS r
CREATE (:Maintainer {handle: r.handle, created_at: r.created_at,
                     last_active_at: r.last_active_at,
                     verified: r.verified, mfa: r.mfa})
"""

SEED_PACKAGES = """
UNWIND $rows AS r
CREATE (:Package {name: r.name, kind: r.kind, tier: r.tier,
                  weekly_downloads: r.weekly_downloads})
"""

SEED_DEPENDS_ON = """
UNWIND $rows AS r
MATCH (a:Package {name: r.src}), (b:Package {name: r.dst})
CREATE (a)-[:DEPENDS_ON]->(b)
"""

SEED_MAINTAINS = """
UNWIND $rows AS r
MATCH (m:Maintainer {handle: r.handle}), (p:Package {name: r.pkg})
CREATE (m)-[:MAINTAINS {since: r.since}]->(p)
"""

SEED_VERSIONS = """
UNWIND $rows AS r
MATCH (m:Maintainer {handle: r.handle}), (p:Package {name: r.pkg})
CREATE (m)-[:PUBLISHED {at: r.published_at}]->
       (:Version {id: r.id, number: r.number, published_at: r.published_at,
                  has_install_script: r.has_install_script, status: 'released'})
       -[:PART_OF]->(p)
"""

# --- live events (used by the simulator) -------------------------------------

UPSERT_MAINTAINER = """
MERGE (m:Maintainer {handle: $handle})
ON CREATE SET m.created_at = $created_at, m.last_active_at = timestamp(),
              m.verified = $verified, m.mfa = $mfa
"""

GRANT_MAINTAINER = """
MATCH (m:Maintainer {handle: $handle}), (p:Package {name: $pkg})
MERGE (m)-[r:MAINTAINS]->(p)
ON CREATE SET r.since = timestamp()
"""

# prev_active_at keeps when the publisher was last seen *before* this release,
# so the agent can spot a long-dormant account that suddenly wakes up.
PUBLISH_VERSION = """
MATCH (m:Maintainer {handle: $handle}), (p:Package {name: $pkg})
WITH m, p, coalesce(m.last_active_at, timestamp()) AS prev_active
CREATE (m)-[:PUBLISHED {at: timestamp()}]->
       (v:Version {id: $id, number: $number, published_at: timestamp(),
                   prev_active_at: prev_active,
                   has_install_script: $has_install_script, status: 'pending'})
       -[:PART_OF]->(p)
SET m.last_active_at = timestamp()
RETURN v.id
"""

# --- agent steps --------------------------------------------------------------

# 1. Who published what?
PUBLISH_CONTEXT = """
MATCH (m:Maintainer)-[:PUBLISHED]->(v:Version {id: $vid})-[:PART_OF]->(p:Package)
RETURN m.handle AS maintainer, p.name AS package, v.number AS version,
       v.has_install_script AS has_install_script,
       (v.published_at - coalesce(v.prev_active_at, v.published_at)) / 86400000 AS dormant_days
"""

# 2. How much do we trust the publisher? (account age, MFA, tenure on THIS package)
MAINTAINER_TRUST = """
MATCH (m:Maintainer {handle: $handle})
OPTIONAL MATCH (m)-[r:MAINTAINS]->(:Package {name: $pkg})
OPTIONAL MATCH (m)-[:PUBLISHED]->(v:Version)
RETURN (timestamp() - m.created_at) / 86400000 AS account_age_days,
       m.verified AS verified, m.mfa AS mfa,
       (timestamp() - r.since) / 86400000 AS days_as_maintainer,
       count(v) AS versions_published,
       coalesce(m.flagged, false) AS flagged, m.flag_reason AS flag_reason
"""

# 3. Trust propagation: is this maintainer vouched for by established peers
#    through co-maintainership on OTHER packages? The co-maintainership itself must be
#    established (> 90 days): a fresh grant is exactly how attackers borrow trust.
PEER_VOUCHES = """
MATCH (m:Maintainer {handle: $handle})-[r:MAINTAINS]->(p:Package)<-[:MAINTAINS]-(peer:Maintainer)
WHERE p.name <> $pkg AND peer.handle <> m.handle
  AND timestamp() - r.since > 90 * 86400000
  AND peer.verified = true
  AND timestamp() - peer.created_at > 365 * 86400000
RETURN count(DISTINCT peer) AS vouching_peers
"""

# 4. Blast radius: everything that transitively depends on the package.
BLAST_RADIUS = """
MATCH (dep:Package)-[:DEPENDS_ON*1..5]->(t:Package {name: $pkg})
WITH collect(DISTINCT dep) AS deps
RETURN size(deps) AS total_dependents,
       size([d IN deps WHERE d.kind = 'app']) AS apps_affected,
       reduce(s = 0, d IN deps | s + d.weekly_downloads) AS weekly_downloads_at_risk
"""

# 5. Show the deepest real chains from an app down to the package.
ATTACK_PATHS = """
MATCH path = (a:Package {kind: 'app'})-[:DEPENDS_ON*1..5]->(t:Package {name: $pkg})
RETURN [n IN nodes(path) | n.name] AS chain, length(path) AS hops
ORDER BY hops DESC
LIMIT 5
"""

# 6. Memory: what has the agent decided before about this maintainer / package?
PRIOR_DECISIONS = """
MATCH (m:Maintainer {handle: $handle}), (p:Package {name: $pkg})
OPTIONAL MATCH (d1:Decision)-[:CITED]->(m)
WHERE d1.verdict <> 'ALLOW'
WITH p, count(d1) AS maintainer_flags
OPTIONAL MATCH (d2:Decision)-[:CITED]->(p)
WHERE d2.verdict <> 'ALLOW'
RETURN maintainer_flags, count(d2) AS package_flags
"""

# 7. Persist the decision and its evidence back into the graph.
RECORD_DECISION = """
MATCH (m:Maintainer {handle: $handle})-[:PUBLISHED]->(v:Version {id: $vid})-[:PART_OF]->(p:Package)
CREATE (d:Decision {id: $did, verdict: $verdict, risk: $risk, impact: $impact,
                    reasons: $reasons, at: timestamp(),
                    needs_investigation: $needs_investigation})
CREATE (d)-[:EVALUATED]->(v), (d)-[:CITED]->(m), (d)-[:CITED]->(p)
SET v.status = $status
RETURN d.id
"""

# --- simulator helpers ---------------------------------------------------------

LATEST_NEW_ACCOUNT = """
MATCH (m:Maintainer)
WHERE m.handle STARTS WITH 'helpful-dev-'
RETURN m.handle ORDER BY m.last_active_at DESC LIMIT 1
"""

# --- Investigator agent (coordinates with the Gatekeeper through the graph) ---

# The Gatekeeper leaves BLOCK / QUARANTINE decisions open; the Investigator picks them up.
OPEN_CASES = """
MATCH (d:Decision {needs_investigation: true})
RETURN d.id AS decision_id ORDER BY d.at DESC
"""

CASE_FILE = """
MATCH (d:Decision {id: $did})-[:EVALUATED]->(v:Version)-[:PART_OF]->(p:Package),
      (m:Maintainer)-[:PUBLISHED]->(v)
RETURN d.id AS decision_id, d.verdict AS verdict, d.risk AS risk, d.impact AS impact,
       d.reasons AS gatekeeper_reasons, v.id AS version_id, p.name AS package,
       m.handle AS publisher, v.has_install_script AS has_install_script
"""

FLAG_MAINTAINER = """
MATCH (m:Maintainer {handle: $handle})
SET m.flagged = true, m.flag_reason = $reason, m.flagged_at = timestamp()
RETURN m.handle AS flagged
"""

RECORD_INVESTIGATION = """
MATCH (d:Decision {id: $did})
CREATE (i:Investigation {id: $iid, severity: $severity, headline: $headline,
                         summary: $summary, findings: $findings,
                         actions: $actions, packages_at_risk: $packages_at_risk,
                         model: $model, at: timestamp()})
CREATE (i)-[:INVESTIGATED]->(d)
SET d.needs_investigation = false
WITH i
UNWIND $flagged AS h
MATCH (m:Maintainer {handle: h})
CREATE (i)-[:FLAGGED]->(m)
RETURN count(*) AS flags_linked
"""

INVESTIGATION_LOG = """
MATCH (i:Investigation)-[:INVESTIGATED]->(d:Decision)-[:EVALUATED]->(v:Version)
OPTIONAL MATCH (i)-[:FLAGGED]->(m:Maintainer)
RETURN i.at AS at, i.severity AS severity, v.id AS version, i.headline AS headline,
       collect(m.handle) AS flagged
ORDER BY at DESC
LIMIT 25
"""

# --- UI helpers ---------------------------------------------------------------

GRAPH_STATS = """
MATCH (n) RETURN labels(n)[0] AS label, count(n) AS count ORDER BY label
"""

UPSTREAM_SUBGRAPH = """
MATCH (dep:Package)-[:DEPENDS_ON*1..5]->(t:Package {name: $pkg})
WITH t, collect(DISTINCT dep.name) + [t.name] AS names
MATCH (x:Package)-[:DEPENDS_ON]->(y:Package)
WHERE x.name IN names AND y.name IN names
RETURN x.name AS src, x.kind AS src_kind, y.name AS dst, y.kind AS dst_kind
"""

DECISION_LOG = """
MATCH (d:Decision)-[:EVALUATED]->(v:Version)-[:PART_OF]->(p:Package),
      (m:Maintainer)-[:PUBLISHED]->(v)
RETURN d.at AS at, d.verdict AS verdict, d.risk AS risk, d.impact AS impact,
       p.name AS package, v.number AS version, m.handle AS maintainer
ORDER BY d.at DESC
LIMIT 25
"""
