"""Single source of truth for the AdGuard Rules Merger version (M0).

This is the ONLY place the version string is stored. All other version
points (pyproject metadata, README badge, CLI banner, rule-file titles,
CI cache key, User-Agent) are derived from this constant or guarded by
tests/test_version_consistency.py.

V7 notes:
- Product version: 7.0.0.
- The on-disk parsed-rule sidecar (``SIDECAR_VERSION``) and the cache
  index (``CACHE_VERSION``) tag *formats*, not the product. They are
  deliberately left untouched so previously populated caches keep loading
  across a product upgrade.
"""

__version__ = "7.0.0"
__version_short__ = "7.0"

# On-disk format tags — bump only when the serialized layout changes.
# These are intentionally independent of the product version.
SIDECAR_VERSION = 1
CACHE_VERSION = 2
# Incremented in V7 to invalidate the JSON whitelist-audit cache when the
# persisted field set changes. The JSON record is forward/backward tolerant,
# so a bumped version simply forces a one-time re-audit on upgrade.
AUDIT_CACHE_VERSION = 2


def user_agent() -> str:
    """HTTP User-Agent advertised when fetching remote lists."""
    return f"AdGuard-Rules-Merger/{__version_short__}"
