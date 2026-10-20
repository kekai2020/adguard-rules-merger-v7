"""V5.2 whitelist auditor — multi-layer defense-in-depth decision engine.

Layers (all network layers execute in PARALLEL per domain via asyncio.gather):
  1. DNS resolution     — NXDOMAIN=expired, private-IP=suspicious (free, keyless)
  2. Threat intelligence — URLhaus + ThreatFox (free, keyless, rate-limited)
  3. RDAP registration   — domain age, new domains <30d flagged (free, keyless)
  4. MarketNow scam check— typosquatting / suspicious TLD / unregistered (free)
  5. DNSBL lookups (V5.2)— Spamhaus DBL + SURBL multi (free DNS queries)
  6. VirusTotal          — vendor reputation (optional, needs API key)
  7. Offline classifier  — tldextract + PSL registered-domain matching (free, sync)
  8. AI classification   — LLM semantic fallback for low-confidence domains
                           (optional, needs API key, only called for conf<0.6)

V5.2 additions:
  - All reasons are collected (no early-return fusion) + weighted risk_score.
  - DNSBL layer: Spamhaus DBL (dbl.spamhaus.org) + SURBL (multi.surbl.org)
    reply-code parsing; malware/phishing listings are malicious signals,
    spam/junk/abused listings are suspicious signals.
  - Disk-backed result cache (whitelist_audit_cache.json, default TTL 24h) so
    repeated runs skip the network for already-audited domains.

Parallel execution:
  - All independent network layers (DNS, DNSBL, threat-intel, RDAP, scam,
    VirusTotal) run concurrently via asyncio.gather — total latency ≈ max(layer
    latency) instead of sum(layer latencies).
  - The offline PSL classifier is synchronous and microsecond-fast.
  - The AI layer runs after the gather because it depends on the offline
    confidence score (only low-confidence domains trigger it).
  - A shared aiohttp.ClientSession is used across all domains/layers.

Ratings:
  malicious  🔴  any threat-intel / DNSBL malware-phishing source positive
  suspicious 🟡  DNS NXDOMAIN / private IP / new domain / scam / DNSBL spam
  safe       🟢  DNS resolves normally, no threat hits
  unknown    ⚪  all checks failed

In-memory results are cached with a 24h TTL; optional disk cache persists the
same TTL across processes.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import logging
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

from .ai_classifier import classify_with_ai
from .domain_classifier import (
    category_counts,
    classify_domain_with_confidence,
)
from .homograph import detect_typosquat
from .models import Rule
from .scam_check import query_scam_check
from .version import AUDIT_CACHE_VERSION, user_agent
from .virustotal_audit import query_virustotal
from .whois_audit import query_rdap

URLHAUS_HOST_API = "https://urlhaus-api.abuse.ch/v1/host/"
THREATFOX_API = "https://threatfox-api.abuse.ch/api/v1/"

# ── V5.2 DNSBL zones (free keyless DNS lookups) ───────────────────
# Not listed = NXDOMAIN (the normal case). A 127.0.0.x answer = listed.
DNSBL_LISTS = (
    ("dbl.spamhaus.org", "SpamhausDBL"),
    ("multi.surbl.org", "SURBL"),
)
# Spamhaus returns these prefixes when queried from public/open resolvers —
# they mean "query blocked", not "domain listed". Must never be treated as a
# listing (would false-positive every domain on a public resolver).
_DNSBL_BLOCKED = ("127.255.255.", "127.255.254.")

# Spamhaus DBL return codes (last octet).
_DBL_CODES = {
    10: ("spam", False),
    11: ("phishing", True),
    12: ("malware", True),
    13: ("botnet-c2", True),
    14: ("abused-spam", False),
    15: ("hijacked", False),
}
# SURBL multi.surbl.org is a bitmask in the last octet.
_SURBL_BITS = (
    (4, "scam", True),
    (8, "junk", False),
    (16, "phishing", True),
    (32, "malware", True),
    (64, "abused-ads", False),
)

RATING_MALICIOUS = "malicious"
RATING_SUSPICIOUS = "suspicious"
RATING_SAFE = "safe"
RATING_UNKNOWN = "unknown"

CACHE_TTL = 86400  # 24 hours
AUDIT_CACHE_FILENAME = "whitelist_audit_cache.json"

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


# Abused / disposable TLDs frequently used in phishing kits. Conservative
# list — a match alone is not enough to mark a domain suspicious.
_SUSPICIOUS_TLDS = frozenset(
    {
        "xyz",
        "top",
        "click",
        "country",
        "cfd",
        "sbs",
        "zip",
        "mov",
        "gq",
        "tk",
        "ml",
        "cf",
        "ga",
        "work",
        "bond",
        "rest",
        "cyou",
        "qpon",
        "monster",
        "quest",
        "icu",
        "cam",
        "lol",
        "pics",
        "buzz",
        # V6: additional frequently-abused cheap TLDs (conservative; a match
        # alone only adds 1 point, escalation still needs score >= 3).
        "party",
        "review",
        "vip",
        "world",
        "site",
        "online",
        "store",
        "shop",
        "tech",
        "today",
        "stream",
        "racing",
        "club",
        "zone",
        "fun",
        "life",
        "news",
    }
)

# Rating → human-readable action recommendation.
_RECOMMEND = {
    "malicious": "remove",
    "suspicious": "review",
    "unknown": "review",
    "safe": "keep",
}
_RECOMMEND_LABEL = {
    "remove": "建议移除",
    "review": "建议复核",
    "keep": "建议保留",
}


def recycled_domain_clue(rdap: dict[str, Any], dns: dict[str, Any]) -> bool:
    """Offline recycled/dropped-domain clue from already-collected signals.

    True when RDAP exposes no registrar record, the domain is not flagged as
    newly registered, yet it still resolves — a weak hint that the old
    registration record was dropped after expiry (a recycled domain being
    re-used). Informational only: it never contributes to the risk score on
    its own.
    """
    try:
        if rdap.get("registrar"):
            return False
        if rdap.get("is_new_domain"):
            return False
        return bool(dns.get("ips"))
    except AttributeError:
        return False


def local_heuristics(domain: str) -> dict[str, Any]:
    """Offline, keyless signals. ``is_risky`` only when score >= 3.

    Checks: punycode/IDN, abused TLD, deep subdomains, over-long domain,
    digit-heavy core label, digit-letter homoglyph substitution.
    """
    flags: list[str] = []
    score = 0
    d = (domain or "").lower().strip(".")
    if not d:
        return {"score": 0, "flags": [], "is_risky": False, "tld": ""}

    if d.startswith("xn--") or ".xn--" in d:
        flags.append("punycode/IDN")
        score += 2

    labels = d.split(".")
    tld = labels[-1] if labels else ""
    if tld in _SUSPICIOUS_TLDS:
        flags.append(f"可疑TLD .{tld}")
        score += 1
    if len(labels) >= 6:
        flags.append(f"子域过深({len(labels)})")
        score += 1
    if len(d) >= 60:
        flags.append(f"域名过长({len(d)})")
        score += 1

    core = labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")
    digits = sum(c.isdigit() for c in core)
    if core and digits >= 3 and len(core) <= 12:
        flags.append("标签含大量数字")
        score += 1
    if core and any(c in core for c in "01") and any(c in core for c in "olil"):
        flags.append("数字字母混用(疑似仿冒)")
        score += 2
    # V6: phishing kits stack branding across hyphens (e.g. "apple-support-login")
    if core and core.count("-") >= 2:
        flags.append("标签含多个连字符")
        score += 1

    return {
        "score": score,
        "flags": flags,
        "is_risky": score >= 3,
        "tld": tld,
    }


@dataclass
class AuditConfig:
    """Configuration for the multi-layer audit engine."""

    use_dns: bool = True
    use_urlhaus: bool = True
    use_threatfox: bool = True
    use_rdap: bool = True
    use_scam_check: bool = True
    use_virustotal: bool = False
    virustotal_api_key: str = ""
    use_ai: bool = False
    ai_api_key: str = ""
    ai_base_url: str = "https://api.openai.com/v1"
    ai_model: str = "gpt-4o-mini"
    ai_min_confidence: float = 0.6
    ai_max_domains: int = 100
    concurrency: int = 20
    urlhaus_delay: float = 0.2
    new_domain_threshold_days: int = 30
    # V5.2 — DNSBL layer + disk cache (opt-in so offline unit tests stay
    # hermetic; enabled in config/sources.yaml).
    use_dnsbl: bool = False
    # Offline heuristics (punycode, abused TLD, deep subdomains, homoglyphs).
    # Always on by default — zero network cost, provides offline signal.
    use_heuristics: bool = True
    cache_results: bool = False
    cache_dir: str = "cache"
    cache_ttl_seconds: int = CACHE_TTL
    # V5.3: configurable fusion weights (defaults = the V5.2 hard-coded scores,
    # so default behaviour is unchanged). Used by the cache fingerprint AND by
    # _fuse_rating (V6: weights are actually wired into scoring).
    fusion_weights: dict[str, int] = field(
        default_factory=lambda: {
            "threat_intel": 40,
            "dnsbl_malicious": 30,
            "scam_confirmed": 30,
            "dns_private_ip": 20,
            "scam_suspicious": 20,
            "dnsbl_listed": 15,
            "dns_nxdomain": 15,
            "rdap_new_domain": 15,
            "heuristics": 10,
            # V6: new signals (conservative defaults; a non-hit domain adds 0).
            "homograph": 12,
            "dns_mx_missing": 8,
            "gsb_malicious": 35,
            "phishtank_malicious": 30,
            "urlscan_suspicious": 20,
        }
    )
    # V5.3: threat-intel mode — "api" (per-domain HTTP, legacy) or
    # "auto" (download feed once, O(1) local lookup, API fallback).
    ti_mode: str = "api"
    feed_ttl_seconds: int = 3600
    # Optional DNS-over-HTTPS JSON endpoint (e.g. a NextDNS profile URL
    # ``https://dns.nextdns.io/<id>``). Empty = use the system resolver via
    # DnsChecker. On any DoH transport/parse failure we fall back to the
    # system resolver so the layer never hard-fails on a misconfigured proxy.
    doh_endpoint: str = ""
    doh_timeout: float = 5.0
    # V6: offline homograph/typosquat layer (zero network, on by default).
    use_homograph: bool = True
    # V6: MX/SPF TXT missing clue (DNS-derived; optional, default off).
    use_dns_mx: bool = False
    # V6: optional online intel layers — default off, skipped without a key.
    use_gsb: bool = False
    gsb_api_key: str = ""
    use_phishtank: bool = False
    phishtank_api_key: str = ""
    use_urlscan: bool = False
    urlscan_api_key: str = ""
    # V6: certificate transparency (crt.sh) — optional interface only, default off.
    use_crtsh: bool = False


@dataclass
class _CacheEntry:
    result: dict[str, Any]
    timestamp: float = field(default_factory=time.time)


# Note: the threat-intel rate-limit semaphore is created per run inside
# audit_whitelist() so it binds to that run's event loop (a module-level
# Semaphore breaks across repeated asyncio.run() calls / pytest loops).
# V5.3: the in-process result cache is likewise per-run (local to
# audit_whitelist) to avoid cross-run / cross-test pollution.


def _is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return any(ip in net for net in _PRIVATE_NETS)


# ── V5.3 disk cache (config-fingerprinted, fixed TTL, v2 format) ───


def _disk_cache_path(config: AuditConfig) -> Path:
    return Path(config.cache_dir) / AUDIT_CACHE_FILENAME


def _cfg_fingerprint(config: AuditConfig) -> str:
    """Stable hash of audit-affecting config (layers + weights + thresholds).

    Changing any of these invalidates stale cache entries for this config,
    so flipping a layer switch or a fusion weight produces a fresh subtree
    instead of returning decisions made under the old configuration.
    """
    layers = (
        config.use_dns,
        config.use_urlhaus,
        config.use_threatfox,
        config.use_rdap,
        config.use_scam_check,
        config.use_dnsbl,
        config.use_virustotal,
        config.use_ai,
        config.use_heuristics,
        # V6 layers
        config.use_homograph,
        config.use_dns_mx,
        config.use_gsb,
        config.use_phishtank,
        config.use_urlscan,
        config.use_crtsh,
    )
    payload = {
        "schema": AUDIT_CACHE_VERSION,
        "layers": layers,
        "fusion_weights": config.fusion_weights,
        "new_domain_threshold_days": config.new_domain_threshold_days,
        "cache_ttl_seconds": config.cache_ttl_seconds,
        "doh_endpoint": config.doh_endpoint,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _disk_cache_load(config: AuditConfig) -> dict[str, dict[str, Any]]:
    """Load {domain: result} entries still inside the TTL window (v2 format).

    v1 files (flat ``{"version":1,"entries":{...}}``) are read as if their
    entries belonged to the current config fingerprint, so the first save
    after an upgrade migrates them into the v2 subtree automatically.
    """
    if not config.cache_results:
        return {}
    p = _disk_cache_path(config)
    if not p.exists():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("whitelist audit cache unreadable: %s", e)
        return {}
    fp = _cfg_fingerprint(config)
    now = time.time()
    ttl = config.cache_ttl_seconds
    out: dict[str, dict[str, Any]] = {}
    if data.get("version", 1) >= AUDIT_CACHE_VERSION:
        subtree = (data.get("configs") or {}).get(fp) or {}
        for domain, rec in (subtree.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    else:
        for domain, rec in (data.get("entries") or {}).items():
            if now - rec.get("ts", 0) < ttl:
                out[domain] = rec.get("result") or {}
    return out


def _disk_cache_save(config: AuditConfig, fresh: dict[str, dict[str, Any]]) -> None:
    """Persist fresh results to the v2 disk cache (fixed TTL, no ts refresh).

    Existing non-expired entries keep their original ``ts`` (fixed-TTL
    semantics — an entry fetched 23h ago is not "renewed" to now just
    because a later run touched the file). Expired entries are pruned.
    A v1 file on disk is migrated into the current fingerprint subtree.
    """
    if not config.cache_results or not fresh:
        return
    p = _disk_cache_path(config)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        fp = _cfg_fingerprint(config)
        now = time.time()
        ttl = config.cache_ttl_seconds
        existing_configs: dict[str, Any] = {}
        if p.exists():
            try:
                raw = json.loads(p.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                raw = {}
            if raw.get("version", 1) >= AUDIT_CACHE_VERSION:
                existing_configs = raw.get("configs") or {}
            elif raw.get("entries"):
                existing_configs[fp] = {"entries": raw["entries"]}
        subtree = existing_configs.get(fp) or {}
        old_entries = subtree.get("entries") or {}
        merged: dict[str, Any] = {}
        for domain, rec in old_entries.items():
            if now - rec.get("ts", 0) < ttl:
                merged[domain] = rec
        for domain, result in fresh.items():
            merged[domain] = {"ts": now, "result": result}
        existing_configs[fp] = {"entries": merged}
        tmp = p.with_suffix(".json.tmp")
        tmp.write_text(
            json.dumps(
                {"version": AUDIT_CACHE_VERSION, "configs": existing_configs},
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        tmp.replace(p)
    except OSError as e:
        logger.warning("whitelist audit cache write failed: %s", e)


def _parse_doh_json(data: dict[str, Any]) -> dict[str, Any] | None:
    """Parse a Google/NextDNS JSON DoH payload into the legacy DNS shape.

    Status 3 = NXDOMAIN; Status 0 collects A/AAAA answer data; any other
    status (SERVFAIL/REFUSED/...) returns None so the caller falls back to
    the system resolver instead of misreading a resolver error as expired.
    A null / non-dict / malformed payload also returns None (never raises).
    """
    if not isinstance(data, dict):
        return None
    status = data.get("Status")
    if status == 3:  # NXDOMAIN
        return {"nxdomain": True, "ips": [], "error": None}
    if status != 0:
        return None
    ips: list[str] = []
    answers = data.get("Answer")
    if isinstance(answers, list):
        for ans in answers:
            if not isinstance(ans, dict):
                continue
            if ans.get("type") in (1, 28):  # A / AAAA (skip CNAME chains)
                ip = ans.get("data")
                if ip:
                    ips.append(ip)
    return {"nxdomain": False, "ips": ips, "error": None}


async def _doh_lookup(domain: str, endpoint: str, timeout: float = 5.0) -> dict[str, Any] | None:
    """Query a Google/NextDNS-style JSON DoH endpoint, return the legacy shape.

    ``GET <endpoint>?name=<domain>&type=A`` with ``Accept: application/dns-json``.
    Returns ``None`` on any transport / non-200 / parse failure so the caller
    can fall back to the system resolver instead of declaring the domain
    unknown.
    """
    import aiohttp

    base = endpoint.rstrip("/")
    headers = {"Accept": "application/dns-json", "User-Agent": user_agent()}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                base,
                params={"name": domain, "type": "A"},
                headers=headers,
                timeout=timeout,
            ) as resp:
                if resp.status != 200:
                    return None
                data = await resp.json(content_type=None)
    except Exception:  # noqa: BLE001 — any DoH failure degrades to system DNS
        return None

    return _parse_doh_json(data)


async def _dns_check(domain: str, timeout: int = 5, doh_endpoint: str = "") -> dict[str, Any]:
    """Async DNS resolution via DoH (when configured) then DnsChecker fallback.

    Thin wrapper preserving the legacy ``{nxdomain, ips, error}`` shape so
    ``_fuse_rating`` and existing tests don't need to change. The actual
    system resolution goes through :class:`merger.dnsx.DnsChecker` which uses
    dnspython's explicit rcode (works on glibc / musl / Windows) and falls
    back to getaddrinfo when dnspython is unavailable.
    """
    if doh_endpoint:
        via_doh = await _doh_lookup(domain, doh_endpoint, timeout=timeout)
        if via_doh is not None:
            return via_doh

    from .dnsx import DnsChecker

    result = await DnsChecker(timeout=timeout).check(domain)
    error = result.get("error_type")
    if error == "nxdomain":
        error = None
    return {"nxdomain": result["nxdomain"], "ips": result["ips"], "error": error}


async def _query_urlhaus(domain: str, session, timeout: int = 8) -> dict[str, Any]:
    try:
        data = {"host": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(
            URLHAUS_HOST_API, data=data, headers=headers, timeout=timeout
        ) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok":
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threatfox(domain: str, session, timeout: int = 8) -> dict[str, Any]:
    try:
        data = {"query": "search_ioc", "search_term": domain}
        headers = {"User-Agent": user_agent()}
        async with session.post(THREATFOX_API, json=data, headers=headers, timeout=timeout) as resp:
            if resp.status != 200:
                return {"malicious": False, "error": f"HTTP {resp.status}"}
            result = await resp.json(content_type=None)
            if result.get("query_status") == "ok" and result.get("data"):
                return {"malicious": True, "error": None}
            return {"malicious": False, "error": None}
    except Exception as e:
        return {"malicious": False, "error": str(e)}


async def _query_threat_intel(
    domain: str, session, config: AuditConfig, ti_sem=None
) -> tuple[dict, dict]:
    """Query URLhaus + ThreatFox with rate-limit semaphore.

    Uses a per-run semaphore (default 3 concurrent) instead of a global lock,
    and a fixed small delay rather than idx-proportional sleep.
    Returns (urlhaus_result, threatfox_result).
    """
    urlhaus = {"malicious": False, "error": "disabled"}
    threatfox = {"malicious": False, "error": "disabled"}

    if not (config.use_urlhaus or config.use_threatfox):
        return urlhaus, threatfox

    async with ti_sem:
        # Fixed small delay to avoid burst; NOT idx-proportional.
        if config.urlhaus_delay > 0:
            await asyncio.sleep(config.urlhaus_delay)
        if config.use_urlhaus:
            urlhaus = await _query_urlhaus(domain, session)
        if config.use_threatfox:
            threatfox = await _query_threatfox(domain, session)

    return urlhaus, threatfox


async def _query_threat_intel_dataset(
    domain: str,
    feed_index,
) -> tuple[dict, dict]:
    """Dataset-mode threat lookup (V5.3) — replaces per-domain API calls.

    Returns (urlhaus_result, threatfox_result) with the same shape as
    ``_query_threat_intel`` so ``_fuse_rating`` is unchanged.
    """
    hit = feed_index.lookup_domain(domain)
    no = {"malicious": False, "error": None}
    if not hit["listed"]:
        return no, no
    source = hit.get("source") or ""
    if source == "ThreatFox":
        return no, {"malicious": True, "error": None}
    return {"malicious": True, "error": None}, no


async def _query_rdap_wrapper(domain: str, session, config: AuditConfig) -> dict[str, Any]:
    """RDAP query using registered domain (eTLD+1)."""
    try:
        from .domain_classifier import registered_domain

        reg_domain = registered_domain(domain)
        return await query_rdap(
            reg_domain, session, threshold_days=config.new_domain_threshold_days
        )
    except Exception as e:
        return {"is_new_domain": False, "domain_age_days": None, "registrar": None, "error": str(e)}


# ── V5.2 DNSBL layer ───────────────────────────────────────────────


def parse_dnsbl_response(list_name: str, ip: str) -> tuple[bool, list[str]]:
    """Interpret a 127.0.0.x DNSBL reply.

    Returns (malicious_signal, labels). Spamhaus DBL uses one code per last
    octet; SURBL multi uses a bitmask. Codes marking phishing / malware /
    scam / botnet produce a malicious signal; spam/junk/abused only warn.
    """
    if not ip.startswith("127."):
        return False, []
    try:
        last = int(ip.rsplit(".", 1)[-1])
    except ValueError:
        return False, []
    bad = False
    labels: list[str] = []
    if list_name == "SpamhausDBL":
        name, mal = _DBL_CODES.get(last, (f"code-{last}", False))
        labels.append(f"{list_name}:{name}")
        bad = mal
    else:  # SURBL-style bitmask
        for bit, name, mal in _SURBL_BITS:
            if last & bit:
                labels.append(f"{list_name}:{name}")
                bad = bad or mal
    return bad, labels


async def _dnsbl_lookup(qname: str, timeout: int) -> list[str]:
    """Resolve a DNSBL query name, returning the A-record answers.

    NXDOMAIN / not-listed raises ``socket.gaierror`` (handled by the caller).
    Factored out so tests can stub resolution without touching asyncio.
    """
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(qname, None, family=socket.AF_INET), timeout=timeout
    )
    return [info[4][0] for info in infos]


async def _query_dnsbl(domain: str, timeout: int = 6) -> dict[str, Any]:
    """Free keyless DNSBL lookups (Spamhaus DBL + SURBL multi).

    NXDOMAIN means "not listed" — the normal, healthy answer — so these
    queries are cheap and safe to fan out. Volume is one lookup per whitelist
    domain per run (plus disk-cache hits skipped entirely).
    """
    hits: list[str] = []
    errors: list[str] = []
    malicious = False
    for zone, list_name in DNSBL_LISTS:
        qname = f"{domain}.{zone}"
        try:
            for ip in await _dnsbl_lookup(qname, timeout):
                if any(ip.startswith(p) for p in _DNSBL_BLOCKED):
                    errors.append(f"{list_name}: query blocked (open resolver)")
                    continue
                bad, labels = parse_dnsbl_response(list_name, ip)
                hits.extend(labels)
                malicious = malicious or bad
        except socket.gaierror:
            continue  # NXDOMAIN / not listed
        except asyncio.TimeoutError:
            errors.append(f"{list_name}: timeout")
        except Exception as e:  # noqa: BLE001
            errors.append(f"{list_name}: {e}")
    return {
        "listed": bool(hits),
        "malicious": malicious,
        "hits": hits,
        "error": "; ".join(errors) or None,
    }


# ── V6 optional online intel layers (default off; error-safe) ───────
# Every query returns a plain dict on success and an ``{"error": ...}`` dict
# on any transport/parse failure; a disabled or keyless layer returns
# ``error="disabled"`` / ``"no API key configured"`` so fusion can ignore it.

GSB_LOOKUP_API = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
PHISHTANK_API = "http://checkurl.phishtank.com/checkurl/"
URLSCAN_SEARCH_API = "https://urlscan.io/api/v1/search/"
CRT_SH_API = "https://crt.sh/"


async def _query_gsb(domain: str, api_key: str, session, timeout: int = 8) -> dict[str, Any]:
    """Google Safe Browsing v4 threatMatches/find (needs API key, optional)."""
    result = {"malicious": False, "threats": [], "error": None}
    if not api_key:
        result["error"] = "no API key configured"
        return result
    try:
        payload = {
            "client": {"clientId": "adguard-rules-merger", "clientVersion": "6"},
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ALL_PLATFORMS"],
                "threatEntries": [{"url": f"http://{domain}"}],
            },
        }
        async with session.post(
            GSB_LOOKUP_API,
            params={"key": api_key},
            json=payload,
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        matches = data.get("matches") or []
        result["threats"] = sorted({m.get("threatType", "?") for m in matches})
        result["malicious"] = bool(result["threats"])
        return result
    except Exception as e:  # noqa: BLE001 — layer degrades to error dict
        result["error"] = str(e)
        return result


async def _query_phishtank(domain: str, api_key: str, session, timeout: int = 10) -> dict[str, Any]:
    """PhishTank checkurl (needs app key, optional)."""
    result = {"malicious": False, "phish_id": None, "error": None}
    if not api_key:
        result["error"] = "no API key configured"
        return result
    try:
        async with session.post(
            PHISHTANK_API,
            data={"url": f"http://{domain}", "app_key": api_key, "format": "json"},
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        phish = (data.get("results") or {}).get("phish") or {}
        result["phish_id"] = phish.get("phish_id")
        result["malicious"] = bool(phish.get("in_database")) and str(
            phish.get("valid", "")
        ).lower() not in ("false", "0")
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result


async def _query_urlscan(domain: str, api_key: str, session, timeout: int = 10) -> dict[str, Any]:
    """urlscan.io community verdicts search (key optional, layer off by default)."""
    result = {"malicious": False, "verdict": None, "error": None}
    try:
        headers = {"User-Agent": user_agent()}
        if api_key:
            headers["API-Key"] = api_key
        async with session.get(
            URLSCAN_SEARCH_API,
            params={"q": f"domain:{domain}"},
            headers=headers,
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        for hit in data.get("results") or []:
            community = (hit.get("verdicts") or {}).get("community") or {}
            if community.get("malicious"):
                result["malicious"] = True
                result["verdict"] = "community-malicious"
                break
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result


async def _query_crtsh(domain: str, session, timeout: int = 10) -> dict[str, Any]:
    """Certificate transparency via crt.sh (informational; never scores alone)."""
    result = {"entries": [], "error": None}
    try:
        async with session.get(
            CRT_SH_API,
            params={"q": f"%.{domain}", "output": "json"},
            headers={"User-Agent": user_agent()},
            timeout=timeout,
        ) as resp:
            if resp.status != 200:
                result["error"] = f"HTTP {resp.status}"
                return result
            data = await resp.json(content_type=None)
        result["entries"] = [
            {"issuer": e.get("issuer_name"), "not_before": e.get("not_before")}
            for e in (data or [])[:20]
        ]
        return result
    except Exception as e:  # noqa: BLE001
        result["error"] = str(e)
        return result


async def _query_mx_spf(domain: str, timeout: float = 5.0) -> dict[str, Any]:
    """DNS-derived MX + SPF TXT presence clue (dnspython in executor).

    Missing SPF/MX is a weak clue only; the layer defaults off so benign
    websites (which usually publish no MX) never contribute by default.
    """
    result = {
        "has_mx": None,
        "has_spf": None,
        "missing_mx": False,
        "missing_spf": False,
        "recycled_clue": False,
        "reasons": [],
        "error": None,
    }
    try:
        import dns.resolver

        loop = asyncio.get_running_loop()

        def _resolve(rdtype: str) -> list[str]:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = timeout
            try:
                answer = resolver.resolve(domain, rdtype)
                return [r.to_text() for r in answer]
            except dns.resolver.NoAnswer:
                return []

        mx = await loop.run_in_executor(None, _resolve, "MX")
        txt = await loop.run_in_executor(None, _resolve, "TXT")
        result["has_mx"] = bool(mx)
        result["has_spf"] = any("v=spf1" in t.lower() for t in txt)
        result["missing_mx"] = not result["has_mx"]
        result["missing_spf"] = not result["has_spf"]
        if result["missing_mx"]:
            result["reasons"].append("无 MX 记录")
        if result["missing_spf"]:
            result["reasons"].append("无 SPF TXT 记录")
        return result
    except Exception as e:  # noqa: BLE001 — resolver error degrades to clue error
        result["error"] = str(e)
        return result


def _fuse_rating(
    dns,
    urlhaus,
    threatfox,
    rdap,
    scam,
    vt,
    config,
    dnsbl=None,
    heuristics=None,
    homograph=None,
    mxspf=None,
    gsb=None,
    phishtank=None,
    urlscan=None,
) -> tuple[str, list[str], int]:
    """Multi-layer fusion (V5.2): collect ALL reasons + weighted risk score.

    Returns (rating, reasons, risk_score 0-100). Every enabled layer
    contributes its reason and score — no early return — so the audit output
    shows the complete evidence picture for each domain.
    """
    reasons: list[str] = []
    score = 0
    malicious_signal = False
    suspicious_signal = False
    dnsbl = dnsbl or {"listed": False, "malicious": False, "hits": [], "error": None}
    heuristics = heuristics or {"score": 0, "flags": [], "is_risky": False}
    homograph = homograph or {
        "is_typosquat": False,
        "matched_brand": None,
        "distance": None,
        "reasons": [],
    }
    mxspf = mxspf or {
        "missing_mx": False,
        "missing_spf": False,
        "reasons": [],
        "error": None,
    }
    gsb = gsb or {"malicious": False, "threats": [], "error": None}
    phishtank = phishtank or {"malicious": False, "error": None}
    urlscan = urlscan or {"malicious": False, "verdict": None, "error": None}
    # V6: fusion weights are read from config (defaults equal the original
    # hard-coded scores, so default behaviour is unchanged) and participate
    # in the disk-cache fingerprint.
    w = config.fusion_weights or {}

    # Threat intelligence: any positive → malicious
    ti_sources = []
    if urlhaus.get("malicious"):
        ti_sources.append("URLhaus")
    if threatfox.get("malicious"):
        ti_sources.append("ThreatFox")
    if vt.get("malicious"):
        ti_sources.append("VirusTotal")
    if ti_sources:
        malicious_signal = True
        score += w.get("threat_intel", 40)
        reasons.append(f"威胁情报命中 ({'+'.join(ti_sources)})")

    # V5.2 DNSBL: phishing / malware / scam listings are malicious signals
    if dnsbl.get("malicious"):
        malicious_signal = True
        score += w.get("dnsbl_malicious", 30)
        reasons.append(f"DNSBL 命中（{'+'.join(dnsbl.get('hits', []))}）")
    elif dnsbl.get("listed"):
        suspicious_signal = True
        score += w.get("dnsbl_listed", 15)
        reasons.append(f"DNSBL 列表命中（{'+'.join(dnsbl.get('hits', []))}）")

    # DNS: expired or private IP → suspicious
    if dns.get("nxdomain"):
        suspicious_signal = True
        score += w.get("dns_nxdomain", 15)
        reasons.append("DNS NXDOMAIN（域名已过期，白名单可能无效）")
    elif dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
        suspicious_signal = True
        score += w.get("dns_private_ip", 20)
        reasons.append(f"解析到私有/回环 IP: {dns['ips']}")

    # RDAP: newly registered → suspicious
    if rdap.get("is_new_domain"):
        suspicious_signal = True
        score += w.get("rdap_new_domain", 15)
        age = rdap.get("domain_age_days", "?")
        reasons.append(f"新注册域名（{age}天，<{config.new_domain_threshold_days}天阈值）")

    # MarketNow scam check → suspicious
    if scam.get("is_suspicious"):
        suspicious_signal = True
        score += (
            w.get("scam_confirmed", 30)
            if scam.get("is_confirmed_scam")
            else w.get("scam_suspicious", 20)
        )
        decision = scam.get("decision", "?")
        risk = scam.get("risk_score", 0)
        scam_reasons = scam.get("reasons", [])
        detail = "; ".join(scam_reasons[:2]) if scam_reasons else ""
        reasons.append(
            f"诈骗/钓鱼检测 [{decision}, 风险分{risk}]" + (f": {detail}" if detail else "")
        )

    # Offline heuristics: only escalate when several signals fire (score>=3).
    if heuristics.get("is_risky"):
        suspicious_signal = True
        score += w.get("heuristics", 10)
        flags = ", ".join(heuristics.get("flags") or []) or f"score={heuristics.get('score', 0)}"
        reasons.append(f"本地启发式风险 ({flags})")

    # V6: offline homograph / typosquat impersonation → suspicious
    if config.use_homograph and homograph.get("is_typosquat"):
        suspicious_signal = True
        score += w.get("homograph", 12)
        kind = "同形字" if homograph.get("homograph") else "拼写劫持"
        brand = homograph.get("matched_brand")
        dist = homograph.get("distance")
        reasons.append(f"{kind}仿冒品牌 {brand}（编辑距离 {dist}）")

    # V6: MX/SPF missing clue → weak suspicious (layer off by default)
    if config.use_dns_mx and (mxspf.get("missing_mx") or mxspf.get("missing_spf")):
        suspicious_signal = True
        score += w.get("dns_mx_missing", 8)
        clues = ", ".join(mxspf.get("reasons") or [])
        reasons.append(f"MX/SPF 记录缺失线索（{clues}）")

    # V6: Google Safe Browsing → malicious
    if config.use_gsb and gsb.get("malicious"):
        malicious_signal = True
        score += w.get("gsb_malicious", 35)
        threats = "; ".join(gsb.get("threats") or []) or "Safe Browsing"
        reasons.append(f"Google Safe Browsing 命中（{threats}）")

    # V6: PhishTank confirmed phishing → malicious
    if config.use_phishtank and phishtank.get("malicious"):
        malicious_signal = True
        score += w.get("phishtank_malicious", 30)
        reasons.append("PhishTank 确认钓鱼域名")

    # V6: urlscan community malicious verdict → suspicious
    if config.use_urlscan and urlscan.get("malicious"):
        suspicious_signal = True
        score += w.get("urlscan_suspicious", 20)
        verdict = urlscan.get("verdict") or "suspicious"
        reasons.append(f"urlscan 社区标记（{verdict}）")

    score = min(score, 100)

    if malicious_signal:
        return RATING_MALICIOUS, reasons, score

    # DNS failure fallbacks: never claim "DNS normal" on errors.
    dns_error = dns.get("error")
    ti_disabled = not config.use_urlhaus and not config.use_threatfox and not config.use_virustotal
    ti_all_errors = (
        (not config.use_urlhaus or urlhaus.get("error") not in (None, "disabled"))
        and (not config.use_threatfox or threatfox.get("error") not in (None, "disabled"))
        and (not config.use_virustotal or vt.get("error") not in (None, "disabled"))
    )
    if suspicious_signal:
        return RATING_SUSPICIOUS, reasons, score
    if dns_error and (ti_disabled or ti_all_errors):
        reasons.append(f"检测不完整：DNS 查询失败 ({dns_error})，威胁情报无有效命中")
        return RATING_UNKNOWN, reasons, score
    if dns_error:
        reasons.append(f"DNS 查询失败 ({dns_error})，但威胁情报无命中")
        return RATING_UNKNOWN, reasons, score

    reasons.append("DNS 正常解析，无威胁情报标记")
    return RATING_SAFE, reasons, score


async def audit_whitelist(
    allows: list[Rule],
    source_names: dict[str, str] | None = None,
    config: AuditConfig | None = None,
    # Backwards-compat kwargs (deprecated, use config instead)
    concurrency: int = 10,
    use_dns: bool = True,
    use_urlhaus: bool = True,
    use_threatfox: bool = True,
    urlhaus_delay: float = 1.0,
) -> dict[str, Any]:
    """Audit all domain-based whitelist rules with parallel multi-layer fusion.

    All independent network layers execute concurrently per domain.
    """
    if config is None:
        config = AuditConfig(
            use_dns=use_dns,
            use_urlhaus=use_urlhaus,
            use_threatfox=use_threatfox,
            concurrency=concurrency,
            urlhaus_delay=urlhaus_delay,
        )

    source_names = source_names or {}
    targets = [a for a in allows if a.normalized_domain]
    if not targets:
        return {
            "summary": {"total": 0, "safe": 0, "suspicious": 0, "malicious": 0, "unknown": 0},
            "rules": [],
        }

    # ── V5.2 disk cache: previously audited domains skip the network ──
    disk_cache = _disk_cache_load(config)
    disk_hits = [0]  # list for nonlocal mutation
    fresh_disk: dict[str, dict[str, Any]] = {}
    # V5.3: per-run in-process cache (local, not module-level) to avoid
    # cross-run / cross-test pollution. _audit_one reads/writes this dict.
    result_cache: dict[str, _CacheEntry] = {}

    # ── Shared HTTP session for all network layers ──
    import aiohttp

    sem = asyncio.Semaphore(config.concurrency)
    ti_sem = asyncio.Semaphore(3)  # per-run, bound to this event loop
    layer_hits = {
        "dns_nxdomain": 0,
        "dns_private_ip": 0,
        "urlhaus": 0,
        "threatfox": 0,
        "rdap_new_domain": 0,
        "scam_check": 0,
        "virustotal": 0,
        "ai_classified": 0,
        "heuristics": 0,
        "dnsbl_malicious": 0,
        "dnsbl_listed": 0,
        # V6 layers
        "homograph": 0,
        "dns_mx_missing": 0,
        "gsb": 0,
        "phishtank": 0,
        "urlscan": 0,
    }
    # AI budget: limit LLM calls to config.ai_max_domains (cost control)
    ai_budget = [config.ai_max_domains]  # list for nonlocal mutation in nested fn

    async with aiohttp.ClientSession() as session:
        # V5.3: build threat-feed index once (ti_mode=auto). On failure
        # _audit_one falls back to per-domain API calls.
        feed_index = None
        if config.ti_mode == "auto" and (config.use_urlhaus or config.use_threatfox):
            from .threat_feeds import ThreatFeedIndex

            feed_index = ThreatFeedIndex(
                cache_dir=config.cache_dir, ttl_seconds=config.feed_ttl_seconds
            )
            await feed_index.build(session)

        async def _audit_one(rule: Rule) -> dict[str, Any]:
            domain = rule.normalized_domain
            cache_key = f"audit:{domain}"
            _entry = result_cache.get(cache_key)
            cached = (
                _entry.result if _entry and (time.time() - _entry.timestamp) < CACHE_TTL else None
            )
            if cached:
                cached = dict(cached)
                cached["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                cached["rule"] = rule.output_raw
                cached["disk_cache"] = False
                return cached
            if domain in disk_cache:
                disk_hits[0] += 1
                hit = dict(disk_cache[domain])
                hit["sources"] = [source_names.get(s, s) for s in rule.source_ids]
                hit["rule"] = rule.output_raw
                hit["disk_cache"] = True
                result_cache[cache_key] = _CacheEntry(
                    result={
                        k: v for k, v in hit.items() if k not in ("sources", "rule", "disk_cache")
                    }
                )
                return hit

            async with sem:
                # Layer 6: Offline PSL classification (sync, microseconds)
                category, confidence, cat_reason = classify_domain_with_confidence(domain)

                # ── Layers 1-5: parallel network queries ──
                tasks = []
                task_names = []

                if config.use_dns:
                    tasks.append(_dns_check(domain, doh_endpoint=config.doh_endpoint))
                    task_names.append("dns")

                if config.use_urlhaus or config.use_threatfox:
                    if feed_index is not None and feed_index.ready:
                        tasks.append(_query_threat_intel_dataset(domain, feed_index))
                    else:
                        if feed_index is not None:
                            feed_index.stats["api_fallbacks"] += 1
                        tasks.append(_query_threat_intel(domain, session, config, ti_sem=ti_sem))
                    task_names.append("ti")

                if config.use_rdap:
                    tasks.append(_query_rdap_wrapper(domain, session, config))
                    task_names.append("rdap")

                if config.use_scam_check:
                    tasks.append(query_scam_check(domain, session))
                    task_names.append("scam")

                if config.use_dnsbl:
                    tasks.append(_query_dnsbl(domain))
                    task_names.append("dnsbl")

                if config.use_virustotal and config.virustotal_api_key:
                    tasks.append(query_virustotal(domain, config.virustotal_api_key, session))
                    task_names.append("vt")

                # V6: MX/SPF DNS clue (off by default)
                if config.use_dns_mx:
                    tasks.append(_query_mx_spf(domain))
                    task_names.append("mxspf")

                # V6: optional online intel (off by default; skip without key)
                if config.use_gsb and config.gsb_api_key:
                    tasks.append(_query_gsb(domain, config.gsb_api_key, session))
                    task_names.append("gsb")

                if config.use_phishtank and config.phishtank_api_key:
                    tasks.append(_query_phishtank(domain, config.phishtank_api_key, session))
                    task_names.append("phishtank")

                if config.use_urlscan:
                    tasks.append(_query_urlscan(domain, config.urlscan_api_key, session))
                    task_names.append("urlscan")

                if config.use_crtsh:
                    tasks.append(_query_crtsh(domain, session))
                    task_names.append("crtsh")

                # Execute all network layers concurrently
                gathered = await asyncio.gather(*tasks) if tasks else []
                layer_data = dict(zip(task_names, gathered))

                dns = layer_data.get("dns", {"nxdomain": False, "ips": [], "error": "disabled"})
                ti = layer_data.get(
                    "ti",
                    (
                        {"malicious": False, "error": "disabled"},
                        {"malicious": False, "error": "disabled"},
                    ),
                )
                urlhaus, threatfox = (
                    ti
                    if isinstance(ti, tuple)
                    else (
                        {"malicious": False, "error": "disabled"},
                        {"malicious": False, "error": "disabled"},
                    )
                )
                rdap = layer_data.get(
                    "rdap",
                    {
                        "is_new_domain": False,
                        "domain_age_days": None,
                        "registrar": None,
                        "error": "disabled",
                    },
                )
                scam = layer_data.get(
                    "scam",
                    {
                        "is_suspicious": False,
                        "is_confirmed_scam": False,
                        "decision": None,
                        "risk_score": 0,
                        "reasons": [],
                        "error": "disabled",
                    },
                )
                vt = layer_data.get(
                    "vt",
                    {
                        "malicious": False,
                        "error": "disabled",
                        "reputation_score": 0.0,
                        "malicious_votes": 0,
                    },
                )
                dnsbl = layer_data.get(
                    "dnsbl", {"listed": False, "malicious": False, "hits": [], "error": "disabled"}
                )
                mxspf = layer_data.get(
                    "mxspf",
                    {
                        "has_mx": None,
                        "has_spf": None,
                        "missing_mx": False,
                        "missing_spf": False,
                        "recycled_clue": False,
                        "reasons": [],
                        "error": "disabled",
                    },
                )
                gsb = layer_data.get(
                    "gsb", {"malicious": False, "threats": [], "error": "disabled"}
                )
                phishtank = layer_data.get(
                    "phishtank", {"malicious": False, "phish_id": None, "error": "disabled"}
                )
                urlscan = layer_data.get(
                    "urlscan", {"malicious": False, "verdict": None, "error": "disabled"}
                )
                crtsh = layer_data.get("crtsh", {"entries": [], "error": "disabled"})

                # Offline heuristics (sync, microseconds)
                heur = (
                    local_heuristics(domain)
                    if config.use_heuristics
                    else {"score": 0, "flags": [], "is_risky": False, "tld": ""}
                )

                # V6: offline homograph / typosquat (sync, zero network, error-safe)
                try:
                    hom = (
                        detect_typosquat(domain)
                        if config.use_homograph
                        else {
                            "is_typosquat": False,
                            "matched_brand": None,
                            "distance": None,
                            "reasons": [],
                            "folded": "",
                            "homograph": False,
                        }
                    )
                except Exception as e:  # noqa: BLE001 — layer must never hard-fail
                    hom = {
                        "is_typosquat": False,
                        "matched_brand": None,
                        "distance": None,
                        "reasons": [],
                        "folded": "",
                        "homograph": False,
                        "error": str(e),
                    }

                # V6: offline recycled-domain clue (from collected RDAP+DNS;
                # informational only, never scores on its own).
                mxspf["recycled_clue"] = recycled_domain_clue(rdap, dns)

                # Layer 7: AI classification (only for low confidence, after gather)
                ai_result = {"category": None, "confidence": 0.0, "reason": "", "error": "disabled"}
                if (
                    config.use_ai
                    and config.ai_api_key
                    and confidence < config.ai_min_confidence
                    and ai_budget[0] > 0
                ):
                    ai_budget[0] -= 1
                    try:
                        ai_result = await classify_with_ai(
                            domain,
                            config.ai_api_key,
                            session,
                            base_url=config.ai_base_url,
                            model=config.ai_model,
                        )
                        if ai_result.get("category") and not ai_result.get("error"):
                            category = ai_result["category"]
                            confidence = max(confidence, ai_result["confidence"] * 0.7)
                            cat_reason = f"AI: {ai_result.get('reason', '')}"
                    except Exception as e:
                        ai_result["error"] = str(e)

            # ── Multi-layer fusion (V5.2: all reasons + risk score) ──
            rating, reasons, risk_score = _fuse_rating(
                dns,
                urlhaus,
                threatfox,
                rdap,
                scam,
                vt,
                config,
                dnsbl=dnsbl,
                heuristics=heur,
                homograph=hom,
                mxspf=mxspf,
                gsb=gsb,
                phishtank=phishtank,
                urlscan=urlscan,
            )

            # Track layer hits
            if dns.get("nxdomain"):
                layer_hits["dns_nxdomain"] += 1
            if dns.get("ips") and any(_is_private_ip(ip) for ip in dns["ips"]):
                layer_hits["dns_private_ip"] += 1
            if urlhaus.get("malicious"):
                layer_hits["urlhaus"] += 1
            if threatfox.get("malicious"):
                layer_hits["threatfox"] += 1
            if rdap.get("is_new_domain"):
                layer_hits["rdap_new_domain"] += 1
            if scam.get("is_suspicious"):
                layer_hits["scam_check"] += 1
            if vt.get("malicious"):
                layer_hits["virustotal"] += 1
            if dnsbl.get("malicious"):
                layer_hits["dnsbl_malicious"] += 1
            elif dnsbl.get("listed"):
                layer_hits["dnsbl_listed"] += 1
            if heur.get("is_risky"):
                layer_hits["heuristics"] += 1
            if hom.get("is_typosquat"):
                layer_hits["homograph"] += 1
            if config.use_dns_mx and (mxspf.get("missing_mx") or mxspf.get("missing_spf")):
                layer_hits["dns_mx_missing"] += 1
            if gsb.get("malicious"):
                layer_hits["gsb"] += 1
            if phishtank.get("malicious"):
                layer_hits["phishtank"] += 1
            if urlscan.get("malicious"):
                layer_hits["urlscan"] += 1
            if ai_result.get("category") and not ai_result.get("error"):
                layer_hits["ai_classified"] += 1

            result = {
                "domain": domain,
                "rule": rule.output_raw,
                "sources": [source_names.get(s, s) for s in rule.source_ids],
                "rating": rating,
                "category": category,
                "category_confidence": round(confidence, 2),
                "category_reason": cat_reason,
                "reason": "; ".join(reasons),
                "dns_ips": dns.get("ips", []),
                "dns_nxdomain": dns.get("nxdomain", False),
                "urlhaus_malicious": urlhaus.get("malicious", False),
                "threatfox_malicious": threatfox.get("malicious", False),
                "rdap_new_domain": rdap.get("is_new_domain", False),
                "rdap_domain_age_days": rdap.get("domain_age_days"),
                "rdap_registrar": rdap.get("registrar"),
                "scam_suspicious": scam.get("is_suspicious", False),
                "scam_decision": scam.get("decision"),
                "scam_risk_score": scam.get("risk_score", 0),
                "virustotal_malicious": vt.get("malicious", False),
                "virustotal_reputation": vt.get("reputation_score", 0.0),
                "dnsbl_listed": dnsbl.get("listed", False),
                "dnsbl_malicious": dnsbl.get("malicious", False),
                "dnsbl_hits": dnsbl.get("hits", []),
                "risk_score": risk_score,
                "heuristics_score": heur.get("score", 0),
                "heuristics_flags": heur.get("flags", []),
                # V6: offline homograph / typosquat
                "homograph_is_typosquat": hom.get("is_typosquat", False),
                "homograph_brand": hom.get("matched_brand"),
                "homograph_distance": hom.get("distance"),
                "homograph_reasons": hom.get("reasons", []),
                # V6: MX/SPF DNS clue
                "mxspf_has_mx": mxspf.get("has_mx"),
                "mxspf_has_spf": mxspf.get("has_spf"),
                "mxspf_missing": bool(mxspf.get("missing_mx") or mxspf.get("missing_spf")),
                "mxspf_recycled_clue": bool(mxspf.get("recycled_clue")),
                # V6: optional online intel
                "gsb_malicious": gsb.get("malicious", False),
                "phishtank_malicious": phishtank.get("malicious", False),
                "urlscan_malicious": urlscan.get("malicious", False),
                "crtsh_entries": crtsh.get("entries", []),
                "recommendation": _RECOMMEND.get(rating, "review"),
                "recommendation_label": _RECOMMEND_LABEL.get(
                    _RECOMMEND.get(rating, "review"), "建议复核"
                ),
                "ai_classified": ai_result.get("category") is not None
                and not ai_result.get("error"),
            }
            stored = {k: v for k, v in result.items() if k not in ("sources", "rule", "disk_cache")}
            result_cache[cache_key] = _CacheEntry(result=stored)
            fresh_disk[domain] = stored
            return result

        tasks = [_audit_one(r) for r in targets]
        # Defensive: a single domain must never take the whole audit down.
        # Exceptions (from any layer) are demoted to an "unknown" record.
        gathered = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for r, rule in zip(gathered, targets):
            if isinstance(r, BaseException):
                logger.warning("audit failed for %s: %s", rule.normalized_domain, r)
                results.append(
                    {
                        "domain": rule.normalized_domain,
                        "rule": rule.output_raw,
                        "sources": [source_names.get(s, s) for s in rule.source_ids],
                        "rating": RATING_UNKNOWN,
                        "category": "other",
                        "category_confidence": 0.0,
                        "category_reason": "audit exception",
                        "reason": f"审计异常: {r}",
                        "dns_ips": [],
                        "dns_nxdomain": False,
                        "urlhaus_malicious": False,
                        "threatfox_malicious": False,
                        "rdap_new_domain": False,
                        "rdap_domain_age_days": None,
                        "rdap_registrar": None,
                        "scam_suspicious": False,
                        "scam_decision": None,
                        "scam_risk_score": 0,
                        "virustotal_malicious": False,
                        "virustotal_reputation": 0.0,
                        "dnsbl_listed": False,
                        "dnsbl_malicious": False,
                        "dnsbl_hits": [],
                        "risk_score": 0,
                        "heuristics_score": 0,
                        "heuristics_flags": [],
                        "homograph_is_typosquat": False,
                        "homograph_brand": None,
                        "homograph_distance": None,
                        "homograph_reasons": [],
                        "mxspf_has_mx": None,
                        "mxspf_has_spf": None,
                        "mxspf_missing": False,
                        "mxspf_recycled_clue": False,
                        "gsb_malicious": False,
                        "phishtank_malicious": False,
                        "urlscan_malicious": False,
                        "crtsh_entries": [],
                        "recommendation": "review",
                        "recommendation_label": "建议复核",
                        "ai_classified": False,
                    }
                )
            else:
                results.append(r)

    # persist fresh results to the disk cache (V5.2)
    _disk_cache_save(config, fresh_disk)

    # ── summary ──
    summary = {"total": len(results), "safe": 0, "suspicious": 0, "malicious": 0, "unknown": 0}
    all_categories = []
    for r in results:
        summary[r["rating"]] += 1
        all_categories.append(r["category"])
    summary["category_counts"] = category_counts(all_categories)
    summary["by_rating"] = {}
    for rating in (RATING_SAFE, RATING_SUSPICIOUS, RATING_MALICIOUS, RATING_UNKNOWN):
        cats = [r["category"] for r in results if r["rating"] == rating]
        summary["by_rating"][rating] = category_counts(cats)
    conf_buckets = {"high(>=0.9)": 0, "medium(0.6-0.89)": 0, "low(<0.6)": 0}
    for r in results:
        c = r.get("category_confidence", 0)
        if c >= 0.9:
            conf_buckets["high(>=0.9)"] += 1
        elif c >= 0.6:
            conf_buckets["medium(0.6-0.89)"] += 1
        else:
            conf_buckets["low(<0.6)"] += 1
    summary["category_confidence"] = conf_buckets
    # V5.2 risk score distribution + top risky domains
    risk_buckets = {"high(>=50)": 0, "medium(20-49)": 0, "low(1-19)": 0, "none(0)": 0}
    for r in results:
        s = r.get("risk_score", 0)
        if s >= 50:
            risk_buckets["high(>=50)"] += 1
        elif s >= 20:
            risk_buckets["medium(20-49)"] += 1
        elif s >= 1:
            risk_buckets["low(1-19)"] += 1
        else:
            risk_buckets["none(0)"] += 1
    summary["risk_score_buckets"] = risk_buckets
    summary["top_risky"] = [
        {
            "domain": r["domain"],
            "rating": r["rating"],
            "risk_score": r.get("risk_score", 0),
            "reason": r["reason"],
        }
        for r in sorted(results, key=lambda r: (-r.get("risk_score", 0), r.get("domain", "")))[:10]
        if r.get("risk_score", 0) > 0
    ]
    summary["disk_cache"] = {
        "enabled": config.cache_results,
        "hits": disk_hits[0],
        "stored": len(fresh_disk),
        "path": str(_disk_cache_path(config)) if config.cache_results else None,
    }
    summary["layer_hits"] = layer_hits
    summary["layers_enabled"] = {
        "dns": config.use_dns,
        "doh": bool(config.doh_endpoint),
        "urlhaus": config.use_urlhaus,
        "threatfox": config.use_threatfox,
        "rdap": config.use_rdap,
        "scam_check": config.use_scam_check,
        "dnsbl": config.use_dnsbl,
        "virustotal": config.use_virustotal,
        "ai": config.use_ai,
        # V6 layers
        "homograph": config.use_homograph,
        "dns_mx": config.use_dns_mx,
        "gsb": config.use_gsb,
        "phishtank": config.use_phishtank,
        "urlscan": config.use_urlscan,
        "crtsh": config.use_crtsh,
    }
    summary["execution_mode"] = "parallel"
    if feed_index is not None:
        summary["threat_feeds"] = feed_index.stats
    else:
        summary["threat_feeds"] = {"mode": "api"}

    order = {RATING_MALICIOUS: 0, RATING_SUSPICIOUS: 1, RATING_UNKNOWN: 2, RATING_SAFE: 3}
    results.sort(key=lambda r: (order.get(r["rating"], 9), r["domain"]))

    return {"summary": summary, "rules": results}
