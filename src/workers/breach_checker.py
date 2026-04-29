# src/workers/breach_checker.py
"""
Dark Web & Breach Checker — queries multiple sources for exposed emails, domains,
API keys, and credentials.

Sources (no paid APIs required for core functionality):
  1. HaveIBeenPwned API  — email breach lookup (free tier: 1 req/1.5s, no key needed for names)
  2. IntelX API          — paste/darkweb search (free tier available)
  3. Dehashed API        — breach database search (paid, optional)
  4. Builtin paste scraper — public Pastebin/GitHub gist search via Google dorks

Each result is a normalized Exposure dict:
  source, identifier, type, severity, title, description, dataTypes, foundAt, url
"""
from __future__ import annotations
import asyncio, re, hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from src.utils.logging import logger


# ── Exposure structure ────────────────────────────────────────────────────────

def _exposure(
    source:      str,
    identifier:  str,
    exp_type:    str,         # email | domain | api_key | credential | ip
    severity:    str,         # critical | high | medium | low
    title:       str,
    description: str,
    data_types:  List[str],   # ["passwords", "emails", "names", ...]
    url:         str = "",
    breach_date: Optional[str] = None,
    pwn_count:   Optional[int] = None,
) -> Dict:
    return {
        "source":      source,
        "identifier":  identifier,
        "type":        exp_type,
        "severity":    severity,
        "title":       title,
        "description": description,
        "dataTypes":   data_types,
        "url":         url,
        "breachDate":  breach_date,
        "pwnCount":    pwn_count,
        "foundAt":     datetime.now(timezone.utc).isoformat(),
    }


# ── Main entry ────────────────────────────────────────────────────────────────

async def check_identifier(
    identifier: str,
    id_type:    str,    # "email" | "domain"
    api_keys:   Dict[str, str] = {},
) -> List[Dict]:
    """
    Run all available breach checks for a single identifier.
    Returns list of exposures sorted by severity.
    """
    identifier = identifier.strip().lower()
    exposures:  List[Dict] = []

    tasks = []
    if id_type == "email":
        tasks.append(_check_hibp_email(identifier, api_keys.get("hibp", "")))
        tasks.append(_check_intelx(identifier, id_type, api_keys.get("intelx", "")))
        tasks.append(_check_google_dork_email(identifier))
    elif id_type == "domain":
        tasks.append(_check_hibp_domain(identifier, api_keys.get("hibp", "")))
        tasks.append(_check_intelx(identifier, id_type, api_keys.get("intelx", "")))
        tasks.append(_check_google_dork_domain(identifier))
        tasks.append(_check_certsh_leaks(identifier))

    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, list):
            exposures.extend(r)
        elif isinstance(r, Exception):
            logger.debug(f"[breach] check error for {identifier}: {r}")

    # Dedup by (source, title)
    seen = set()
    unique = []
    for e in exposures:
        key = (e["source"], e["title"])
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # Sort by severity
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    unique.sort(key=lambda e: rank.get(e["severity"], 3))

    logger.info(f"[breach] {identifier} ({id_type}): {len(unique)} exposures")
    return unique


# ── HIBP — email ──────────────────────────────────────────────────────────────

async def _check_hibp_email(email: str, api_key: str = "") -> List[Dict]:
    """
    HaveIBeenPwned API v3 — check if email is in known breaches.
    Requires API key for full results; without key, uses the public name-only endpoint.
    Rate limit: 1 request per 1500ms.
    """
    exposures = []
    try:
        import aiohttp
        headers = {
            "User-Agent": "XCloak-DarkWeb-Monitor/1.0",
            "hibp-api-key": api_key,
        } if api_key else {"User-Agent": "XCloak-DarkWeb-Monitor/1.0"}

        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    breaches = await r.json()
                    for b in breaches:
                        pwn_count   = b.get("PwnCount", 0)
                        data_classes = b.get("DataClasses") or []
                        severity = (
                            "critical" if "Passwords" in data_classes else
                            "high"     if any(d in data_classes for d in ["Credit Cards","Bank Account Numbers","Financial Information"]) else
                            "high"     if pwn_count > 1_000_000 else
                            "medium"
                        )
                        exposures.append(_exposure(
                            source="HaveIBeenPwned",
                            identifier=email,
                            exp_type="email",
                            severity=severity,
                            title=f"Breach: {b.get('Name', 'Unknown')}",
                            description=f"Found in '{b.get('Name')}' data breach ({b.get('BreachDate','?')}). {pwn_count:,} accounts affected.",
                            data_types=data_classes,
                            url=f"https://haveibeenpwned.com/account/{email}",
                            breach_date=b.get("BreachDate"),
                            pwn_count=pwn_count,
                        ))
                elif r.status == 404:
                    pass  # no breaches found — good
                elif r.status == 401:
                    logger.info("[breach] HIBP: API key required for full results")
                elif r.status == 429:
                    logger.warning("[breach] HIBP: rate limited")
                    await asyncio.sleep(2)
    except ImportError:
        logger.warning("[breach] aiohttp not installed — pip install aiohttp")
    except Exception as e:
        logger.debug(f"[breach] HIBP email check error: {e}")
    return exposures


# ── HIBP — domain (check all emails at domain) ────────────────────────────────

async def _check_hibp_domain(domain: str, api_key: str = "") -> List[Dict]:
    """HIBP domain search — requires paid API key."""
    if not api_key:
        return []
    exposures = []
    try:
        import aiohttp
        url = f"https://haveibeenpwned.com/api/v3/breacheddomain/{domain}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"hibp-api-key": api_key, "User-Agent":"XCloak/1.0"},
                                   timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status == 200:
                    data = await r.json()
                    # data = {email: [breach_names...], ...}
                    total_exposed = len(data)
                    all_breaches  = set()
                    for breaches in data.values():
                        all_breaches.update(breaches)
                    if total_exposed > 0:
                        exposures.append(_exposure(
                            source="HaveIBeenPwned",
                            identifier=domain,
                            exp_type="domain",
                            severity="critical" if total_exposed > 100 else "high" if total_exposed > 10 else "medium",
                            title=f"{total_exposed} domain email(s) found in breaches",
                            description=f"{total_exposed} @{domain} addresses exposed across breaches: {', '.join(list(all_breaches)[:5])}{'...' if len(all_breaches) > 5 else ''}",
                            data_types=["Email addresses", "Passwords"],
                            url=f"https://haveibeenpwned.com",
                            pwn_count=total_exposed,
                        ))
    except Exception as e:
        logger.debug(f"[breach] HIBP domain error: {e}")
    return exposures


# ── IntelX ───────────────────────────────────────────────────────────────────

async def _check_intelx(identifier: str, id_type: str, api_key: str = "") -> List[Dict]:
    """
    Intelligence X API — searches paste sites, darkweb, and data leaks.
    Free tier: limited searches per day.
    """
    if not api_key:
        return []
    exposures = []
    try:
        import aiohttp
        base = "https://2.intelx.io"
        headers = {"x-key": api_key, "Content-Type": "application/json"}

        # Start search
        search_payload = {
            "term":    identifier,
            "buckets": [],
            "lookuplevel": 0,
            "maxresults": 20,
            "timeout": 5,
            "datefrom": "",
            "dateto": "",
            "sort": 4,      # sort by date desc
            "media": 0,
            "terminate": [],
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(f"{base}/intelligent/search", json=search_payload,
                                    headers=headers, timeout=aiohttp.ClientTimeout(total=15)) as r:
                if r.status != 200:
                    return []
                search_resp = await r.json()
                search_id   = search_resp.get("id")
                if not search_id:
                    return []

            # Poll results
            await asyncio.sleep(3)
            async with session.get(f"{base}/intelligent/search/result?id={search_id}&limit=20&offset=0",
                                   headers=headers, timeout=aiohttp.ClientTimeout(total=10)) as r:
                if r.status != 200:
                    return []
                results = await r.json()

            records = results.get("records") or []
            for rec in records[:10]:
                name    = rec.get("name", "Unknown source")
                bucket  = rec.get("bucket", "")
                date    = rec.get("date", "")[:10] if rec.get("date") else None
                media   = rec.get("media", 0)
                rec_id  = rec.get("systemid", "")

                severity = (
                    "critical" if "password" in name.lower() or "credential" in name.lower() else
                    "high"     if bucket in ("pastes", "leaks") else
                    "medium"
                )
                exposures.append(_exposure(
                    source="Intelligence X",
                    identifier=identifier,
                    exp_type=id_type,
                    severity=severity,
                    title=f"Found in: {name}",
                    description=f"'{identifier}' found in IntelX source '{name}' (bucket: {bucket}). Date: {date or 'unknown'}.",
                    data_types=["Unknown — manual review required"],
                    url=f"https://intelx.io/?did={rec_id}" if rec_id else "https://intelx.io",
                    breach_date=date,
                ))
    except Exception as e:
        logger.debug(f"[breach] IntelX error: {e}")
    return exposures


# ── Google dork — email ───────────────────────────────────────────────────────

async def _check_google_dork_email(email: str) -> List[Dict]:
    """
    Search for email in public paste sites via common paste site URLs.
    Uses direct HTTP checks (no Google API needed).
    """
    exposures = []
    domain = email.split("@")[-1] if "@" in email else ""
    user   = email.split("@")[0]   if "@" in email else email

    # Check paste sites directly
    paste_urls = [
        f"https://pastebin.com/search?q={email}",
        f"https://gist.github.com/search?q={email}",
    ]
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for url in paste_urls:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                           headers={"User-Agent": "Mozilla/5.0"}) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Check if the email appears in results
                            if email in text.lower() and ("paste" in text.lower() or "gist" in text.lower()):
                                site = url.split("/")[2].replace("www.", "")
                                exposures.append(_exposure(
                                    source=site,
                                    identifier=email,
                                    exp_type="email",
                                    severity="medium",
                                    title=f"Email found in {site} search results",
                                    description=f"'{email}' appears in public paste site search results on {site}. Manual review recommended.",
                                    data_types=["Email address"],
                                    url=url,
                                ))
                except Exception:
                    pass
    except ImportError:
        pass
    return exposures


# ── Google dork — domain ─────────────────────────────────────────────────────

async def _check_google_dork_domain(domain: str) -> List[Dict]:
    """Check for domain-related leaks in public paste sites."""
    exposures = []
    paste_urls = [
        f"https://pastebin.com/search?q={domain}",
        f"https://gist.github.com/search?q={domain}+password",
    ]
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            for url in paste_urls:
                try:
                    async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                                           headers={"User-Agent": "Mozilla/5.0"}) as r:
                        if r.status == 200:
                            text = await r.text()
                            # Look for password/credential patterns alongside domain
                            if domain in text.lower() and re.search(r'password|passwd|secret|api.?key|token', text, re.I):
                                site = url.split("/")[2]
                                exposures.append(_exposure(
                                    source=site,
                                    identifier=domain,
                                    exp_type="domain",
                                    severity="high",
                                    title=f"Domain + credential keywords on {site}",
                                    description=f"'{domain}' appears alongside password/credential keywords in public paste results.",
                                    data_types=["Possible credentials", "Domain mention"],
                                    url=url,
                                ))
                except Exception:
                    pass
    except ImportError:
        pass
    return exposures


# ── crt.sh — check for unusual cert registrations indicating domain abuse ─────

async def _check_certsh_leaks(domain: str) -> List[Dict]:
    """
    Check crt.sh for wildcard or suspicious subdomain certificate registrations
    that might indicate domain takeover or phishing infrastructure.
    """
    exposures = []
    try:
        import aiohttp
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=aiohttp.ClientTimeout(total=10),
                                   headers={"User-Agent": "XCloak/1.0"}) as r:
                if r.status != 200:
                    return []
                certs = await r.json(content_type=None)

        suspicious_patterns = re.compile(
            r'(login|account|secure|verify|bank|paypal|support|update|signin|auth|admin)\.',
            re.I
        )
        suspicious = []
        seen_names = set()
        for cert in (certs or [])[:100]:
            name = cert.get("name_value", "").lower().strip()
            if name in seen_names or name == f"*.{domain}" or name == domain:
                continue
            seen_names.add(name)
            if suspicious_patterns.search(name):
                suspicious.append(name)

        if suspicious:
            exposures.append(_exposure(
                source="crt.sh",
                identifier=domain,
                exp_type="domain",
                severity="medium",
                title=f"{len(suspicious)} suspicious certificate(s) for {domain}",
                description=f"Certificates registered for suspicious subdomains that may indicate phishing: {', '.join(suspicious[:5])}{'...' if len(suspicious) > 5 else ''}",
                data_types=["Phishing infrastructure", "Domain abuse"],
                url=f"https://crt.sh/?q=%.{domain}",
            ))
    except Exception as e:
        logger.debug(f"[breach] crt.sh check error: {e}")
    return exposures
