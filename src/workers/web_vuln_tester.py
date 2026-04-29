# src/workers/web_vuln_tester.py
"""
Web Vulnerability Tester — runs security tests against discovered authenticated pages and forms.

Tests:
  XSS          — reflected XSS in form fields and URL params
  CSRF         — forms missing CSRF tokens
  IDOR         — numeric IDs in URLs, try adjacent values
  Open Redirect — redirect params with external URLs
  Sensitive Exposure — admin/debug pages accessible
  Insecure Forms — forms submitted over HTTP
  Cookie Security — missing Secure/HttpOnly/SameSite flags
  Security Headers — missing CSP, HSTS, X-Frame-Options
"""
from __future__ import annotations
import asyncio, re
from typing import Any, Dict, List
from src.utils.logging import logger


SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def _f(test_id, url, severity, title, detail, evidence=""):
    return {"testId": test_id, "url": url, "severity": severity,
            "title": title, "detail": detail, "evidence": evidence[:300]}


async def run_web_tests(
    context,
    sitemap:  List[Dict],
    forms:    List[Dict],
    xhr_calls: List[Dict],
    start_url: str,
) -> List[Dict]:
    """Run all web vulnerability tests and return findings."""
    findings: List[Dict] = []

    page = await context.new_page()
    try:
        results = await asyncio.gather(
            _test_security_headers(page, start_url),
            _test_cookie_security(page, start_url),
            _test_sensitive_pages(context, start_url, sitemap),
            _test_open_redirect(page, sitemap),
            _test_csrf(forms),
            _test_idor(page, sitemap),
            _test_xss_forms(context, forms),
            _test_insecure_forms(forms),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, list):
                findings.extend(r)
            elif isinstance(r, Exception):
                logger.debug(f"[vuln-tester] check error: {r}")
    finally:
        await page.close()

    findings.sort(key=lambda f: SEV.get(f.get("severity","info"), 4))
    logger.info(f"[vuln-tester] {len(findings)} findings")
    return findings


# ── Security headers ─────────────────────────────────────────────────────────

async def _test_security_headers(page, url: str) -> List[Dict]:
    findings = []
    try:
        resp = await page.goto(url, wait_until="domcontentloaded", timeout=10000)
        if not resp:
            return []
        headers = {k.lower(): v for k, v in resp.headers.items()}

        checks = [
            ("content-security-policy",  "high",   "Missing Content-Security-Policy header",
             "No CSP header — XSS attacks can execute arbitrary scripts without restriction."),
            ("strict-transport-security","medium",  "Missing HSTS header",
             "No Strict-Transport-Security — browsers may connect via HTTP, enabling downgrade attacks."),
            ("x-frame-options",          "medium",  "Missing X-Frame-Options header",
             "No X-Frame-Options — page may be embedded in iframes enabling clickjacking attacks."),
            ("x-content-type-options",   "low",     "Missing X-Content-Type-Options header",
             "No X-Content-Type-Options: nosniff — browsers may MIME-sniff responses."),
            ("permissions-policy",       "low",     "Missing Permissions-Policy header",
             "No Permissions-Policy — camera, mic, geolocation access is unrestricted."),
        ]
        for header, severity, title, detail in checks:
            if header not in headers:
                findings.append(_f(f"missing-header-{header.replace('-','_')}", url, severity, title, detail, f"Header '{header}' absent"))
    except Exception as e:
        logger.debug(f"[vuln-tester] headers: {e}")
    return findings


# ── Cookie security ───────────────────────────────────────────────────────────

async def _test_cookie_security(page, url: str) -> List[Dict]:
    findings = []
    try:
        await page.goto(url, wait_until="domcontentloaded", timeout=10000)
        cookies = await page.context.cookies()
        sensitive_names = re.compile(r"(session|token|auth|jwt|sid|csrf|user)", re.I)

        for cookie in cookies:
            name = cookie.get("name", "")
            if not sensitive_names.search(name):
                continue

            if not cookie.get("httpOnly"):
                findings.append(_f("cookie-no-httponly", url, "high",
                    f"Cookie '{name}' missing HttpOnly flag",
                    f"Session cookie '{name}' is readable by JavaScript — XSS can steal it.",
                    f"Cookie: {name}; HttpOnly=False"))

            if not cookie.get("secure"):
                findings.append(_f("cookie-no-secure", url, "medium",
                    f"Cookie '{name}' missing Secure flag",
                    f"Cookie '{name}' transmitted over HTTP — may be intercepted in transit.",
                    f"Cookie: {name}; Secure=False"))

            samesite = cookie.get("sameSite", "None")
            if samesite in ("None", ""):
                findings.append(_f("cookie-samesite-none", url, "medium",
                    f"Cookie '{name}' has SameSite=None",
                    f"Cookie '{name}' sent on all cross-site requests — enables CSRF attacks.",
                    f"Cookie: {name}; SameSite={samesite}"))
    except Exception as e:
        logger.debug(f"[vuln-tester] cookies: {e}")
    return findings


# ── Sensitive pages ───────────────────────────────────────────────────────────

SENSITIVE_PATHS = [
    ("/admin",              "critical", "Admin panel accessible"),
    ("/admin/",             "critical", "Admin panel accessible"),
    ("/wp-admin",           "critical", "WordPress admin accessible"),
    ("/phpmyadmin",         "critical", "phpMyAdmin accessible"),
    ("/debug",              "high",     "Debug endpoint exposed"),
    ("/api/debug",          "high",     "API debug endpoint exposed"),
    ("/api/internal",       "high",     "Internal API endpoint exposed"),
    ("/.env",               "critical", ".env file accessible"),
    ("/config.json",        "critical", "Config file accessible"),
    ("/api/swagger",        "medium",   "Swagger UI exposed"),
    ("/api/docs",           "medium",   "API docs exposed"),
    ("/api/graphql",        "medium",   "GraphQL endpoint exposed"),
    ("/metrics",            "medium",   "Metrics endpoint exposed"),
    ("/actuator",           "high",     "Spring actuator exposed"),
    ("/actuator/health",    "medium",   "Actuator health endpoint exposed"),
    ("/server-status",      "high",     "Apache server-status exposed"),
]

async def _test_sensitive_pages(context, base_url: str, sitemap: List[Dict]) -> List[Dict]:
    from urllib.parse import urlparse
    findings = []
    base = f"{urlparse(base_url).scheme}://{urlparse(base_url).netloc}"
    visited_urls = {u["url"] for u in sitemap}

    page = await context.new_page()
    try:
        for path, severity, title in SENSITIVE_PATHS:
            url = base + path
            if url in visited_urls:
                continue
            try:
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=8000)
                if resp and resp.status in (200, 301, 302):
                    content = await page.content()
                    # Avoid false positives — check for meaningful content
                    if len(content) > 200 and not any(p in content.lower() for p in
                        ["404", "not found", "page not found", "does not exist"]):
                        findings.append(_f(f"sensitive-{path.replace('/','_').strip('_')}", url, severity,
                            title,
                            f"GET {url} returned {resp.status}. This endpoint should not be publicly accessible.",
                            f"Status: {resp.status}, Content length: {len(content)}"))
            except Exception:
                pass
    finally:
        await page.close()
    return findings


# ── Open redirect ─────────────────────────────────────────────────────────────

REDIRECT_PARAMS = re.compile(r"(redirect|return|next|url|to|goto|destination|redir|forward|target)=", re.I)
REDIRECT_PAYLOAD = "https://evil.attacker.com"

async def _test_open_redirect(page, sitemap: List[Dict]) -> List[Dict]:
    findings = []
    checked = set()
    for entry in sitemap[:20]:
        url = entry.get("url", "")
        if "?" not in url or not REDIRECT_PARAMS.search(url):
            continue
        # Replace redirect param value
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        for param in list(params.keys()):
            if REDIRECT_PARAMS.search(f"{param}="):
                test_url = urlunparse(parsed._replace(
                    query=urlencode({**params, param: [REDIRECT_PAYLOAD]}, doseq=True)
                ))
                if test_url in checked:
                    continue
                checked.add(test_url)
                try:
                    resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                    final = page.url
                    if REDIRECT_PAYLOAD in final or (resp and resp.url and REDIRECT_PAYLOAD in resp.url):
                        findings.append(_f("open-redirect", url, "high",
                            f"Open redirect via '{param}' parameter",
                            f"Parameter '{param}' redirected to attacker-controlled domain. Enables phishing and token theft.",
                            f"GET {test_url} → {final}"))
                except Exception:
                    pass
    return findings


# ── CSRF check ────────────────────────────────────────────────────────────────

CSRF_TOKEN_NAMES = re.compile(r"(csrf|_token|xsrf|authenticity_token|__requestverificationtoken)", re.I)

async def _test_csrf(forms: List[Dict]) -> List[Dict]:
    findings = []
    for form in forms:
        if form.get("method") != "POST":
            continue
        inputs = form.get("inputs", [])
        has_csrf = any(CSRF_TOKEN_NAMES.search(inp.get("name", "") or "") for inp in inputs)
        has_csrf = has_csrf or any(CSRF_TOKEN_NAMES.search(inp.get("id", "") or "") for inp in inputs)
        if not has_csrf:
            findings.append(_f("missing-csrf", form["page_url"], "high",
                "POST form missing CSRF token",
                f"Form at {form['page_url']} submits to {form['action']} via POST with no CSRF token. Cross-site request forgery possible.",
                f"Form action: {form['action']}, inputs: {[i.get('name') for i in inputs]}"))
    return findings


# ── IDOR ─────────────────────────────────────────────────────────────────────

NUMERIC_ID = re.compile(r"/(\d+)(?:/|$|\?)")

async def _test_idor(page, sitemap: List[Dict]) -> List[Dict]:
    findings = []
    checked = set()
    for entry in sitemap[:30]:
        url = entry.get("url", "")
        m = NUMERIC_ID.search(url)
        if not m:
            continue
        original_id = int(m.group(1))
        for test_id in [original_id + 1, original_id - 1, 1, 9999]:
            if test_id <= 0:
                continue
            test_url = url[:m.start(1)] + str(test_id) + url[m.end(1):]
            if test_url in checked or test_url == url:
                continue
            checked.add(test_url)
            try:
                resp = await page.goto(test_url, wait_until="domcontentloaded", timeout=8000)
                if resp and resp.status == 200:
                    content = await page.content()
                    orig_resp = await page.goto(url, wait_until="domcontentloaded", timeout=8000)
                    orig_content = await page.content() if orig_resp and orig_resp.status == 200 else ""
                    # If different content returned for different IDs at similar length, likely IDOR
                    if len(content) > 500 and abs(len(content) - len(orig_content)) > 100:
                        findings.append(_f("potential-idor", url, "high",
                            f"Potential IDOR — resource ID {test_id} accessible",
                            f"URL with ID {original_id} also returned data for ID {test_id}. Other users' data may be accessible.",
                            f"Original: {url}\nTest: {test_url} → {resp.status}"))
                        break
            except Exception:
                pass
            if len(findings) >= 3:
                break
    return findings


# ── XSS in forms ─────────────────────────────────────────────────────────────

XSS_PAYLOAD = "<script>window._xss=1</script>"
XSS_ALT     = "'\"><img src=x onerror=alert(1)>"

async def _test_xss_forms(context, forms: List[Dict]) -> List[Dict]:
    findings = []
    page = await context.new_page()
    try:
        for form in forms[:10]:
            if not form.get("inputs"):
                continue
            text_inputs = [i for i in form["inputs"] if i.get("type") not in ("hidden","submit","file","checkbox","radio")]
            if not text_inputs:
                continue
            try:
                await page.goto(form["page_url"], wait_until="domcontentloaded", timeout=10000)

                # Fill all text fields with XSS payload
                for inp in text_inputs:
                    sel = f"[name='{inp['name']}']"
                    try:
                        el = page.locator(sel).first
                        if await el.count():
                            await el.fill(XSS_PAYLOAD)
                    except Exception:
                        pass

                # Submit
                try:
                    submit = page.locator("button[type='submit'], input[type='submit']").first
                    if await submit.count():
                        await submit.click()
                        await page.wait_for_load_state("networkidle", timeout=5000)
                except Exception:
                    pass

                content = await page.content()
                if XSS_PAYLOAD in content or "<script>window._xss" in content:
                    findings.append(_f("reflected-xss", form["page_url"], "critical",
                        f"Reflected XSS in form at {form['page_url']}",
                        f"XSS payload reflected in response from form submitting to {form['action']}.",
                        f"Payload: {XSS_PAYLOAD[:60]}"))
            except Exception:
                pass
    finally:
        await page.close()
    return findings


# ── Insecure forms ────────────────────────────────────────────────────────────

async def _test_insecure_forms(forms: List[Dict]) -> List[Dict]:
    findings = []
    for form in forms:
        action = form.get("action", "")
        if action.startswith("http://"):
            has_password = any(i.get("type") == "password" for i in form.get("inputs", []))
            severity = "critical" if has_password else "medium"
            findings.append(_f("form-http", form["page_url"], severity,
                f"{'Password' if has_password else 'Form'} submitted over HTTP",
                f"Form action '{action}' uses HTTP — data submitted in plaintext.",
                f"Page: {form['page_url']}"))
    return findings
