# src/workers/authenticated_crawler.py
"""
Authenticated Web Crawler — uses Playwright to crawl an authenticated web app,
discovering pages, forms, and API calls that only appear when logged in.

Returns:
  - List of discovered URLs (sitemap)
  - List of forms with their action, method, and input fields
  - List of XHR/fetch requests observed during crawl
"""
from __future__ import annotations
import asyncio, re
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Set
from src.utils.logging import logger


MAX_PAGES     = 30    # cap crawl depth
MAX_FORMS     = 50
SKIP_EXTS     = {".png",".jpg",".gif",".svg",".ico",".css",".js",".woff",".woff2",".ttf",".pdf",".zip"}
SKIP_PATTERNS = re.compile(r"(logout|signout|delete|destroy|reset-password|unsubscribe)", re.I)


async def crawl_authenticated(
    context,              # Playwright BrowserContext (already authenticated)
    start_url:   str,
    max_pages:   int = MAX_PAGES,
    progress_cb = None,   # optional async callback(pct: int, msg: str)
) -> Dict:
    """
    Crawl the target starting from start_url using the authenticated context.
    Returns {"urls": [...], "forms": [...], "xhr_calls": [...]}
    """
    base = _base(start_url)
    visited:   Set[str]  = set()
    queue:     List[str] = [start_url]
    urls:      List[Dict] = []
    forms:     List[Dict] = []
    xhr_calls: List[Dict] = []

    page = await context.new_page()

    # Track XHR/fetch calls
    async def on_request(req):
        if req.resource_type in ("xhr", "fetch") and req.url.startswith("http"):
            xhr_calls.append({
                "url":    req.url,
                "method": req.method,
                "headers": dict(req.headers),
            })

    page.on("request", on_request)

    try:
        while queue and len(visited) < max_pages:
            url = queue.pop(0)
            if url in visited:
                continue

            # Skip dangerous or off-domain links
            if not url.startswith(base) or SKIP_PATTERNS.search(url):
                continue
            ext = urlparse(url).path.rsplit(".", 1)[-1] if "." in urlparse(url).path else ""
            if f".{ext}" in SKIP_EXTS:
                continue

            visited.add(url)
            pct = min(95, int(len(visited) / max_pages * 100))
            if progress_cb:
                await progress_cb(pct, f"Crawling: {url[:60]}")

            try:
                resp = await page.goto(url, wait_until="domcontentloaded", timeout=12000)
                await page.wait_for_load_state("networkidle", timeout=5000)

                status = resp.status if resp else 0
                title  = await page.title()
                urls.append({"url": url, "status": status, "title": title[:80]})

                # Discover links on this page
                links = await page.eval_on_selector_all("a[href]", "els => els.map(e => e.href)")
                for link in links:
                    link = link.split("#")[0].split("?")[0]
                    if link and link not in visited and link.startswith(base):
                        queue.append(link)

                # Discover forms
                page_forms = await _extract_forms(page, url)
                forms.extend(page_forms[:5])   # max 5 forms per page

            except Exception as e:
                logger.debug(f"[crawler] {url}: {e}")
                urls.append({"url": url, "status": 0, "title": "", "error": str(e)[:80]})

    finally:
        await page.close()

    logger.info(f"[crawler] Done: {len(visited)} pages, {len(forms)} forms, {len(xhr_calls)} XHR")
    return {
        "urls":      urls[:max_pages],
        "forms":     forms[:MAX_FORMS],
        "xhr_calls": xhr_calls[:100],
    }


async def _extract_forms(page, page_url: str) -> List[Dict]:
    """Extract all forms from the current page."""
    try:
        form_data = await page.evaluate("""() => {
            return Array.from(document.forms).map(f => ({
                action:  f.action || window.location.href,
                method:  f.method || 'GET',
                inputs:  Array.from(f.elements).map(el => ({
                    name:  el.name,
                    type:  el.type,
                    value: el.value && el.type !== 'password' ? el.value : '',
                    id:    el.id,
                    required: el.required,
                })).filter(i => i.name),
            }))
        }""")
        result = []
        for f in (form_data or []):
            if not f.get("inputs"):
                continue
            result.append({
                "page_url": page_url,
                "action":   f.get("action", page_url),
                "method":   (f.get("method") or "GET").upper(),
                "inputs":   f.get("inputs") or [],
            })
        return result
    except Exception:
        return []


def _base(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}"
