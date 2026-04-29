# src/workers/auth_handler.py
"""
Auth Handler — handles different authentication methods for Playwright sessions.
Supports: form-based login, cookie injection, Bearer/API token headers.

Returns: Playwright BrowserContext with auth applied, ready for crawling.
"""
from __future__ import annotations
import json, asyncio
from typing import Any, Dict, List, Optional
from src.utils.logging import logger


AuthResult = Dict[str, Any]  # {"ok": bool, "method": str, "error"?: str, "cookies"?: list, "headers"?: dict}


async def build_auth_context(
    playwright,
    browser,
    auth_config: Dict[str, Any],
    target_url:  str,
) -> tuple:
    """
    Create a Playwright BrowserContext with authentication applied.
    Returns (context, auth_result).
    """
    method = auth_config.get("type", "none")

    if method == "none":
        ctx = await browser.new_context(ignore_https_errors=True)
        return ctx, {"ok": True, "method": "none"}

    if method == "cookie":
        return await _cookie_auth(browser, auth_config, target_url)

    if method == "token":
        return await _token_auth(browser, auth_config)

    if method == "form":
        return await _form_auth(playwright, browser, auth_config, target_url)

    ctx = await browser.new_context(ignore_https_errors=True)
    return ctx, {"ok": False, "method": method, "error": f"Unknown auth type: {method}"}


async def _cookie_auth(browser, auth_config: Dict, target_url: str) -> tuple:
    """Inject raw cookies into the browser context."""
    raw_cookies = auth_config.get("cookies", "")

    cookies: List[Dict] = []
    if isinstance(raw_cookies, str) and raw_cookies.strip():
        # Parse "name=value; name2=value2" format
        for part in raw_cookies.split(";"):
            part = part.strip()
            if "=" in part:
                name, _, value = part.partition("=")
                cookies.append({
                    "name":  name.strip(),
                    "value": value.strip(),
                    "url":   target_url,
                })
    elif isinstance(raw_cookies, list):
        cookies = raw_cookies

    try:
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        domain = parsed.netloc or parsed.path

        ctx = await browser.new_context(ignore_https_errors=True)
        if cookies:
            await ctx.add_cookies(cookies)
        logger.info(f"[auth] Cookie auth: {len(cookies)} cookies injected")
        return ctx, {"ok": True, "method": "cookie", "cookies": len(cookies)}
    except Exception as e:
        ctx = await browser.new_context(ignore_https_errors=True)
        return ctx, {"ok": False, "method": "cookie", "error": str(e)}


async def _token_auth(browser, auth_config: Dict) -> tuple:
    """Set Authorization header on all requests via extra_http_headers."""
    token_type  = auth_config.get("token_type", "Bearer")
    token_value = auth_config.get("token", "")
    header_name = auth_config.get("header_name", "Authorization")

    if header_name == "Authorization":
        header_value = f"{token_type} {token_value}".strip()
    else:
        header_value = token_value

    try:
        ctx = await browser.new_context(
            ignore_https_errors=True,
            extra_http_headers={header_name: header_value},
        )
        logger.info(f"[auth] Token auth: {header_name}: {token_type} ***")
        return ctx, {"ok": True, "method": "token", "header": header_name}
    except Exception as e:
        ctx = await browser.new_context(ignore_https_errors=True)
        return ctx, {"ok": False, "method": "token", "error": str(e)}


async def _form_auth(playwright, browser, auth_config: Dict, target_url: str) -> tuple:
    """
    Perform form-based login using Playwright.
    Auto-detects login form fields or uses provided selectors.
    """
    login_url      = auth_config.get("login_url") or target_url
    # If login_url not set and target looks like an admin URL, warn in logs
    if not auth_config.get("login_url") and any(p in (login_url or "").lower() for p in ("/admin", "/wp-admin", "/dashboard")):
        logger.warning(f"[auth] login_url not set and target appears to be a protected page ({login_url}). "
                       f"Consider setting login_url to your actual login page (e.g. /login or /auth/signin).")
    username       = auth_config.get("username", "")
    password       = auth_config.get("password", "")
    username_sel   = auth_config.get("username_selector", "")
    password_sel   = auth_config.get("password_selector", "")
    submit_sel     = auth_config.get("submit_selector", "")
    success_url    = auth_config.get("success_url_contains", "")

    try:
        ctx  = await browser.new_context(ignore_https_errors=True)
        page = await ctx.new_page()

        logger.info(f"[auth] Form auth: navigating to {login_url}")
        await page.goto(login_url, wait_until="domcontentloaded", timeout=15000)
        await page.wait_for_load_state("networkidle", timeout=8000)

        # Auto-detect selectors if not provided
        if not username_sel:
            username_sel = await _find_input_selector(page, ["username","email","user","login","name"])
        if not password_sel:
            password_sel = await _find_input_selector(page, ["password","passwd","pass"])
        if not submit_sel:
            submit_sel = await _find_submit_selector(page)

        if not username_sel or not password_sel:
            await page.close()
            return ctx, {"ok": False, "method": "form", "error": "Could not locate login form fields"}

        # Fill and submit
        await page.fill(username_sel, username)
        await page.fill(password_sel, password)

        if submit_sel:
            await page.click(submit_sel)
        else:
            await page.keyboard.press("Enter")

        # Wait for navigation
        try:
            await page.wait_for_load_state("networkidle", timeout=8000)
        except Exception:
            pass

        final_url = page.url
        await page.close()

        # Verify success
        if success_url and success_url not in final_url:
            return ctx, {
                "ok": False, "method": "form",
                "error": f"Login may have failed — expected URL to contain '{success_url}', got: {final_url}"
            }

        # Check for failure: if final URL is same as login URL, we didn't navigate away
        from urllib.parse import urlparse
        def _strip(u): return urlparse(u).path.rstrip('/')
        if _strip(final_url) == _strip(login_url):
            return ctx, {
                "ok": False, "method": "form",
                "error": f"Login likely failed — still on auth page: {final_url}"
            }
        # Also check for explicit error indicators in query string or path
        fail_patterns = ["error", "invalid", "failed", "denied", "wrong"]
        if any(p in final_url.lower() for p in fail_patterns):
            return ctx, {
                "ok": False, "method": "form",
                "error": f"Login likely failed — error indicator in URL: {final_url}"
            }

        logger.info(f"[auth] Form login succeeded → {final_url}")
        return ctx, {"ok": True, "method": "form", "final_url": final_url}

    except Exception as e:
        logger.error(f"[auth] Form auth error: {e}")
        try:
            ctx = await browser.new_context(ignore_https_errors=True)
        except Exception:
            pass
        return ctx, {"ok": False, "method": "form", "error": str(e)}


async def _find_input_selector(page, keywords: List[str]) -> str:
    """Find an input field by common name/id/placeholder patterns."""
    for kw in keywords:
        selectors = [
            f"input[name*='{kw}' i]",
            f"input[id*='{kw}' i]",
            f"input[placeholder*='{kw}' i]",
            f"input[type='{kw}']",
            f"input[autocomplete='{kw}']",
        ]
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if await el.count() > 0:
                    return sel
            except Exception:
                pass
    return ""


async def _find_submit_selector(page) -> str:
    """Find the form submit button."""
    candidates = [
        "button[type='submit']",
        "input[type='submit']",
        "button:has-text('Login')",
        "button:has-text('Sign in')",
        "button:has-text('Log in')",
        "button:has-text('Continue')",
        "[role='button']:has-text('Login')",
    ]
    for sel in candidates:
        try:
            el = page.locator(sel).first
            if await el.count() > 0:
                return sel
        except Exception:
            pass
    return ""
