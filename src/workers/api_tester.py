# src/workers/api_tester.py
"""
API Security Tester — automated security tests against API endpoints.
Tests: CORS, JWT attacks, auth bypass, injection, mass assignment,
       method override, param pollution, SSRF, rate limiting.
"""
from __future__ import annotations
import asyncio, json, time, base64, re
from typing import Any, Dict, List, Optional
from src.utils.logging import logger
from src.workers.spec_parser import Endpoint


def _f(test_id, endpoint, method, severity, title, detail, req="", resp=""):
    return {"testId": test_id, "endpoint": endpoint, "method": method,
            "severity": severity, "title": title, "detail": detail,
            "requestSnippet": req[:500], "responseSnippet": resp[:500]}


async def run_api_tests(
    endpoints: List[Endpoint],
    auth_config: Dict[str, Any],
    base_url: str = "",
    max_workers: int = 5,
    timeout: int = 10,
) -> List[Dict]:
    import httpx
    if not endpoints:
        return []

    findings: List[Dict] = []
    sem = asyncio.Semaphore(max_workers)

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True, verify=False) as client:
        async def test_ep(ep: Endpoint):
            ep_base = (base_url or ep.base_url or "http://localhost").rstrip("/")
            url     = ep_base + ep.path
            auth_h  = _auth_headers(auth_config)
            async with sem:
                results = await asyncio.gather(
                    _cors(client, ep, url, auth_h),
                    _jwt(client, ep, url, auth_config),
                    _auth_bypass(client, ep, url, auth_h),
                    _injection(client, ep, url, auth_h),
                    _mass_assign(client, ep, url, auth_h),
                    _method_override(client, ep, url, auth_h),
                    _param_pollution(client, ep, url, auth_h),
                    _ssrf(client, ep, url, auth_h),
                    return_exceptions=True,
                )
                for r in results:
                    if isinstance(r, list): findings.extend(r)

        rl_ep  = next((e for e in endpoints if e.method == "GET"), endpoints[0])
        rl_url = (base_url or rl_ep.base_url or "http://localhost").rstrip("/") + rl_ep.path
        rl_res = await _rate_limit(client, rl_ep, rl_url, _auth_headers(auth_config))
        findings.extend(rl_res)

        await asyncio.gather(*[test_ep(ep) for ep in endpoints], return_exceptions=True)

    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: rank.get(f.get("severity","info"), 4))
    logger.info(f"[api-tester] {len(findings)} findings across {len(endpoints)} endpoints")
    return findings


def _auth_headers(auth: Dict) -> Dict[str, str]:
    t = auth.get("type","none")
    if t == "bearer":  return {"Authorization": f"Bearer {auth.get('token','')}"}
    if t == "apikey":  return {auth.get("header_name","X-API-Key"): auth.get("token","")}
    if t == "basic":
        creds = base64.b64encode(f"{auth.get('username','')}:{auth.get('password','')}".encode()).decode()
        return {"Authorization": f"Basic {creds}"}
    return {}


async def _cors(client, ep, url, auth):
    findings = []
    for origin, label in [("https://evil.attacker.com","reflected"),("null","null")]:
        try:
            r = await client.options(url, headers={**auth, "Origin": origin,
                "Access-Control-Request-Method": ep.method})
            acao = r.headers.get("access-control-allow-origin","")
            acac = r.headers.get("access-control-allow-credentials","")
            if acao == "*":
                findings.append(_f("cors-wildcard", f"{ep.method} {ep.path}", ep.method, "medium",
                    "CORS wildcard origin", "Access-Control-Allow-Origin: * allows any site to read responses.",
                    f"OPTIONS {url}", f"ACAO: {acao}"))
                break
            elif acao == origin and acac.lower() == "true":
                findings.append(_f(f"cors-{label}", f"{ep.method} {ep.path}", ep.method,
                    "high" if origin == "null" else "medium",
                    f"CORS reflects '{origin}' with credentials",
                    f"Origin {origin} is echoed back with ACAC: true — enables authenticated cross-site requests.",
                    f"OPTIONS {url} Origin: {origin}", f"ACAO: {acao} ACAC: {acac}"))
                break
        except Exception: pass
    return findings


async def _jwt(client, ep, url, auth):
    findings = []
    if auth.get("type") != "bearer": return findings
    token = auth.get("token","")
    if not token or token.count(".") != 2: return findings
    hdr_b64, pay_b64, sig = token.split(".")
    try:
        # none algorithm
        none_hdr = base64.b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).decode().rstrip("=")
        none_tok = f"{none_hdr}.{pay_b64}."
        r = await client.request(ep.method, url, headers={"Authorization": f"Bearer {none_tok}"})
        if r.status_code not in (401,403,422):
            findings.append(_f("jwt-none-alg", f"{ep.method} {ep.path}", ep.method, "critical",
                "JWT 'none' algorithm accepted",
                "Server accepted a JWT with alg=none — token signature is not verified. Any user can forge tokens.",
                f"{ep.method} {url} Bearer {none_tok[:40]}...", f"Status: {r.status_code}"))
    except Exception: pass
    try:
        # expired token
        pad = pay_b64 + "=" * (4 - len(pay_b64) % 4)
        payload = json.loads(base64.b64decode(pad))
        if "exp" in payload:
            payload["exp"] = 1000000
            new_pay = base64.b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            r2 = await client.request(ep.method, url,
                headers={"Authorization": f"Bearer {hdr_b64}.{new_pay}.{sig}"})
            if r2.status_code not in (401,403):
                findings.append(_f("jwt-expired", f"{ep.method} {ep.path}", ep.method, "high",
                    "Expired JWT accepted",
                    "Token with exp=1000000 (year 2001) was accepted — expiry is not validated.",
                    f"{ep.method} {url} (exp=1000000)", f"Status: {r2.status_code}"))
    except Exception: pass
    return findings


async def _auth_bypass(client, ep, url, auth):
    if not ep.auth_required or not auth: return []
    try:
        r = await client.request(ep.method, url, headers={"Content-Type":"application/json"})
        if r.status_code not in (401,403):
            return [_f("auth-bypass", f"{ep.method} {ep.path}", ep.method, "high",
                "Endpoint accessible without auth",
                f"Auth-required endpoint returned {r.status_code} with no token.",
                f"{ep.method} {url} (no auth)", f"Status: {r.status_code}")]
    except Exception: pass
    return []


INJECTIONS = [
    ("sqli",  "' OR '1'='1",           r"(sql|syntax|mysql|postgres|sqlite|ORA-|unterminated)", "high"),
    ("sqli",  "1; DROP TABLE users--", r"(error|exception|syntax)",                             "high"),
    ("nosql", '{"$gt":""}',            r"(\$gt|bson|cast|operator)",                            "high"),
    ("ssti",  "{{7*7}}",               r"\b49\b",                                               "critical"),
    ("xss",   "<script>alert(1)</script>", r"<script>alert",                                    "medium"),
]

async def _injection(client, ep, url, auth):
    findings = []
    params = [p for p in ep.params if p.type in ("string","") and p.location in ("query","path")][:3]
    for param in params:
        for typ, payload, pattern, sev in INJECTIONS:
            try:
                test_url = url
                if param.location == "query":   test_url = url + f"?{param.name}={payload}"
                elif param.location == "path":  test_url = url.replace(f"{{{param.name}}}", payload)
                r = await client.request(ep.method, test_url, headers={**auth, "Content-Type":"application/json"})
                if re.search(pattern, r.text[:1000], re.I):
                    findings.append(_f(f"injection-{typ}", f"{ep.method} {ep.path}", ep.method, sev,
                        f"{typ.upper()} injection in '{param.name}'",
                        f"Param '{param.name}' triggers a {typ} indicator. Payload: {payload!r}",
                        f"{ep.method} {test_url[:200]}", r.text[:200]))
                    break
            except Exception: pass
    return findings


PRIV_FIELDS = ["isAdmin","role","admin","is_admin","privilege","permissions","price","balance"]

async def _mass_assign(client, ep, url, auth):
    if ep.method not in ("POST","PUT","PATCH"): return []
    body: Dict[str,Any] = {}
    if ep.body_schema and isinstance(ep.body_schema.get("example"), dict):
        body = dict(ep.body_schema["example"])
    for f in PRIV_FIELDS: body[f] = True
    try:
        r = await client.request(ep.method, url,
            headers={**auth, "Content-Type":"application/json"}, content=json.dumps(body))
        if any(f in r.text for f in PRIV_FIELDS) and r.status_code < 400:
            return [_f("mass-assignment", f"{ep.method} {ep.path}", ep.method, "high",
                "Potential mass assignment",
                f"Server echoed back privileged fields (isAdmin, role…) from request body. Status: {r.status_code}",
                f"{ep.method} {url}", r.text[:200])]
    except Exception: pass
    return []


async def _method_override(client, ep, url, auth):
    if ep.method == "GET": return []
    for hdr, val in [("X-HTTP-Method-Override", ep.method),("X-Method-Override", ep.method)]:
        try:
            r = await client.get(url, headers={**auth, hdr: val})
            if r.status_code < 400:
                return [_f("method-override", f"{ep.method} {ep.path}", ep.method, "medium",
                    f"HTTP method override via '{hdr}'",
                    f"GET + {hdr}: {val} returned {r.status_code} — may bypass method-level ACLs.",
                    f"GET {url} {hdr}: {val}", f"Status: {r.status_code}")]
        except Exception: pass
    return []


async def _param_pollution(client, ep, url, auth):
    qp = [p for p in ep.params if p.location == "query"][:1]
    if not qp: return []
    param = qp[0]
    v1 = param.example or "1"
    try:
        r = await client.request(ep.method, f"{url}?{param.name}={v1}&{param.name}=99999", headers=auth)
        if "99999" in r.text and r.status_code < 400:
            return [_f("param-pollution", f"{ep.method} {ep.path}", ep.method, "low",
                f"HTTP param pollution on '{param.name}'",
                f"Server processed duplicate param '{param.name}' with conflicting values.",
                f"{ep.method} {url}?{param.name}={v1}&{param.name}=99999", r.text[:200])]
    except Exception: pass
    return []


SSRF_URLS = ["http://169.254.169.254/latest/meta-data/","http://localhost:6379"]

async def _ssrf(client, ep, url, auth):
    findings = []
    url_params = [p for p in ep.params if p.type == "string" and
                  any(kw in p.name.lower() for kw in ("url","uri","path","redirect","callback","src","href","webhook"))][:2]
    for param in url_params:
        for payload in SSRF_URLS:
            try:
                if param.location == "query":
                    r = await client.request(ep.method, f"{url}?{param.name}={payload}", headers=auth)
                else:
                    r = await client.request(ep.method, url,
                        headers={**auth,"Content-Type":"application/json"},
                        content=json.dumps({param.name: payload}))
                if "ami-id" in r.text or "instance" in r.text.lower():
                    findings.append(_f("ssrf-critical", f"{ep.method} {ep.path}", ep.method, "critical",
                        f"SSRF — cloud metadata via '{param.name}'",
                        f"Parameter '{param.name}' fetched cloud IMDS ({payload}). Credentials may be accessible.",
                        f"{ep.method} {url} {param.name}={payload}", r.text[:200]))
                elif r.status_code not in (400,422,403) and len(r.text) > 10:
                    findings.append(_f("ssrf-potential", f"{ep.method} {ep.path}", ep.method, "medium",
                        f"Potential SSRF via '{param.name}'",
                        f"Server made a request to an internal URL without blocking (status {r.status_code}).",
                        f"{ep.method} {url} {param.name}={payload}", f"Status: {r.status_code}"))
            except Exception: pass
    return findings


async def _rate_limit(client, ep, url, auth):
    try:
        responses = await asyncio.gather(
            *[client.request(ep.method, url, headers=auth) for _ in range(30)],
            return_exceptions=True)
        codes = [r.status_code for r in responses if not isinstance(r, Exception)]
        has_429 = 429 in codes
        has_hdr = any(not isinstance(r, Exception) and
                      any(h in r.headers for h in ("x-ratelimit-limit","retry-after","ratelimit-limit"))
                      for r in responses)
        if not has_429 and not has_hdr:
            return [_f("no-rate-limit", f"{ep.method} {ep.path}", ep.method, "medium",
                "No rate limiting detected",
                f"30 rapid requests returned no 429 or rate-limit headers. Brute-force and DoS risk.",
                f"30x {ep.method} {url}", f"Codes: {set(codes)!r}")]
    except Exception: pass
    return []
