# src/workers/asset_scanner.py
"""
Asset Scanner — runs discovery tools in parallel for CASM.
Tools used:
  - nmap          : port scanning + service/version detection
  - subfinder     : subdomain enumeration (if target is domain)
  - whatweb       : technology fingerprinting
  - ssl check     : certificate expiry via Python ssl module
  - dns lookup    : A, MX, TXT, CNAME records via dnspython/socket
  - http probe    : check HTTP status code
"""
import asyncio
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
from datetime import datetime, timezone
from typing   import Any, Dict, List, Optional
from src.utils.logging import logger


def _find_bin(name: str) -> Optional[str]:
    venv_bin = os.path.join(os.path.dirname(sys.executable), name)
    if os.path.isfile(venv_bin) and os.access(venv_bin, os.X_OK):
        return venv_bin
    return shutil.which(name)


NMAP_BIN      = _find_bin("nmap")
SUBFINDER_BIN = _find_bin("subfinder")
WHATWEB_BIN   = _find_bin("whatweb")


async def run_asset_scan(target: str, asset_type: str) -> Dict[str, Any]:
    """Run all discovery tools and return normalized snapshot."""
    logger.info(f"[asset-scanner] Starting scan: {target} ({asset_type})")

    tasks = [
        _run_nmap(target),
        _run_ssl_check(target) if asset_type == "domain" else asyncio.sleep(0, result=None),
        _run_dns_lookup(target) if asset_type == "domain" else asyncio.sleep(0, result={}),
        _run_http_probe(target),
        _run_whatweb(target),
    ]

    if asset_type == "domain" and SUBFINDER_BIN:
        tasks.append(_run_subfinder(target))
    else:
        tasks.append(asyncio.sleep(0, result=[]))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    nmap_result, ssl_result, dns_result, http_result, whatweb_result, subdomain_result = results

    # Normalize
    open_ports  = nmap_result  if isinstance(nmap_result, list)  else []
    ssl_expiry  = ssl_result   if isinstance(ssl_result, (datetime, type(None))) else None
    dns_records = dns_result   if isinstance(dns_result, dict)   else {}
    http_status = http_result  if isinstance(http_result, int)   else None
    techs       = whatweb_result if isinstance(whatweb_result, list) else []
    subdomains  = subdomain_result if isinstance(subdomain_result, list) else []

    # CVE matching against detected services/versions
    cves = await _match_cves(open_ports, techs)

    snapshot = {
        "subdomains": subdomains,
        "openPorts":  open_ports,
        "techs":      techs,
        "cves":       cves,
        "sslExpiry":  ssl_expiry.isoformat() if ssl_expiry else None,
        "httpStatus": http_status,
        "dnsRecords": dns_records,
    }

    logger.info(
        f"[asset-scanner] Done: {target} — "
        f"{len(subdomains)} subdomains, {len(open_ports)} ports, "
        f"{len(techs)} techs, {len(cves)} CVEs"
    )
    return snapshot


# ── nmap ───────────────────────────────────────────────────────────────────────

async def _run_nmap(target: str) -> List[Dict]:
    if not NMAP_BIN:
        logger.warning("[asset-scanner] nmap not found — skipping port scan")
        return []
    cmd = [
        NMAP_BIN, "-sV", "--version-intensity", "3",
        "-p", "21,22,23,25,53,80,110,143,443,445,465,587,993,995,"
               "1433,1521,2375,2376,3000,3306,3389,5432,5900,6379,"
               "8000,8080,8443,8888,9000,9200,27017",
        "--open",
        "-oX", "-",   # XML to stdout
        target,
    ]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=120)
        return _parse_nmap_xml(stdout.decode(errors="ignore"))
    except asyncio.TimeoutError:
        logger.warning(f"[asset-scanner] nmap timeout for {target}")
        return []
    except Exception as e:
        logger.warning(f"[asset-scanner] nmap error: {e}")
        return []


def _parse_nmap_xml(xml: str) -> List[Dict]:
    """Parse nmap XML output into list of {port, protocol, service, version, state}."""
    import xml.etree.ElementTree as ET
    ports = []
    try:
        root = ET.fromstring(xml)
        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                state_el   = port_el.find("state")
                service_el = port_el.find("service")
                if state_el is None or state_el.get("state") != "open":
                    continue
                ports.append({
                    "port":     int(port_el.get("portid", 0)),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service":  service_el.get("name",    "") if service_el is not None else "",
                    "version":  service_el.get("version", "") if service_el is not None else "",
                    "product":  service_el.get("product", "") if service_el is not None else "",
                })
    except ET.ParseError:
        pass
    return ports


# ── subfinder ─────────────────────────────────────────────────────────────────

async def _run_subfinder(domain: str) -> List[str]:
    cmd = [SUBFINDER_BIN, "-d", domain, "-silent", "-timeout", "30"]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=90)
        lines = stdout.decode(errors="ignore").strip().splitlines()
        return [l.strip() for l in lines if l.strip() and domain in l]
    except asyncio.TimeoutError:
        logger.warning(f"[asset-scanner] subfinder timeout for {domain}")
        return []
    except Exception as e:
        logger.warning(f"[asset-scanner] subfinder error: {e}")
        return []


# ── whatweb ───────────────────────────────────────────────────────────────────

async def _run_whatweb(target: str) -> List[Dict]:
    if not WHATWEB_BIN:
        return []
    url = target if target.startswith("http") else f"https://{target}"
    cmd = [WHATWEB_BIN, "--log-json=-", "--quiet", url]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=30)
        return _parse_whatweb_json(stdout.decode(errors="ignore"))
    except Exception as e:
        logger.debug(f"[asset-scanner] whatweb error: {e}")
        return []


def _parse_whatweb_json(raw: str) -> List[Dict]:
    techs = []
    for line in raw.strip().splitlines():
        if not line.strip():
            continue
        try:
            data = json.loads(line)
            plugins = data.get("plugins", {})
            for name, info in plugins.items():
                version = ""
                if isinstance(info, dict):
                    v = info.get("version", [])
                    version = v[0] if v else ""
                techs.append({"name": name, "version": version, "category": "detected"})
        except (json.JSONDecodeError, Exception):
            continue
    return techs


# ── SSL certificate check ─────────────────────────────────────────────────────

async def _run_ssl_check(domain: str) -> Optional[datetime]:
    """Returns SSL certificate expiry date or None."""
    try:
        loop = asyncio.get_event_loop()
        expiry = await loop.run_in_executor(None, _ssl_expiry_sync, domain)
        return expiry
    except Exception as e:
        logger.debug(f"[asset-scanner] SSL check error for {domain}: {e}")
        return None


def _ssl_expiry_sync(domain: str) -> Optional[datetime]:
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(
            socket.create_connection((domain, 443), timeout=10),
            server_hostname=domain,
        ) as sock:
            cert  = sock.getpeercert()
            expiry_str = cert.get("notAfter", "")
            if expiry_str:
                return datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        pass
    return None


# ── DNS lookup ────────────────────────────────────────────────────────────────

async def _run_dns_lookup(domain: str) -> Dict:
    """Returns A, MX, TXT, CNAME records."""
    loop = asyncio.get_event_loop()
    try:
        return await loop.run_in_executor(None, _dns_lookup_sync, domain)
    except Exception:
        return {}


def _dns_lookup_sync(domain: str) -> Dict:
    records: Dict[str, List] = {"A": [], "MX": [], "TXT": [], "CNAME": []}
    try:
        import dns.resolver  # type: ignore
        for rtype in ["A", "MX", "TXT", "CNAME"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                pass
    except ImportError:
        # Fallback to socket for A records
        try:
            ips = socket.getaddrinfo(domain, None)
            records["A"] = list({r[4][0] for r in ips})
        except Exception:
            pass
    return records


# ── HTTP probe ────────────────────────────────────────────────────────────────

async def _run_http_probe(target: str) -> Optional[int]:
    import httpx
    url = target if target.startswith("http") else f"https://{target}"
    try:
        async with httpx.AsyncClient(timeout=10, follow_redirects=True, verify=False) as client:
            res = await client.head(url)
            return res.status_code
    except Exception:
        # Try http fallback
        try:
            url_http = f"http://{target}"
            async with httpx.AsyncClient(timeout=10, follow_redirects=True) as client:
                res = await client.head(url_http)
                return res.status_code
        except Exception:
            return None


# ── CVE matching ──────────────────────────────────────────────────────────────

async def _match_cves(ports: List[Dict], techs: List[Dict]) -> List[Dict]:
    """
    Cross-reference detected services/versions against NVD CPE data.
    Uses the existing NVD integration if available, otherwise basic matching.
    """
    cves = []
    # Combine service names + versions from nmap and whatweb
    targets = []
    for p in ports:
        if p.get("product") or p.get("service"):
            targets.append({
                "name":    p.get("product") or p.get("service", ""),
                "version": p.get("version", ""),
                "source":  f"port/{p.get('port')}",
            })
    for t in techs:
        if t.get("name") and t.get("version"):
            targets.append({
                "name":    t["name"],
                "version": t["version"],
                "source":  "tech",
            })

    for item in targets[:10]:  # cap to avoid too many API calls
        if not item["version"]:
            continue
        try:
            found = await _nvd_lookup(item["name"], item["version"])
            for cve in found:
                cve["service"] = item["source"]
                cves.append(cve)
        except Exception:
            pass

    return cves[:20]  # cap findings


async def _nvd_lookup(product: str, version: str) -> List[Dict]:
    """Query NVD API for CVEs matching product+version."""
    import httpx, os
    api_key = os.getenv("NVD_API_KEY", "")
    headers = {"apiKey": api_key} if api_key else {}
    keyword = f"{product} {version}".strip()

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params={"keywordSearch": keyword, "resultsPerPage": 5},
                headers=headers,
            )
            if not res.is_success:
                return []
            data = res.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve_data = item.get("cve", {})
                metrics  = cve_data.get("metrics", {})
                # Try CVSS v3 then v2
                severity = "unknown"
                score    = 0.0
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m        = metrics[key][0]
                        cvss     = m.get("cvssData", {})
                        severity = cvss.get("baseSeverity", "unknown").lower()
                        score    = cvss.get("baseScore", 0.0)
                        break
                descs = cve_data.get("descriptions", [])
                desc  = next((d["value"] for d in descs if d.get("lang") == "en"), "")
                cves.append({
                    "id":          cve_data.get("id", ""),
                    "severity":    severity,
                    "score":       score,
                    "description": desc[:200],
                    "product":     product,
                    "version":     version,
                })
            return cves
    except Exception:
        return []
