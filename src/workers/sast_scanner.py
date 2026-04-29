# src/workers/sast_scanner.py
"""
SAST Scanner — runs three tools in parallel on a shallow git clone:
  1. Semgrep       — static analysis, 200+ security rules across 20+ languages
  2. Trufflehog    — secret / credential detection in code + git history
  3. Dep audit     — npm audit (Node) / pip-audit / safety (Python) dep vuln check

Returns a normalized list of findings in XCloak format.
"""
import os
import json
import shutil
import asyncio
import tempfile
import subprocess
from typing import List, Dict, Any
from src.utils.logging import logger


import sys as _sys
import os as _os

def _find_bin(name: str) -> str:
    """Find binary — checks venv/bin first, then PATH."""
    # Check venv bin directory (same Python as we're running)
    venv_bin = _os.path.join(_os.path.dirname(_sys.executable), name)
    if _os.path.isfile(venv_bin) and _os.access(venv_bin, _os.X_OK):
        return venv_bin
    # Fall back to PATH
    return shutil.which(name) or name

SEMGREP_BIN    = _find_bin("semgrep")
TRUFFLEHOG_BIN = _find_bin("trufflehog")
NPM_BIN        = _find_bin("npm")
PIP_AUDIT_BIN  = _find_bin("pip-audit")

# Semgrep rule packs — all free / open source
SEMGREP_RULES = [
    "p/owasp-top-ten",       # OWASP Top 10 — SQLi, XSS, path traversal, etc.
    "p/secrets",             # Hardcoded secrets, API keys, credentials
    "p/security-audit",      # General security audit rules
    "p/javascript",          # JS/TS specific security rules
    "p/python",              # Python security rules
    "p/java",                # Java security rules
    "p/command-injection",   # OS command injection patterns
    "p/sql-injection",       # SQL injection patterns
]


async def run_sast(
    clone_url:     str,
    commit_sha:    str,
    access_token:  str,
    repo_full_name: str,
) -> List[Dict[str, Any]]:
    """
    Main entry point. Clones the repo, runs all scanners in parallel, returns findings.
    """
    tmpdir = tempfile.mkdtemp(prefix="xcloak_sast_")
    try:
        # ── 1. Shallow clone (only latest commit) ──────────────────────────────
        # cloneUrl from XCloak already contains the token embedded.
        # If it doesn't, embed it now. Either way produce a clean auth URL.
        if "@github.com" in clone_url:
            auth_url = clone_url   # token already embedded by XCloak
        else:
            auth_url = clone_url.replace(
                "https://",
                f"https://x-access-token:{access_token}@",
            )
        logger.info(f"[sast] Cloning {repo_full_name} (full history) into {tmpdir}")
        clone_ok = await _run_cmd(
            ["git", "clone", "--no-tags", auth_url, tmpdir],
            cwd="/tmp",
            timeout=300,
        )
        if not clone_ok:
            # Fallback: build URL from repo name directly
            fallback_url = f"https://x-access-token:{access_token}@github.com/{repo_full_name}.git"
            clone_ok = await _run_cmd(
                ["git", "clone", "--no-tags", fallback_url, tmpdir],
                cwd="/tmp",
                timeout=300,
            )
        if not clone_ok:
            logger.error(f"[sast] Failed to clone {repo_full_name}")
            return []

        # ── 2. Run scanners in parallel ────────────────────────────────────────
        semgrep_task   = asyncio.create_task(_run_semgrep(tmpdir, repo_full_name))
        trufflehog_task = asyncio.create_task(_run_trufflehog(tmpdir, repo_full_name))
        dep_audit_task  = asyncio.create_task(_run_dep_audit(tmpdir, repo_full_name))

        semgrep_findings, trufflehog_findings, dep_findings = await asyncio.gather(
            semgrep_task, trufflehog_task, dep_audit_task,
            return_exceptions=True,
        )

        all_findings: List[Dict] = []
        for result in [semgrep_findings, trufflehog_findings, dep_findings]:
            if isinstance(result, Exception):
                logger.warning(f"[sast] Scanner error: {result}")
            elif isinstance(result, list):
                all_findings.extend(result)

        # Deduplicate by (file, line, rule_id)
        seen: set = set()
        deduped = []
        for f in all_findings:
            key = (f.get("file", ""), f.get("line", 0), f.get("rule_id", ""))
            if key not in seen:
                seen.add(key)
                deduped.append(f)

        logger.info(f"[sast] {repo_full_name}: {len(deduped)} unique findings")
        return deduped

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


# ── Semgrep ────────────────────────────────────────────────────────────────────

async def _run_semgrep(repo_dir: str, repo_full_name: str) -> List[Dict]:
    if not SEMGREP_BIN or not (_os.path.isfile(SEMGREP_BIN) or shutil.which(SEMGREP_BIN)):
        logger.warning("[sast] semgrep not found — skipping")
        return []

    rules = ",".join(SEMGREP_RULES)
    cmd = [
        SEMGREP_BIN, "scan",
        "--config", rules,
        "--json",
        "--no-git-ignore",
        "--timeout", "60",
        "--max-memory", "512",
        "--quiet",
        repo_dir,
    ]

    out, _, rc = await _run_cmd_output(cmd, cwd=repo_dir, timeout=180)
    if not out:
        return []

    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        logger.warning("[sast] semgrep output is not valid JSON")
        return []

    findings = []
    for r in data.get("results", []):
        severity = _semgrep_severity(r.get("extra", {}).get("severity", "INFO"))
        findings.append({
            "tool":      "semgrep",
            "rule_id":   r.get("check_id", "unknown"),
            "severity":  severity,
            "file":      _rel_path(r.get("path", ""), repo_dir),
            "line":      r.get("start", {}).get("line", 0),
            "col":       r.get("start", {}).get("col", 0),
            "message":   r.get("extra", {}).get("message", ""),
            "code":      r.get("extra", {}).get("lines", ""),
            "cwe":       r.get("extra", {}).get("metadata", {}).get("cwe", []),
            "owasp":     r.get("extra", {}).get("metadata", {}).get("owasp", []),
            "fix":       r.get("extra", {}).get("fix", None),
            "repo":      repo_full_name,
        })

    logger.info(f"[sast/semgrep] {len(findings)} findings in {repo_full_name}")
    return findings


def _semgrep_severity(s: str) -> str:
    return {"ERROR": "critical", "WARNING": "high", "INFO": "medium"}.get(s.upper(), "low")


# ── Trufflehog ────────────────────────────────────────────────────────────────

async def _run_trufflehog(repo_dir: str, repo_full_name: str) -> List[Dict]:
    if not TRUFFLEHOG_BIN or not (_os.path.isfile(TRUFFLEHOG_BIN) or shutil.which(TRUFFLEHOG_BIN)):
        logger.warning("[sast] trufflehog not found — skipping")
        return []

    cmd = [
        TRUFFLEHOG_BIN, "git",
        f"file://{repo_dir}",   # scan full git history
        "--json",
        "--no-update",
        "--concurrency", "4",
        "--only-verified",      # skip false positives
    ]

    out, _, _ = await _run_cmd_output(cmd, cwd=repo_dir, timeout=120)
    if not out:
        return []

    findings = []
    for line in out.strip().split("\n"):
        if not line.strip():
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue

        # Each Trufflehog result is a detected secret
        det_type    = r.get("DetectorName", r.get("DetectorType", "secret"))
        # Git mode uses "Git" key, filesystem mode uses "Filesystem"
        data_meta   = r.get("SourceMetadata", {}).get("Data", {})
        source_meta = data_meta.get("Git", data_meta.get("Filesystem", {}))
        file_path   = source_meta.get("file", source_meta.get("File", "unknown"))
        line_num    = source_meta.get("line", source_meta.get("Line", 0))
        commit      = source_meta.get("commit", source_meta.get("Commit", ""))
        raw_secret  = r.get("Raw", "")

        # Redact the secret — show only first 4 chars
        redacted = raw_secret[:4] + "****" if len(raw_secret) > 4 else "****"

        findings.append({
            "tool":      "trufflehog",
            "rule_id":   f"secret.{det_type.lower().replace(' ', '_')}",
            "severity":  "critical",     # secrets are always critical
            "file":      _rel_path(file_path, repo_dir),
            "line":      line_num,
            "col":       0,
            "message":   f"Secret detected: {det_type} — {redacted}" + (f" (commit: {commit[:8]})" if commit else ""),
            "code":      redacted,
            "cwe":       ["CWE-798"],    # Use of Hard-coded Credentials
            "owasp":     ["A07:2021"],   # Identification and Authentication Failures
            "fix":       f"Remove the {det_type} credential and rotate it immediately. Use environment variables or a secrets manager.",
            "repo":      repo_full_name,
            "verified":  r.get("Verified", False),
        })

    logger.info(f"[sast/trufflehog] {len(findings)} secrets in {repo_full_name}")
    return findings


# ── Dependency Audit ──────────────────────────────────────────────────────────

async def _run_dep_audit(repo_dir: str, repo_full_name: str) -> List[Dict]:
    findings = []

    # npm audit (Node.js)
    pkg_json = os.path.join(repo_dir, "package.json")
    if os.path.exists(pkg_json):
        npm_findings = await _run_npm_audit(repo_dir, repo_full_name)
        findings.extend(npm_findings)

    # pip-audit (Python)
    requirements = (
        os.path.join(repo_dir, "requirements.txt")
        or os.path.join(repo_dir, "Pipfile.lock")
        or os.path.join(repo_dir, "pyproject.toml")
    )
    if os.path.exists(os.path.join(repo_dir, "requirements.txt")):
        pip_findings = await _run_pip_audit(repo_dir, repo_full_name)
        findings.extend(pip_findings)

    return findings


async def _run_npm_audit(repo_dir: str, repo_full_name: str) -> List[Dict]:
    # npm audit --json returns structured vuln data
    out, _, _ = await _run_cmd_output(
        [NPM_BIN, "audit", "--json", "--audit-level=moderate"],
        cwd=repo_dir,
        timeout=60,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    findings = []
    vulns = data.get("vulnerabilities", {})
    for pkg_name, info in vulns.items():
        severity = info.get("severity", "moderate")
        via      = info.get("via", [])
        # Get first advisory
        advisory = next((v for v in via if isinstance(v, dict)), {})
        findings.append({
            "tool":     "npm-audit",
            "rule_id":  f"dep.npm.{pkg_name}",
            "severity": _npm_severity(severity),
            "file":     "package.json",
            "line":     0,
            "col":      0,
            "message":  f"Vulnerable dependency: {pkg_name}@{info.get('range', '?')} — {advisory.get('title', severity + ' severity')}",
            "code":     f"{pkg_name}: {info.get('range', '?')}",
            "cwe":      advisory.get("cwe", []),
            "owasp":    ["A06:2021"],   # Vulnerable and Outdated Components
            "fix":      f"Run `npm audit fix` or update {pkg_name} to a patched version",
            "repo":     repo_full_name,
        })

    logger.info(f"[sast/npm-audit] {len(findings)} dep vulns in {repo_full_name}")
    return findings


def _npm_severity(s: str) -> str:
    return {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}.get(s, "medium")


async def _run_pip_audit(repo_dir: str, repo_full_name: str) -> List[Dict]:
    if not shutil.which(PIP_AUDIT_BIN):
        return []

    out, _, _ = await _run_cmd_output(
        [PIP_AUDIT_BIN, "--format", "json", "-r", "requirements.txt"],
        cwd=repo_dir,
        timeout=60,
    )
    if not out:
        return []
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return []

    findings = []
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            findings.append({
                "tool":     "pip-audit",
                "rule_id":  f"dep.pip.{vuln.get('id', 'unknown')}",
                "severity": "high",
                "file":     "requirements.txt",
                "line":     0,
                "col":      0,
                "message":  f"{dep.get('name')}=={dep.get('version')} — {vuln.get('description', '')}",
                "code":     f"{dep.get('name')}=={dep.get('version')}",
                "cwe":      [],
                "owasp":    ["A06:2021"],
                "fix":      f"Upgrade to: {', '.join(vuln.get('fix_versions', ['latest']))}",
                "repo":     repo_full_name,
            })

    logger.info(f"[sast/pip-audit] {len(findings)} dep vulns in {repo_full_name}")
    return findings


# ── Async subprocess helpers ───────────────────────────────────────────────────

async def _run_cmd(cmd: list, cwd: str, timeout: int = 60) -> bool:
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout)
        return proc.returncode == 0
    except (asyncio.TimeoutError, Exception) as e:
        logger.warning(f"[sast] cmd failed: {cmd[0]} — {e}")
        return False


async def _run_cmd_output(cmd: list, cwd: str, timeout: int = 60):
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        return stdout.decode(errors="ignore"), stderr.decode(errors="ignore"), proc.returncode
    except asyncio.TimeoutError:
        logger.warning(f"[sast] timeout running: {cmd[0]}")
        return "", "", -1
    except Exception as e:
        logger.warning(f"[sast] error running {cmd[0]}: {e}")
        return "", "", -1


def _rel_path(path: str, base: str) -> str:
    """Strip tmpdir prefix from file paths."""
    if path.startswith(base):
        return path[len(base):].lstrip("/")
    return path
