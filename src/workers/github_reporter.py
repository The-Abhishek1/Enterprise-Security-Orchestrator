# src/workers/github_reporter.py
"""
GitHub Reporter — posts SAST findings as PR review comments.
Also calls back to XCloak to update RepoScan status in Prisma.
"""
import os
import json
import httpx
from typing import List, Dict, Any, Optional
from src.utils.logging import logger

# Do NOT use os.getenv at module level — pydantic-settings doesn't populate os.environ
# Read from settings object or lazily inside functions
GH_API          = "https://api.github.com"
GH_API_VERSION  = "2022-11-28"

SEVERITY_EMOJI = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

TOOL_LABEL = {
    "semgrep":    "Semgrep SAST",
    "trufflehog": "Trufflehog Secrets",
    "npm-audit":  "npm audit",
    "pip-audit":  "pip-audit",
}


async def update_scan_status(
    scan_id:  str,
    status:   str,
    findings: Optional[List[Dict]] = None,
    error:    Optional[str] = None,
):
    """
    Calls XCloak's internal API to update the RepoScan record in Prisma.
    XCloak owns the Prisma DB — ESO calls back to update it.
    """
    payload: Dict[str, Any] = {"scanId": scan_id, "status": status}

    if findings is not None:
        payload["findings"]  = len(findings)
        payload["criticals"] = sum(1 for f in findings if f.get("severity") == "critical")
        payload["highs"]     = sum(1 for f in findings if f.get("severity") == "high")
        payload["result"]    = {"findings": findings}

    if error:
        payload["error"] = error

    try:
        from src.core.config import get_settings as _gs
        _s = _gs()
        xcloak_url      = _s.xcloak_url
        internal_secret = _s.internal_email_secret
        async with httpx.AsyncClient(timeout=10) as client:
            res = await client.post(
                f"{xcloak_url}/api/v1/github/scan-update",
                json=payload,
                headers={"X-Internal-Secret": internal_secret},
            )
            if not res.is_success:
                logger.warning(f"[reporter] scan-update {scan_id} returned {res.status_code}: {res.text[:200]}")
    except Exception as e:
        logger.error(f"[reporter] failed to update scan {scan_id}: {e}")


async def post_pr_comments(
    repo_full_name: str,
    pr_number:      int,
    commit_sha:     str,
    findings:       List[Dict],
    access_token:   str,
):
    """
    Posts a PR review with inline comments for each finding.
    Groups findings into one review so GitHub doesn't get spammed.
    """
    if not findings:
        await _post_clean_review(repo_full_name, pr_number, commit_sha, access_token)
        return

    headers = _gh_headers(access_token)

    # Fetch PR diff to get valid positions for inline comments
    diff_map = await _fetch_pr_diff_positions(repo_full_name, pr_number, access_token)

    # Build review comments (inline) for findings we can map to diff positions
    review_comments = []
    orphaned = []  # findings we can't place inline

    for f in findings:
        file_path = f.get("file", "")
        line      = f.get("line", 0)
        pos       = diff_map.get((file_path, line))

        comment_body = _format_finding_comment(f)

        if pos and file_path:
            review_comments.append({
                "path":     file_path,
                "position": pos,
                "body":     comment_body,
            })
        else:
            orphaned.append(f)

    # Build summary body
    summary = _build_pr_summary(findings, orphaned)

    # Post the review
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            payload = {
                "commit_id": commit_sha,
                "body":      summary,
                "event":     "COMMENT",
                "comments":  review_comments[:30],  # GitHub limit: 30 inline comments per review
            }
            res = await client.post(
                f"{GH_API}/repos/{repo_full_name}/pulls/{pr_number}/reviews",
                json=payload,
                headers=headers,
            )
            if res.is_success:
                logger.info(f"[reporter] Posted review on {repo_full_name}#{pr_number} with {len(review_comments)} inline comments")
            else:
                logger.warning(f"[reporter] Review post failed ({res.status_code}): {res.text[:300]}")

                # Fallback: post as a regular PR comment
                await _post_pr_comment(repo_full_name, pr_number, summary, access_token)

    except Exception as e:
        logger.error(f"[reporter] PR comment error: {e}")
        # Fallback: post summary as PR comment
        try:
            await _post_pr_comment(repo_full_name, pr_number, summary, access_token)
        except Exception:
            pass


async def _post_clean_review(
    repo_full_name: str,
    pr_number:      int,
    commit_sha:     str,
    access_token:   str,
):
    """Posts a clean bill of health when no findings."""
    body = (
        "## 🛡 XCloak Security Scan\n\n"
        "✅ **No security issues found**\n\n"
        "Scanned with:\n"
        "- Semgrep (OWASP Top 10, secrets, injection patterns)\n"
        "- Trufflehog (credentials and API key detection)\n"
        "- Dependency audit (known vulnerable packages)\n\n"
        "*Powered by [XCloak](https://xcloak.tech)*"
    )
    await _post_pr_comment(repo_full_name, pr_number, body, access_token)


def _format_finding_comment(f: Dict) -> str:
    severity = f.get("severity", "medium")
    emoji    = SEVERITY_EMOJI.get(severity, "⚪")
    tool     = TOOL_LABEL.get(f.get("tool", ""), f.get("tool", "scanner"))
    rule     = f.get("rule_id", "")
    message  = f.get("message", "")
    fix      = f.get("fix", "")
    cwes     = f.get("cwe", [])
    owasps   = f.get("owasp", [])

    lines = [
        f"{emoji} **[{severity.upper()}]** {message}",
        f"",
        f"**Rule:** `{rule}`  |  **Tool:** {tool}",
    ]
    if cwes:
        lines.append(f"**CWE:** {', '.join(cwes) if isinstance(cwes, list) else cwes}")
    if owasps:
        lines.append(f"**OWASP:** {', '.join(owasps) if isinstance(owasps, list) else owasps}")
    if fix:
        lines.append(f"\n**Remediation:** {fix}")

    lines.append(f"\n*[XCloak SAST](https://xcloak.tech/github)*")
    return "\n".join(lines)


def _build_pr_summary(findings: List[Dict], orphaned: List[Dict]) -> str:
    total     = len(findings)
    criticals = sum(1 for f in findings if f.get("severity") == "critical")
    highs     = sum(1 for f in findings if f.get("severity") == "high")
    mediums   = sum(1 for f in findings if f.get("severity") == "medium")
    lows      = sum(1 for f in findings if f.get("severity") in ("low", "info"))

    status_emoji = "🔴" if criticals > 0 else "🟠" if highs > 0 else "🟡" if mediums > 0 else "🔵"

    lines = [
        f"## {status_emoji} XCloak Security Scan — {total} finding{'s' if total != 1 else ''} found\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    if criticals: lines.append(f"| 🔴 Critical | {criticals} |")
    if highs:     lines.append(f"| 🟠 High     | {highs} |")
    if mediums:   lines.append(f"| 🟡 Medium   | {mediums} |")
    if lows:      lines.append(f"| 🔵 Low      | {lows} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    # List orphaned findings (can't be placed inline) in the summary
    if orphaned:
        lines.append(f"\n### Additional findings ({len(orphaned)} couldn't be placed inline)\n")
        for f in orphaned[:20]:
            emoji   = SEVERITY_EMOJI.get(f.get("severity", "medium"), "⚪")
            file_   = f.get("file", "?")
            line_   = f.get("line", 0)
            rule    = f.get("rule_id", "")
            message = f.get("message", "")[:120]
            lines.append(f"- {emoji} **{f.get('severity','?').upper()}** `{file_}:{line_}` — {message}")

    lines.append(f"\n*Powered by [XCloak Security Platform](https://xcloak.tech/github)*")
    return "\n".join(lines)


async def _post_pr_comment(
    repo_full_name: str,
    pr_number:      int,
    body:           str,
    access_token:   str,
):
    async with httpx.AsyncClient(timeout=15) as client:
        await client.post(
            f"{GH_API}/repos/{repo_full_name}/issues/{pr_number}/comments",
            json={"body": body},
            headers=_gh_headers(access_token),
        )


async def _fetch_pr_diff_positions(
    repo_full_name: str,
    pr_number:      int,
    access_token:   str,
) -> Dict[tuple, int]:
    """
    Fetches the PR diff and builds a map of (file_path, line_number) → diff_position.
    Diff positions are required for inline PR review comments.
    """
    position_map: Dict[tuple, int] = {}
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            res = await client.get(
                f"{GH_API}/repos/{repo_full_name}/pulls/{pr_number}/files",
                headers={**_gh_headers(access_token), "Accept": "application/vnd.github+json"},
                params={"per_page": 100},
            )
            if not res.is_success:
                return position_map

            files = res.json()
            for file_info in files:
                filename = file_info.get("filename", "")
                patch    = file_info.get("patch", "")
                if not patch:
                    continue
                # Parse patch to build line → position mapping
                position  = 0
                curr_line = 0
                for patch_line in patch.split("\n"):
                    position += 1
                    if patch_line.startswith("@@"):
                        # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
                        try:
                            new_info = patch_line.split("+")[1].split("@@")[0].strip()
                            curr_line = int(new_info.split(",")[0]) - 1
                        except (IndexError, ValueError):
                            pass
                    elif patch_line.startswith("+"):
                        curr_line += 1
                        position_map[(filename, curr_line)] = position
                    elif not patch_line.startswith("-"):
                        curr_line += 1

    except Exception as e:
        logger.warning(f"[reporter] diff fetch failed: {e}")

    return position_map


def _gh_headers(access_token: str) -> Dict[str, str]:
    return {
        "Authorization":        f"Bearer {access_token}",
        "Accept":               "application/vnd.github+json",
        "X-GitHub-Api-Version": GH_API_VERSION,
    }
