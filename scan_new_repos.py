"""Full-scan cooldown audit for newly created repos.

Why this exists: the org-level Required Workflow only runs on pull
requests, so the push that *creates* a repo's default branch (initial
commit, GitHub's "Add README" auto-init, `gh repo create --push`) is
never checked. With `do_not_enforce_on_create: true` on the ruleset
(required — otherwise repo creation is blocked outright, see PR #8),
a brand-new repo can land day-old packages in its initial commit and
the PR check will never re-examine them: it only diffs changes against
the base branch, so anything present at creation is grandfathered.

This script closes that gap after the fact. It runs on a daily
schedule, finds repos created within LOOKBACK_DAYS, and audits the
*entire contents* of every dependency file on the default branch (not
a diff) against the cooldown threshold. Violations can't be blocked —
the commit already landed — so they're reported: the job fails red,
writes a step summary, and optionally posts to Slack.

Inputs (via env vars):
  GH_TOKEN              token with org repo read access (required)
  ORG                   GitHub org to scan (default: Semianalysis)
  LOOKBACK_DAYS         scan repos created within this window (default 2;
                        overlaps the daily cadence so a missed run can't
                        skip a repo)
  COOLDOWN_DAYS         age threshold in days (default 7)
  ALLOWED_SCOPES        comma-separated npm scopes always allowed
  SLACK_BOT_TOKEN       optional; post findings via chat.postMessage
  SLACK_CHANNEL_ID      optional; channel for the Slack post
  GITHUB_STEP_SUMMARY   provided by Actions for rich summaries

Exit codes:
  0 = no young packages in any newly created repo
  1 = violations found (reported in summary / Slack)
  2 = config error / runtime failure
"""
from __future__ import annotations

import datetime as dt
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

from check import (
    DEP_FILE_PATTERNS,
    USER_AGENT,
    age_check_packages,
    env,
    log,
    parse_file,
    write_summary,
)

GITHUB_API = "https://api.github.com"


# ----------------------------------------------------------------------------
# GitHub API (authenticated — check.py's fetch_json is anonymous-registry only)
# ----------------------------------------------------------------------------

def gh_get(
    path: str,
    token: str,
    accept: str = "application/vnd.github+json",
    missing_ok: bool = False,
) -> Any:
    """GET a GitHub API path. With missing_ok, 404/409 return None —
    only appropriate for per-repo lookups where absence is expected
    (empty repo, file vanished between tree and contents calls). Calls
    where a 404 means misconfiguration (bad org, token without access)
    must leave missing_ok off so the scan fails loudly instead of
    reporting a clean run."""
    req = urllib.request.Request(
        f"{GITHUB_API}{path}",
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": accept,
            "User-Agent": USER_AGENT,
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if missing_ok and e.code in (404, 409):
            return None
        raise
    return body if accept.endswith(".raw") else json.loads(body)


def recent_repos(org: str, token: str, lookback_days: int) -> list[dict[str, Any]]:
    """Org repos created within the lookback window."""
    cutoff = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=lookback_days)
    out: list[dict[str, Any]] = []
    page = 1
    while True:
        repos = gh_get(
            f"/orgs/{org}/repos?sort=created&direction=desc&per_page=100&page={page}",
            token,
        )
        if not repos:
            break
        for repo in repos:
            created = dt.datetime.fromisoformat(repo["created_at"].replace("Z", "+00:00"))
            if created < cutoff:
                return out
            out.append(repo)
        page += 1
    return out


def is_dep_file(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    if name in DEP_FILE_PATTERNS:
        return True
    return name.startswith("requirements") and name.endswith(".txt")


def repo_dep_files(org: str, repo: str, default_branch: str, token: str) -> list[str]:
    """Paths of all dependency files on the default branch."""
    # Quote the branch: names like "releases/main" would otherwise split
    # into extra URL path segments and 404.
    branch = urllib.parse.quote(default_branch, safe="")
    tree = gh_get(
        f"/repos/{org}/{repo}/git/trees/{branch}?recursive=1", token, missing_ok=True
    )
    if not tree:
        return []
    if tree.get("truncated"):
        log(f"  {repo}: tree listing truncated — very large repo, results may be partial")
    return [
        node["path"]
        for node in tree.get("tree", [])
        if node.get("type") == "blob"
        and is_dep_file(node["path"])
        and "node_modules/" not in node["path"]
    ]


def full_scan_pairs(files: list[tuple[str, str]]) -> dict[str, dict[str, str]]:
    """Parse (path, text) dep files into {ecosystem: {pkg: version_or_spec}}.

    Unlike the PR check there is no base to diff against — every package
    present is treated as new and gets age-checked.
    """
    pairs: dict[str, dict[str, str]] = {}
    for path, text in files:
        ecosystem, packages = parse_file(path, text)
        if ecosystem == "unknown":
            continue
        for pkg, ver in packages.items():
            pairs.setdefault(ecosystem, {})[pkg] = ver
    return pairs


# ----------------------------------------------------------------------------
# Reporting
# ----------------------------------------------------------------------------

def format_report(violations: dict[str, list[dict[str, Any]]], cooldown_days: int) -> str:
    lines = [
        "# 🚨 New-repo cooldown scan: violations found",
        "",
        f"Packages younger than {cooldown_days} days landed in newly created "
        "repos via their initial commits, which required workflows cannot check. "
        "Review each package's publish history before trusting it.",
        "",
        "| Repo | Ecosystem | Package | Version | Published | Age |",
        "|---|---|---|---|---|---|",
    ]
    for repo, findings in sorted(violations.items()):
        for r in sorted(findings, key=lambda r: r["age_days"]):
            days = r["age_days"]
            age_str = f"{days*24:.1f} hours" if days < 1 else f"{days:.1f} days"
            lines.append(
                f"| `{repo}` | {r['ecosystem']} | `{r['pkg']}` | `{r['resolved']}` "
                f"| {r['publish_time'][:19]} | **{age_str}** |"
            )
    lines += [
        "",
        "_Generated by [supply-chain-guard](https://github.com/Semianalysis/supply-chain-guard) new-repo scan._",
    ]
    return "\n".join(lines)


def format_slack_message(violations: dict[str, list[dict[str, Any]]], cooldown_days: int) -> str:
    lines = [
        f":rotating_light: *New-repo cooldown scan* — packages younger than "
        f"{cooldown_days} days found in newly created repos (initial commits "
        "bypass the PR check):",
    ]
    for repo, findings in sorted(violations.items()):
        pkgs = ", ".join(
            f"`{r['pkg']}@{r['resolved']}` ({r['age_days']:.1f}d)"
            for r in sorted(findings, key=lambda r: r["age_days"])
        )
        lines.append(f"• <https://github.com/{repo}|{repo}>: {pkgs}")
    lines.append("Review publish history before trusting these packages.")
    return "\n".join(lines)


def post_slack(text: str) -> None:
    token = env("SLACK_BOT_TOKEN")
    channel = env("SLACK_CHANNEL_ID")
    if not (token and channel):
        log("[scan] Slack not configured (SLACK_BOT_TOKEN / SLACK_CHANNEL_ID) — skipping post")
        return
    body = json.dumps({"channel": channel, "text": text}).encode("utf-8")
    req = urllib.request.Request(
        "https://slack.com/api/chat.postMessage",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": USER_AGENT,
        },
    )
    try:
        resp = json.loads(urllib.request.urlopen(req, timeout=20).read())
        if not resp.get("ok"):
            log(f"[scan] Slack post failed: {resp.get('error')}")
    except Exception as e:
        log(f"[scan] Slack post failed: {e}")


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main() -> int:
    token = env("GH_TOKEN")
    if not token:
        log("[scan] GH_TOKEN is required")
        return 2
    org = env("ORG", "Semianalysis")
    lookback_days = int(env("LOOKBACK_DAYS", "2"))
    cooldown_days = int(env("COOLDOWN_DAYS", "7"))
    allowed_scopes = {s.strip() for s in env("ALLOWED_SCOPES").split(",") if s.strip()}

    log(f"[scan] org={org}  lookback_days={lookback_days}  cooldown_days={cooldown_days}")

    repos = recent_repos(org, token, lookback_days)
    log(f"[scan] {len(repos)} repo(s) created in the last {lookback_days} day(s)")
    if not repos:
        write_summary(f"✅ No repos created in the last {lookback_days} day(s).")
        return 0

    violations: dict[str, list[dict[str, Any]]] = {}
    scanned: list[str] = []
    for repo in repos:
        full_name = repo["full_name"]
        name = repo["name"]
        branch = repo.get("default_branch") or "main"
        paths = repo_dep_files(org, name, branch, token)
        log(f"  {full_name} (created {repo['created_at']}): {len(paths)} dep file(s)")
        if not paths:
            scanned.append(full_name)
            continue
        files = []
        for path in paths:
            quoted_path = urllib.parse.quote(path)
            quoted_branch = urllib.parse.quote(branch, safe="")
            text = gh_get(
                f"/repos/{org}/{name}/contents/{quoted_path}?ref={quoted_branch}",
                token,
                accept="application/vnd.github.raw",
                missing_ok=True,
            )
            if text is not None:
                files.append((path, text))
        pairs = full_scan_pairs(files)
        total = sum(len(v) for v in pairs.values())
        log(f"    {total} package(s) to age-check")
        results = age_check_packages(pairs, cooldown_days, allowed_scopes)
        young = [r for r in results if r.get("young")]
        if young:
            violations[full_name] = young
        scanned.append(full_name)

    if not violations:
        msg = (f"✅ Scanned {len(scanned)} newly created repo(s), no packages "
               f"younger than {cooldown_days} days: {', '.join(scanned)}")
        log(msg)
        write_summary(msg)
        return 0

    report = format_report(violations, cooldown_days)
    log(report)
    write_summary(report)
    post_slack(format_slack_message(violations, cooldown_days))
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"[scan] runtime error: {e}")
        sys.exit(2)
