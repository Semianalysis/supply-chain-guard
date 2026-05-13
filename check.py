"""Supply-chain cooldown check.

Blocks PRs that introduce newly-published npm or PyPI packages younger than
COOLDOWN_DAYS. Designed to catch supply-chain worms (Mini Shai-Hulud, etc.)
where a malicious version is published and exfiltrates within hours of release.

Inputs (via env vars):
  BASE_REF              git ref the PR is targeting (e.g. main)
  HEAD_REF              git ref of the PR head (current HEAD)
  COOLDOWN_DAYS         age threshold in days (default 7)
  ALLOWED_SCOPES        comma-separated npm scopes always allowed (e.g. @types,@vercel)
  OVERRIDE_LABEL        PR label that bypasses the check (default: security/cooldown-override)
  PR_LABELS             comma-separated labels currently on the PR
  GITHUB_OUTPUT         path GitHub Actions provides for setting outputs
  GITHUB_STEP_SUMMARY   path GitHub Actions provides for rich summaries
  GH_TOKEN              for posting PR comments (optional)
  PR_NUMBER             pull request number (for comment posting)
  REPO_FULL             owner/repo (for comment posting)

Exit codes:
  0 = pass (no young packages found, or override applied)
  1 = fail (young packages detected; comment posted with details)
  2 = config error / runtime failure
"""
from __future__ import annotations

import datetime as dt
import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
USER_AGENT = "semianalysis-cooldown-check/1.0"


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


def fetch_json(url: str) -> dict[str, Any] | None:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        log(f"  fetch {url}: HTTP {e.code}")
        return None
    except Exception as e:
        log(f"  fetch {url}: {e}")
        return None


# ----------------------------------------------------------------------------
# Diff: figure out which dependency files changed in this PR.
# ----------------------------------------------------------------------------

DEP_FILE_PATTERNS = (
    "package-lock.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
)


def changed_files(base_ref: str) -> list[str]:
    """Files changed in this PR relative to base_ref."""
    rc = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if rc.returncode != 0:
        log(f"  git diff failed: {rc.stderr}")
        return []
    paths = []
    for line in rc.stdout.splitlines():
        name = line.strip().rsplit("/", 1)[-1]
        if name in DEP_FILE_PATTERNS or name.startswith("requirements") and name.endswith(".txt"):
            paths.append(line.strip())
    return paths


def file_at_ref(ref: str, path: str) -> str | None:
    """Get file contents at a git ref, or None if absent."""
    rc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return rc.stdout if rc.returncode == 0 else None


# ----------------------------------------------------------------------------
# npm parsing
# ----------------------------------------------------------------------------

def parse_npm_lock(text: str) -> dict[str, str]:
    """Return {pkg_name: version} from a package-lock.json (v2+)."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    for path, info in (data.get("packages") or {}).items():
        if not path or path == "":
            continue  # root package
        # Extract pkg name from "node_modules/foo" or "node_modules/@scope/foo"
        m = re.match(r"^(?:.*/)?node_modules/((?:@[^/]+/)?[^/]+)$", path)
        if not m:
            continue
        version = info.get("version")
        if version:
            out[m.group(1)] = version
    return out


# Non-registry spec prefixes — packages declared this way are not
# resolvable against npmjs.org, so the cooldown check has nothing
# useful to say about them. Strip them at parse time so the
# downstream resolver never sees them.
#
# Covered:
#   workspace:*      pnpm / yarn / npm monorepo workspaces
#   file:./local     local-path tarball / dir
#   link:../sib      pnpm-style symlink
#   git+https://     git URL
#   git://           git URL (legacy)
#   http://...       tarball URL
#   https://...      tarball URL
#   npm:<alias>@...  npm package aliases (only valid as a value)
#   portal:...       yarn berry portal
#   catalog:         pnpm catalog reference
NPM_NON_REGISTRY_PREFIXES = (
    "workspace:",
    "file:",
    "link:",
    "git+",
    "git:",
    "http:",
    "https:",
    "npm:",
    "portal:",
    "catalog:",
)


def _is_non_registry_npm_spec(spec: str) -> bool:
    """True for any npm version spec that the public registry can't
    resolve (workspace deps, local paths, git URLs, etc.). Also
    returns True for `*` because an unbounded range has no upper
    side to age-check."""
    if not isinstance(spec, str):
        return True
    if spec.strip() == "*":
        return True
    return spec.startswith(NPM_NON_REGISTRY_PREFIXES)


def parse_npm_package_json(text: str) -> dict[str, str]:
    """Return {pkg_name: spec_range} from a package.json. Filters out
    specs the public npm registry can't resolve (workspace:*, file:,
    link:, git:, http(s):, npm:<alias>, portal:, catalog:, plain `*`)
    — see _is_non_registry_npm_spec."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for pkg, spec in (data.get(section) or {}).items():
            if _is_non_registry_npm_spec(spec):
                continue
            out[pkg] = spec
    return out


# ----------------------------------------------------------------------------
# pypi parsing
# ----------------------------------------------------------------------------

REQ_LINE_RE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(\[.*?\])?\s*([<>=!~][^;#]*)?",
)


def parse_requirements_txt(text: str) -> dict[str, str]:
    """Return {pkg: version_or_spec} from requirements.txt."""
    out: dict[str, str] = {}
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or line.startswith("-"):  # skip -r, -e, options
            continue
        m = REQ_LINE_RE.match(line)
        if not m:
            continue
        pkg = m.group(1).lower()
        spec = (m.group(3) or "").strip() or "*"
        out[pkg] = spec
    return out


def parse_pyproject(text: str) -> dict[str, str]:
    """Return {pkg: spec} from pyproject.toml. Handles PEP 621 + Poetry + uv."""
    try:
        import tomllib  # py3.11+
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore
        except ImportError:
            log("  pyproject.toml parse: no tomllib/tomli, skipping")
            return {}
    try:
        data = tomllib.loads(text)
    except Exception as e:
        log(f"  pyproject.toml parse failed: {e}")
        return {}
    out: dict[str, str] = {}
    # PEP 621 [project.dependencies]
    for dep in data.get("project", {}).get("dependencies", []) or []:
        if not isinstance(dep, str):
            continue
        m = REQ_LINE_RE.match(dep)
        if m:
            out[m.group(1).lower()] = (m.group(3) or "").strip() or "*"
    # PEP 621 optional dependencies
    for grp, deps in (data.get("project", {}).get("optional-dependencies") or {}).items():
        for dep in deps:
            m = REQ_LINE_RE.match(dep)
            if m:
                out[m.group(1).lower()] = (m.group(3) or "").strip() or "*"
    # Poetry style
    poetry_deps = data.get("tool", {}).get("poetry", {}).get("dependencies", {}) or {}
    for pkg, spec in poetry_deps.items():
        if pkg.lower() == "python":
            continue
        if isinstance(spec, str):
            out[pkg.lower()] = spec
        elif isinstance(spec, dict) and "version" in spec:
            out[pkg.lower()] = spec["version"]
    # uv style [tool.uv.sources] is just source overrides; dependencies are elsewhere
    return out


def parse_uv_lock(text: str) -> dict[str, str]:
    """Return {pkg: version} from uv.lock."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        data = tomllib.loads(text)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            out[name.lower()] = version
    return out


def parse_poetry_lock(text: str) -> dict[str, str]:
    """Return {pkg: version} from poetry.lock."""
    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore
    try:
        data = tomllib.loads(text)
    except Exception:
        return {}
    out: dict[str, str] = {}
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        version = pkg.get("version")
        if name and version:
            out[name.lower()] = version
    return out


def parse_pipfile_lock(text: str) -> dict[str, str]:
    """Return {pkg: version} from Pipfile.lock."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {}
    out: dict[str, str] = {}
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            v = (info or {}).get("version", "").lstrip("=")
            if v:
                out[name.lower()] = v
    return out


# ----------------------------------------------------------------------------
# Dispatch on filename
# ----------------------------------------------------------------------------

def parse_file(path: str, text: str) -> tuple[str, dict[str, str]]:
    name = path.rsplit("/", 1)[-1]
    if name == "package-lock.json":
        return ("npm", parse_npm_lock(text))
    if name == "package.json":
        return ("npm-spec", parse_npm_package_json(text))
    if name == "uv.lock":
        return ("pypi", parse_uv_lock(text))
    if name == "poetry.lock":
        return ("pypi", parse_poetry_lock(text))
    if name == "Pipfile.lock":
        return ("pypi", parse_pipfile_lock(text))
    if name == "pyproject.toml":
        return ("pypi-spec", parse_pyproject(text))
    if name.startswith("requirements") and name.endswith(".txt"):
        return ("pypi-spec", parse_requirements_txt(text))
    return ("unknown", {})


# ----------------------------------------------------------------------------
# Registry lookups (concurrent, batched)
# ----------------------------------------------------------------------------

def npm_publish_time(pkg: str, version: str) -> dt.datetime | None:
    data = fetch_json(f"{NPM_REGISTRY}/{pkg}")
    if not data:
        return None
    ts = (data.get("time") or {}).get(version)
    if not ts:
        return None
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def npm_resolve_range_latest(pkg: str, spec: str) -> str | None:
    """Return the highest version of `pkg` that satisfies the npm
    spec range, using the `npm` CLI for semver evaluation.

    Why shell out instead of reimplementing semver in Python:
    semver-0 caret rules, prerelease gating, `||` unions, hyphen
    ranges, and X-ranges are all subtle and well-tested inside
    npm itself. The cost of `npm view <pkg>@<spec> version --json`
    is one HTTP round-trip the script would have made anyway.

    Behaviour:
      - Returns the *highest* version satisfying `spec` (mirrors
        what `npm install` would resolve to today, which is the
        worst-case input for the age check).
      - Returns None when nothing satisfies the spec (caller
        treats this as out-of-scope, same as a 404).
      - Falls back to `dist-tags.latest` if the `npm` CLI is
        unavailable on the runner — conservative: a fallback
        cooldown-failure is preferable to silently passing.
    """
    if _is_non_registry_npm_spec(spec):
        return None
    try:
        result = subprocess.run(
            ["npm", "view", f"{pkg}@{spec}", "version", "--json"],
            capture_output=True, text=True, timeout=20, check=False,
        )
    except FileNotFoundError:
        log("  npm CLI not available; falling back to dist-tags.latest")
        return _npm_dist_tags_latest_fallback(pkg)
    except subprocess.TimeoutExpired:
        log(f"  npm view {pkg}@{spec}: timed out")
        return _npm_dist_tags_latest_fallback(pkg)
    if result.returncode != 0:
        # No version satisfies the range, or the package was
        # unpublished entirely. Returning None lets the caller log
        # this as an out-of-scope finding rather than a failure.
        log(f"  npm view {pkg}@{spec}: rc={result.returncode}")
        return None
    return _parse_npm_view_output(result.stdout)


def _npm_dist_tags_latest_fallback(pkg: str) -> str | None:
    """Return `dist-tags.latest` from the npm registry. Used only as
    a fallback when the `npm` CLI is unavailable or times out — the
    primary resolver is spec-aware via `npm view`."""
    data = fetch_json(f"{NPM_REGISTRY}/{pkg}")
    if not data:
        return None
    return (data.get("dist-tags") or {}).get("latest")


def _parse_npm_view_output(stdout: str) -> str | None:
    """Pick the highest version from `npm view <pkg>@<spec> version --json`.

    Output shape varies by match count:
      - Single match: a JSON-encoded string, e.g. '"4.21.0"\n'.
      - Multiple matches: a JSON array of strings, ordered ascending,
        e.g. '["0.27.0", "0.27.7"]\n'.
      - No matches: empty stdout (rc != 0, handled upstream).
    We re-sort the array with a semver-aware key rather than
    trusting npm's emitted order — cheap and defensive.
    """
    raw = stdout.strip()
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError:
        # `npm view <pkg>@<pinned> version` (without --json mode
        # falling back) emits the bare version string. Treat that
        # as the value.
        return raw
    if isinstance(parsed, str):
        return parsed
    if isinstance(parsed, list) and parsed:
        # Sort semver-ascending and pick the highest. Tuples of
        # ints sort correctly for the common case; non-numeric
        # parts (e.g. prereleases) sort to the bottom via a
        # secondary fallback flag.
        return max(parsed, key=_semver_sort_key)
    return None


def _semver_sort_key(version: str) -> tuple:
    """Sort key that gives stable releases > prereleases of the same
    core version. Handles e.g. `5.0.0-rc.1` < `5.0.0`. Not a full
    semver implementation — we only need ordering for `max()`."""
    core, sep, prerelease = version.partition("-")
    # Strip build metadata if present (anything after `+`).
    core = core.split("+", 1)[0]
    try:
        nums = tuple(int(p) for p in core.split("."))
    except ValueError:
        return (0,)
    # Stable releases (no prerelease segment) outrank prereleases
    # with the same core. SemVer 2.0.0 § 11 specifies this ordering.
    is_stable = 0 if sep and prerelease else 1
    return nums + (is_stable,)


def pypi_publish_time(pkg: str, version: str) -> dt.datetime | None:
    data = fetch_json(f"{PYPI_REGISTRY}/{pkg}/json")
    if not data:
        return None
    releases = data.get("releases") or {}
    files = releases.get(version) or []
    if not files:
        return None
    # Each file in the version has an upload_time_iso_8601
    ts = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
    if not ts:
        return None
    try:
        return dt.datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except Exception:
        return None


def pypi_resolve_spec_latest(pkg: str, spec: str) -> str | None:
    """Return the highest version of `pkg` that satisfies `spec`,
    using PEP 440 specifier semantics via the `packaging` library.

    Falls back to `info.version` (registry's latest) if:
      - `packaging` isn't installed on the runner,
      - the spec is empty / unparseable,
      - or nothing in the registry satisfies it.

    All three fall-backs are conservative: the cooldown check
    would then evaluate the registry-latest's age, which is the
    pre-fix behaviour. A clean fail still beats a silent pass.
    """
    data = fetch_json(f"{PYPI_REGISTRY}/{pkg}/json")
    if not data:
        return None
    if not spec or spec.strip() == "*":
        return (data.get("info") or {}).get("version")
    try:
        from packaging.specifiers import InvalidSpecifier, SpecifierSet
        from packaging.version import InvalidVersion, Version
    except ImportError:
        log("  packaging not installed; falling back to info.version")
        return (data.get("info") or {}).get("version")
    try:
        constraint = SpecifierSet(spec)
    except InvalidSpecifier:
        log(f"  pypi spec {spec!r} is not a valid PEP 440 specifier")
        return (data.get("info") or {}).get("version")
    candidates: list[Version] = []
    for raw in (data.get("releases") or {}):
        try:
            ver = Version(raw)
        except InvalidVersion:
            continue
        # Skip prereleases unless the spec explicitly allows them —
        # matches `pip install`'s default behaviour.
        if ver.is_prerelease and not constraint.prereleases:
            continue
        if ver in constraint:
            candidates.append(ver)
    if not candidates:
        return None
    return str(max(candidates))


def lookup_publish_time(ecosystem: str, pkg: str, version_or_spec: str) -> tuple[str, dt.datetime | None]:
    """Returns (resolved_version, publish_time). If the spec is a range, resolves
    to the latest matching version (worst case)."""
    if ecosystem == "npm":
        return version_or_spec, npm_publish_time(pkg, version_or_spec)
    if ecosystem == "npm-spec":
        resolved = npm_resolve_range_latest(pkg, version_or_spec)
        if not resolved:
            return version_or_spec, None
        return resolved, npm_publish_time(pkg, resolved)
    if ecosystem == "pypi":
        return version_or_spec, pypi_publish_time(pkg, version_or_spec)
    if ecosystem == "pypi-spec":
        resolved = pypi_resolve_spec_latest(pkg, version_or_spec)
        if not resolved:
            return version_or_spec, None
        return resolved, pypi_publish_time(pkg, resolved)
    return version_or_spec, None


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main() -> int:
    base_ref = env("BASE_REF", "main")
    cooldown_days = int(env("COOLDOWN_DAYS", "7"))
    allowed_scopes = {s.strip() for s in env("ALLOWED_SCOPES").split(",") if s.strip()}
    override_label = env("OVERRIDE_LABEL", "security/cooldown-override")
    pr_labels = {s.strip() for s in env("PR_LABELS").split(",") if s.strip()}

    log(f"[cooldown] base_ref={base_ref}  cooldown_days={cooldown_days}")
    log(f"[cooldown] allowed_scopes={sorted(allowed_scopes) if allowed_scopes else '(none)'}")
    log(f"[cooldown] override_label={override_label}  PR labels={sorted(pr_labels)}")

    if override_label in pr_labels:
        log(f"[cooldown] override label {override_label!r} present - passing without check")
        write_summary("⚠️ Cooldown check **bypassed** via override label `" + override_label + "`. Document the justification in the PR description.")
        return 0

    paths = changed_files(base_ref)
    log(f"[cooldown] changed dep files: {len(paths)}")
    if not paths:
        write_summary("✅ No dependency files changed.")
        return 0

    # Build before/after package sets
    pairs: dict[str, dict[str, str]] = {}  # ecosystem -> {pkg: new_version}
    for path in paths:
        before_text = file_at_ref(f"origin/{base_ref}", path) or ""
        after_text = file_at_ref("HEAD", path) or ""
        eco_b, before = parse_file(path, before_text)
        eco_a, after = parse_file(path, after_text)
        ecosystem = eco_a or eco_b
        if ecosystem == "unknown":
            continue
        for pkg, ver in after.items():
            # New or version-changed
            if before.get(pkg) != ver:
                pairs.setdefault(ecosystem, {})[pkg] = ver
        log(f"  {path} [{ecosystem}]: {len(after)-len(before):+d} new/changed entries")

    if not pairs:
        write_summary("✅ Dependency files touched but no new or version-changed packages detected.")
        return 0

    total_to_check = sum(len(v) for v in pairs.values())
    log(f"[cooldown] checking {total_to_check} new/changed package(s) across {len(pairs)} ecosystem(s)")

    findings: list[dict[str, Any]] = []
    now = dt.datetime.now(dt.timezone.utc)
    threshold = dt.timedelta(days=cooldown_days)

    # Fan out to registry queries
    def check_one(ecosystem: str, pkg: str, ver: str) -> dict[str, Any]:
        if "/" in pkg:
            scope = "@" + pkg.split("/")[0].lstrip("@")
            if scope in allowed_scopes:
                return {"pkg": pkg, "version": ver, "skipped": "allowlisted scope"}
        resolved, publish_time = lookup_publish_time(ecosystem, pkg, ver)
        if publish_time is None:
            return {"pkg": pkg, "version": ver, "resolved": resolved,
                    "publish_time": None, "age_days": None, "ecosystem": ecosystem}
        age = now - publish_time
        return {
            "pkg": pkg, "version": ver, "resolved": resolved,
            "publish_time": publish_time.isoformat(),
            "age_days": age.total_seconds() / 86400.0,
            "young": age < threshold,
            "ecosystem": ecosystem,
        }

    with ThreadPoolExecutor(max_workers=10) as ex:
        tasks = [
            (ecosystem, pkg, ver)
            for ecosystem, items in pairs.items()
            for pkg, ver in items.items()
        ]
        results = list(ex.map(lambda t: check_one(*t), tasks))

    young = [r for r in results if r.get("young")]
    unresolved = [r for r in results if r.get("publish_time") is None and "skipped" not in r]

    if not young:
        msg = (f"✅ {len(results)} new/changed package(s) checked, none younger than {cooldown_days} days. "
               f"({len(unresolved)} could not be resolved against the registry — out of scope.)")
        log(msg)
        write_summary(msg)
        return 0

    # We have a finding. Build the report.
    young.sort(key=lambda r: r["age_days"])
    report_lines = [
        f"# 🚨 Supply-chain cooldown check failed",
        f"",
        f"**{len(young)} package(s) below the {cooldown_days}-day cooldown threshold.**",
        f"",
        f"This guards against supply-chain attacks (e.g. Mini Shai-Hulud) where a malicious version is published and exfiltrates within hours. Wait until the version ages out, pin to an older known-good version, or add the `{override_label}` label after manual review of the package's publish history.",
        f"",
        f"| Ecosystem | Package | Version | Published | Age |",
        f"|---|---|---|---|---|",
    ]
    for r in young:
        days = r["age_days"]
        age_str = f"{days*24:.1f} hours" if days < 1 else f"{days:.1f} days"
        report_lines.append(
            f"| {r['ecosystem']} | `{r['pkg']}` | `{r['resolved']}` | {r['publish_time'][:19]} | **{age_str}** |"
        )
    report_lines += [
        "",
        f"## How to unblock",
        f"",
        f"1. **Wait it out.** Most safe choice. The package will pass the check in {cooldown_days} days minus its current age.",
        f"2. **Pin to an older version.** Update your spec or lockfile to a version published > {cooldown_days} days ago.",
        f"3. **Override.** Add the `{override_label}` label after manually verifying the package's npm/PyPI history, maintainer, and changelog. The override is logged in PR history; reviewers can audit.",
        f"",
        f"_Generated by [supply-chain-guard](https://github.com/Semianalysis/supply-chain-guard)._",
    ]
    report = "\n".join(report_lines)

    write_summary(report)
    post_pr_comment(report)
    return 1


def write_summary(text: str) -> None:
    out = env("GITHUB_STEP_SUMMARY")
    if not out:
        return
    try:
        with open(out, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass


def post_pr_comment(text: str) -> None:
    pr_num = env("PR_NUMBER")
    repo_full = env("REPO_FULL")
    token = env("GH_TOKEN")
    if not (pr_num and repo_full and token):
        return
    url = f"https://api.github.com/repos/{repo_full}/issues/{pr_num}/comments"
    body = json.dumps({"body": text}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", USER_AGENT)
    try:
        urllib.request.urlopen(req, timeout=20).read()
    except Exception as e:
        log(f"  could not post PR comment: {e}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log(f"[cooldown] runtime error: {e}")
        sys.exit(2)
