"""Supply-chain cooldown check.

Blocks PRs that introduce newly-published npm or PyPI packages younger than
COOLDOWN_DAYS. Designed to catch supply-chain worms (Mini Shai-Hulud, etc.)
where a malicious version is published and exfiltrates within hours of release.

Also blocks PRs that introduce private-registry URLs (the org's Socket
Firewall proxy, sfw.semianalysis.com) into committed lockfiles: those URLs
401 for every environment without dev credentials (CI, Vercel, Dependabot),
so lockfiles must stay canonical-public. Diff-based: pre-existing entries
in a repo do not fail unrelated PRs.

Lockfile-first: when a changed manifest (package.json, pyproject.toml, a
requirements file's ranges) has a lockfile in its directory (or a parent
lockfile that names its directory, as workspaces do), only the
lockfile-resolved versions are judged. Range resolution against the
registry is the fallback for manifests with no lockfile at all.

Fail closed: a version whose publish date cannot be read after retries
fails the check and is named in the report. The override label is the
escape hatch. Lockfiles the check cannot parse give a warning, not a fail.

Inputs (via env vars):
  BASE_REF              git ref the PR is targeting (e.g. main)
  HEAD_REF              git ref of the PR head (current HEAD)
  COOLDOWN_DAYS         age threshold in days (default 7)
  ALLOWED_SCOPES        comma-separated npm scopes always allowed (e.g. @types,@vercel)
  PRIVATE_REGISTRY_HOSTS comma-separated registry hosts that must never appear
                        in lockfiles (default: sfw.semianalysis.com)
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
import threading
import time
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlparse

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_REGISTRY = "https://pypi.org/pypi"
CRATES_API = "https://crates.io/api/v1/crates"
GO_PROXY = "https://proxy.golang.org"
USER_AGENT = "semianalysis-cooldown-check/1.0"

FETCH_ATTEMPTS = 3
FETCH_BACKOFF_SECONDS = 2.0


def env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def log(msg: str) -> None:
    print(msg, file=sys.stderr, flush=True)


_fetch_cache: dict[str, dict[str, Any] | None] = {}
_fetch_lock = threading.Lock()
_crates_lock = threading.Lock()


def _fetch_once(url: str) -> dict[str, Any]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=20) as r:
        return json.loads(r.read().decode("utf-8"))


def fetch_json(url: str) -> dict[str, Any] | None:
    """GET JSON with retries and a per-run cache. None after the last failed attempt.

    A None publish date is a FAIL in the PR check (fail closed), so a
    transient registry error gets FETCH_ATTEMPTS tries before that happens.
    """
    with _fetch_lock:
        if url in _fetch_cache:
            return _fetch_cache[url]
    data: dict[str, Any] | None = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            if url.startswith(CRATES_API):
                # crates.io asks API clients for at most one request per second.
                with _crates_lock:
                    time.sleep(1.0)
                    data = _fetch_once(url)
            else:
                data = _fetch_once(url)
            break
        except urllib.error.HTTPError as e:
            log(f"  fetch {url}: HTTP {e.code} (attempt {attempt}/{FETCH_ATTEMPTS})")
        except Exception as e:
            log(f"  fetch {url}: {e} (attempt {attempt}/{FETCH_ATTEMPTS})")
        if attempt < FETCH_ATTEMPTS:
            time.sleep(FETCH_BACKOFF_SECONDS * attempt)
    with _fetch_lock:
        _fetch_cache[url] = data
    return data


# ----------------------------------------------------------------------------
# Diff: figure out which dependency files changed in this PR.
# ----------------------------------------------------------------------------

DEP_FILE_PATTERNS = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "package.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "requirements.txt",
    "requirements-dev.txt",
    "requirements-test.txt",
    "pyproject.toml",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
)

# Lockfiles this check knows about but cannot read. A change to one is a
# warning in the summary (never a failure).
UNPARSED_LOCKFILES = (
    "bun.lockb",
    "Gemfile.lock",
    "composer.lock",
    "mix.lock",
    "pubspec.lock",
    "Package.resolved",
    "gradle.lockfile",
    "packages.lock.json",
    "pdm.lock",
    "pixi.lock",
)


def _is_dep_file(name: str) -> bool:
    return name in DEP_FILE_PATTERNS or (name.startswith("requirements") and name.endswith(".txt"))


def _changed_paths(base_ref: str) -> list[str]:
    rc = subprocess.run(
        ["git", "diff", "--name-only", f"origin/{base_ref}...HEAD"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    if rc.returncode != 0:
        log(f"  git diff failed: {rc.stderr}")
        return []
    return [line.strip() for line in rc.stdout.splitlines() if line.strip()]


def changed_files(base_ref: str) -> list[str]:
    """Dependency files changed in this PR relative to base_ref."""
    return [p for p in _changed_paths(base_ref) if _is_dep_file(p.rsplit("/", 1)[-1])]


def changed_unparsed_lockfiles(base_ref: str) -> list[str]:
    return [p for p in _changed_paths(base_ref) if p.rsplit("/", 1)[-1] in UNPARSED_LOCKFILES]


def merge_base_ref(base_ref: str) -> str | None:
    """Commit where the PR branched from base. Lockfile entries present there
    are not new, even if base has moved on since."""
    rc = subprocess.run(
        ["git", "merge-base", f"origin/{base_ref}", "HEAD"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    sha = rc.stdout.strip()
    return sha if rc.returncode == 0 and sha else None


def file_at_ref(ref: str, path: str) -> str | None:
    """Get file contents at a git ref, or None if absent."""
    rc = subprocess.run(
        ["git", "show", f"{ref}:{path}"],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
    return rc.stdout if rc.returncode == 0 else None


# ----------------------------------------------------------------------------
# Private-registry URLs in lockfiles (the sfw tripwire)
# ----------------------------------------------------------------------------
#
# Dev/agent machines resolve through the org's Socket Firewall proxy; npm
# records the resolving host into package-lock.json `resolved` fields (pnpm:
# `tarball:`). Committed, those URLs 401 for every credential-less
# environment: Dependabot ("can't authenticate to a private package
# registry"), Vercel/CI (`npm ci` E401), and Bugbot flags them. The paved
# road is a host-only rewrite back to the public registry — local installs
# still transit the proxy via npm's default `replace-registry-host=npmjs`.
# See PLAN_sfw_registry_architecture (kyle_local vault).

DEFAULT_PRIVATE_REGISTRY_HOSTS = "sfw.semianalysis.com"

# Lockfiles only: manifest files (package.json / pyproject.toml /
# requirements*.txt) never carry resolved URLs, and scanning them would
# false-positive on comments or documentation strings.
LOCKFILE_NAMES = (
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "bun.lock",
    "Pipfile.lock",
    "poetry.lock",
    "uv.lock",
)


def _private_registry_urls(text: str, hosts: list[str]) -> set[str]:
    """Return every URL in `text` whose host portion matches one of `hosts`."""
    if not text:
        return set()
    found: set[str] = set()
    for host in hosts:
        for m in re.finditer(
            r"https?://" + re.escape(host) + r"(?::\d+)?[^\s\"']*", text
        ):
            found.add(m.group(0))
    return found


def private_registry_findings(
    paths: list[str], base_ref: str, hosts: list[str]
) -> list[dict[str, Any]]:
    """Diff-based scan: URLs on private-registry hosts that this PR
    *introduces* into lockfiles. Pre-existing entries (present at the
    base ref) are not findings — the stock is cleaned separately; this
    gates the delta."""
    if not hosts:
        return []
    findings: list[dict[str, Any]] = []
    for path in paths:
        if path.rsplit("/", 1)[-1] not in LOCKFILE_NAMES:
            continue
        before = _private_registry_urls(file_at_ref(f"origin/{base_ref}", path) or "", hosts)
        after = _private_registry_urls(file_at_ref("HEAD", path) or "", hosts)
        for url in sorted(after - before):
            findings.append({"path": path, "url": url})
    return findings


def private_registry_report(findings: list[dict[str, Any]]) -> str:
    lines = [
        "# \U0001f6a8 Private-registry URLs introduced into a lockfile",
        "",
        f"**{len(findings)} URL(s) on the org's Socket Firewall proxy were added to committed lockfiles.**",
        "",
        "These URLs require dev credentials and will **401 in every bot/CI "
        "environment**: Dependabot update runs, Vercel builds, and bare "
        "`npm ci`. Lockfiles must resolve to public registries; local "
        "installs still route through the proxy via npm's default "
        "`replace-registry-host` behavior, so this loses no protection.",
        "",
        "| File | URL |",
        "|---|---|",
    ]
    for f in findings:
        lines.append(f"| `{f['path']}` | `{f['url']}` |")
    lines += [
        "",
        "## How to fix (host-only rewrite; integrity hashes unchanged)",
        "",
        "```bash",
        r"sed -i 's|https://sfw\.semianalysis\.com\(:[0-9]*\)\?/npm/|https://registry.npmjs.org/|g' package-lock.json",
        "```",
        "",
        "then commit the result. "
        "_Generated by [supply-chain-guard](https://github.com/Semianalysis/supply-chain-guard)._",
    ]
    return "\n".join(lines)


# ----------------------------------------------------------------------------
# npm parsing
# ----------------------------------------------------------------------------

def parse_npm_lock(text: str) -> dict[str, str]:
    """Return {pkg_name: version} from a package-lock.json. Kept for
    scan_new_repos; the PR check uses lock_npm() so nested copies of one
    package at different versions are all checked."""
    try:
        return _pairs_to_dict(lock_npm(text).pairs)
    except LockfileError:
        return {}


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
    """Return {pkg: version} from uv.lock (registry packages from PyPI only)."""
    try:
        return _pairs_to_dict(lock_uv(text).pairs)
    except LockfileError:
        return {}


def parse_poetry_lock(text: str) -> dict[str, str]:
    """Return {pkg: version} from poetry.lock (PyPI packages only)."""
    try:
        return _pairs_to_dict(lock_poetry(text).pairs)
    except LockfileError:
        return {}


def parse_pipfile_lock(text: str) -> dict[str, str]:
    """Return {pkg: version} from Pipfile.lock (PyPI packages only)."""
    try:
        return _pairs_to_dict(lock_pipfile(text).pairs)
    except LockfileError:
        return {}


# ----------------------------------------------------------------------------
# Lockfile parsers: exact (name, version) pairs the lockfile resolves to.
#
# Each returns every resolved pair, so two versions of one package (npm
# nested copies) are both checked. Entries that do not come from the public
# registry (workspace links, git, local paths, private registries) are
# skipped and listed, because there is no public publish date to judge.
# The org's sfw proxy fronts the public registries, so its URLs count as public.
# ----------------------------------------------------------------------------

class LockfileError(Exception):
    """The lockfile could not be parsed. The check warns and moves on."""


class LockResult:
    def __init__(self) -> None:
        self.pairs: set[tuple[str, str]] = set()
        self.skipped: list[str] = []


NPM_PUBLIC_HOSTS = {"registry.npmjs.org", "registry.yarnpkg.com", "registry.npmjs.com"}
PYPI_PUBLIC_HOSTS = {"pypi.org", "files.pythonhosted.org", "pypi.python.org"}
MIRROR_HOSTS = {h.strip() for h in DEFAULT_PRIVATE_REGISTRY_HOSTS.split(",") if h.strip()}
CRATES_SOURCES = (
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
)
GO_PRIVATE_PREFIXES = (
    "github.com/semianalysis/",
    "github.com/semianalysis-capital/",
    "github.com/semianalysisai/",
    "github.com/citrini-research/",
)
_SEMVERISH = re.compile(r"^v?\d+(\.\d+)*([\-+.][0-9A-Za-z.\-+]*)?$")


def _pairs_to_dict(pairs: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {name: version for name, version in sorted(pairs)}


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _semverish(version: str) -> bool:
    return bool(_SEMVERISH.match(version))


def _split_name_version(spec: str) -> tuple[str, str] | None:
    """'@scope/name@1.2.3' -> ('@scope/name', '1.2.3')."""
    idx = spec.rfind("@")
    if idx <= 0:
        return None
    return spec[:idx], spec[idx + 1:]


def _npm_public(resolved: str) -> bool:
    if not resolved:
        return True  # npm omits `resolved` for the default registry in some configs
    if resolved.startswith(("http://", "https://")):
        host = _host(resolved)
        return host in NPM_PUBLIC_HOSTS or host in MIRROR_HOSTS
    return False  # git+, file:, link:


def _pypi_public(url: str) -> bool:
    host = _host(url)
    return host in PYPI_PUBLIC_HOSTS or host in MIRROR_HOSTS


def _pypi_norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _add_pypi(out: LockResult, name: str, version: str) -> None:
    if "+" in version:
        out.skipped.append(f"{name}=={version} (local version, not on PyPI)")
        return
    out.pairs.add((_pypi_norm(name), version))


def _toml(text: str) -> dict:
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as e:
        raise LockfileError(f"invalid TOML: {e}") from None


def lock_npm(text: str) -> LockResult:
    """package-lock.json / npm-shrinkwrap.json, lockfileVersion 1, 2 and 3."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LockfileError(f"invalid JSON: {e}") from None
    out = LockResult()
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, info in packages.items():
            if not path or not isinstance(info, dict) or "node_modules/" not in path:
                continue  # root project or a workspace folder
            if info.get("link") or info.get("inBundle"):
                out.skipped.append(f"{path} (link or bundled)")
                continue
            name = info.get("name") or path.rsplit("node_modules/", 1)[1]
            version = str(info.get("version") or "")
            if not _semverish(version):
                out.skipped.append(f"{path} (version {version!r})")
                continue
            if not _npm_public(str(info.get("resolved") or "")):
                out.skipped.append(f"{name}@{version} (non-public source)")
                continue
            out.pairs.add((name, version))
        return out

    def walk(deps: dict) -> None:
        for name, info in deps.items():
            if not isinstance(info, dict):
                continue
            version = str(info.get("version") or "")
            if info.get("bundled"):
                out.skipped.append(f"{name} (bundled)")
            elif _semverish(version) and _npm_public(str(info.get("resolved") or "")):
                out.pairs.add((name, version))
            else:
                out.skipped.append(f"{name}@{version} (non-registry)")
            if isinstance(info.get("dependencies"), dict):
                walk(info["dependencies"])

    if isinstance(data.get("dependencies"), dict):
        walk(data["dependencies"])
    return out


def lock_pnpm(text: str) -> LockResult:
    """pnpm-lock.yaml v5, v6 and v9, read line by line (no YAML library)."""
    m = re.search(r"^lockfileVersion:\s*['\"]?(\d+)", text, re.MULTILINE)
    if not m:
        raise LockfileError("no lockfileVersion line")
    major = int(m.group(1))
    out = LockResult()
    in_packages = False
    for line in text.splitlines():
        if line and not line[0].isspace():
            in_packages = line.rstrip() == "packages:"
            continue
        if not in_packages:
            continue
        km = re.match(r"^  (?! )(['\"]?)(.+?)\1:(\s|$)", line)
        if not km:
            continue
        key = km.group(2).split("(", 1)[0]  # v6/v9 peer suffix
        if major <= 5:
            if not key.startswith("/"):
                out.skipped.append(key)
                continue
            parts = key[1:].split("/")
            if key.startswith("/@") and len(parts) >= 3:
                name, version = parts[0] + "/" + parts[1], parts[2]
            elif not key.startswith("/@") and len(parts) >= 2:
                name, version = parts[0], parts[1]
            else:
                out.skipped.append(key)
                continue
            version = version.split("_", 1)[0]  # v5 peer suffix
        else:
            split = _split_name_version(key.lstrip("/"))
            if split is None:
                out.skipped.append(key)
                continue
            name, version = split
        if not _semverish(version):
            out.skipped.append(key)
            continue
        out.pairs.add((name, version))
    return out


def _yarn_blocks(text: str):
    header: str | None = None
    body: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            if header is not None:
                yield header, body
            header, body = line.rstrip().rstrip(":"), {}
            continue
        if header is None or line.startswith("    "):
            continue  # nested maps such as dependencies
        km = re.match(r"^([\w\-]+):?\s+(.*)$", line.strip())
        if km:
            body[km.group(1)] = km.group(2).strip().strip('"')
    if header is not None:
        yield header, body


def lock_yarn(text: str) -> LockResult:
    """yarn.lock, classic (v1) and berry (v2+)."""
    out = LockResult()
    berry = bool(re.search(r"^__metadata:", text, re.MULTILINE))
    for header, body in _yarn_blocks(text):
        if berry:
            if header.startswith("__metadata"):
                continue
            resolution = body.get("resolution", "")
            idx = resolution.find("@npm:", 1)
            if idx <= 0:
                out.skipped.append(f"{header} (non-npm protocol)")
                continue
            name, version = resolution[:idx], resolution[idx + len("@npm:"):]
        else:
            version, resolved = body.get("version", ""), body.get("resolved", "")
            if not resolved.startswith(("http://", "https://")) or not _npm_public(resolved):
                out.skipped.append(f"{header} (non-public source)")
                continue
            path = urlparse(resolved).path
            if "/-/" not in path:
                out.skipped.append(f"{header} (unrecognised tarball URL)")
                continue
            # Name from the tarball path is alias-proof: /@scope/name/-/name-1.0.0.tgz
            name = path.split("/-/", 1)[0].lstrip("/").replace("%2f", "/").replace("%2F", "/")
        if not _semverish(version):
            out.skipped.append(f"{header} (version {version!r})")
            continue
        out.pairs.add((name, version))
    return out


def _strip_jsonc(text: str) -> str:
    """Remove // comments and trailing commas outside strings (bun.lock is JSONC)."""
    out: list[str] = []
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
        elif c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        elif c == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if not (j < n and text[j] in "}]"):
                out.append(c)
        else:
            out.append(c)
        i += 1
    return "".join(out)


def lock_bun(text: str) -> LockResult:
    """bun.lock (text format, bun 1.2+). The binary bun.lockb is not parsed."""
    try:
        data = json.loads(_strip_jsonc(text))
    except json.JSONDecodeError as e:
        raise LockfileError(f"invalid bun.lock: {e}") from None
    out = LockResult()
    for key, entry in (data.get("packages") or {}).items():
        if not isinstance(entry, list) or not entry or not isinstance(entry[0], str):
            out.skipped.append(str(key))
            continue
        split = _split_name_version(entry[0])
        registry = entry[1] if len(entry) > 1 and isinstance(entry[1], str) else ""
        if split is None or not _semverish(split[1]):
            out.skipped.append(f"{entry[0]} (non-registry)")
            continue
        if registry and not _npm_public(registry):
            out.skipped.append(f"{entry[0]} (non-public source)")
            continue
        out.pairs.add(split)
    return out


def lock_uv(text: str) -> LockResult:
    out = LockResult()
    for pkg in _toml(text).get("package", []) or []:
        name, version = pkg.get("name"), pkg.get("version")
        source = pkg.get("source") or {}
        if not name or not version:
            continue
        registry = source.get("registry") if isinstance(source, dict) else None
        if not registry:
            out.skipped.append(f"{name} (not from a registry)")
        elif not _pypi_public(registry):
            out.skipped.append(f"{name}=={version} (registry {registry})")
        else:
            _add_pypi(out, name, str(version))
    return out


def lock_poetry(text: str) -> LockResult:
    out = LockResult()
    for pkg in _toml(text).get("package", []) or []:
        name, version = pkg.get("name"), pkg.get("version")
        if not name or not version:
            continue
        source = pkg.get("source")
        if isinstance(source, dict) and source:
            stype = source.get("type", "")
            if stype in ("git", "directory", "file", "url") or not _pypi_public(source.get("url", "")):
                out.skipped.append(f"{name}=={version} (source {stype or source.get('url')})")
                continue
        _add_pypi(out, name, str(version))
    return out


def lock_pipfile(text: str) -> LockResult:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        raise LockfileError(f"invalid JSON: {e}") from None
    out = LockResult()
    sources = {s.get("name"): s.get("url", "") for s in (data.get("_meta") or {}).get("sources", []) or []}
    for section in ("default", "develop"):
        for name, info in (data.get(section) or {}).items():
            if not isinstance(info, dict):
                continue
            if any(k in info for k in ("git", "path", "file", "editable")):
                out.skipped.append(f"{name} (not from a registry)")
                continue
            version = str(info.get("version") or "")
            if not version.startswith("=="):
                out.skipped.append(f"{name} (version {version!r})")
                continue
            index = info.get("index")
            if index and index in sources and not _pypi_public(sources[index]):
                out.skipped.append(f"{name}{version} (index {index})")
                continue
            _add_pypi(out, name, version[2:])
    return out


_REQ_PIN_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*===?\s*(?P<version>[^\s;,\\]+)\s*(;.*)?$"
)


def _requirement_lines(text: str):
    """Logical requirement lines: continuations joined, comments and inline --options removed."""
    joined = re.sub(r"\\\r?\n", " ", text)
    for raw in joined.splitlines():
        line = re.sub(r"(^|\s)#.*$", "", raw).strip()
        if line:
            yield line


def lock_requirements_pins(text: str) -> LockResult:
    """`name==version` lines from a requirements file. Ranges are ignored here;
    they are manifest entries (see requirements_ranges)."""
    out = LockResult()
    for line in _requirement_lines(text):
        m_index = re.match(r"^(--index-url|-i)[\s=]+(\S+)", line)
        if m_index:
            if not _pypi_public(m_index.group(2)):
                skipped = out.skipped + [f"whole file (index {m_index.group(2)})"]
                out = LockResult()
                out.skipped = skipped
                return out
            continue
        if line.startswith("-"):
            continue
        line = re.sub(r"\s--\S+", "", line).strip()
        if " @ " in line or "://" in line:
            out.skipped.append(f"{line[:60]} (direct reference)")
            continue
        m = _REQ_PIN_RE.match(line)
        if m and "*" not in m.group("version"):
            _add_pypi(out, m.group("name"), m.group("version"))
    return out


def requirements_ranges(text: str) -> dict[str, str]:
    """Non-pinned requirement lines ({pkg: spec}), for range resolution."""
    out: dict[str, str] = {}
    for line in _requirement_lines(text):
        if line.startswith("-") or " @ " in line or "://" in line:
            continue
        line = re.sub(r"\s--\S+", "", line).strip()
        if _REQ_PIN_RE.match(line):
            continue
        m = REQ_LINE_RE.match(line)
        if m:
            out[m.group(1).lower()] = (m.group(3) or "").strip() or "*"
    return out


def lock_cargo(text: str) -> LockResult:
    out = LockResult()
    for pkg in _toml(text).get("package", []) or []:
        name, version, source = pkg.get("name"), pkg.get("version"), str(pkg.get("source") or "")
        if not name or not version or not source:
            continue  # workspace member
        if not source.startswith(CRATES_SOURCES):
            out.skipped.append(f"{name}@{version} ({source.split('#')[0]})")
            continue
        out.pairs.add((name, str(version)))
    return out


def lock_go(text: str) -> LockResult:
    """go.sum lines that hash module code. `/go.mod`-only lines are module-graph
    entries whose code the build never downloads."""
    out = LockResult()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) != 3 or parts[1].endswith("/go.mod"):
            continue
        module, version = parts[0], parts[1]
        if module.lower().startswith(GO_PRIVATE_PREFIXES):
            out.skipped.append(f"{module} (private module)")
            continue
        out.pairs.add((module, version))
    return out


# filename -> (ecosystem, parser)
LOCKFILE_PARSERS = {
    "package-lock.json": ("npm", lock_npm),
    "npm-shrinkwrap.json": ("npm", lock_npm),
    "pnpm-lock.yaml": ("npm", lock_pnpm),
    "yarn.lock": ("npm", lock_yarn),
    "bun.lock": ("npm", lock_bun),
    "uv.lock": ("pypi", lock_uv),
    "poetry.lock": ("pypi", lock_poetry),
    "Pipfile.lock": ("pypi", lock_pipfile),
    "Cargo.lock": ("cargo", lock_cargo),
    "go.sum": ("go", lock_go),
}

# Manifest name -> lockfiles that pin its ranges.
NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock")
PY_LOCKFILES = ("uv.lock", "poetry.lock", "Pipfile.lock")


def _is_requirements(name: str) -> bool:
    return name.startswith("requirements") and name.endswith(".txt")


def lockfile_pairs(path: str, text: str) -> tuple[str, LockResult] | None:
    """(ecosystem, LockResult) for a lockfile or a requirements file's == pins.
    None for manifests. Raises LockfileError on malformed input."""
    name = path.rsplit("/", 1)[-1]
    try:
        if name in LOCKFILE_PARSERS:
            eco, parser = LOCKFILE_PARSERS[name]
            return eco, parser(text)
        if _is_requirements(name):
            return "pypi", lock_requirements_pins(text)
    except LockfileError:
        raise
    except Exception as e:  # malformed input must never crash the check
        raise LockfileError(f"{type(e).__name__}: {e}") from None
    return None


def covering_lockfile(manifest_path: str, ref: str = "HEAD") -> str | None:
    """Lockfile that resolves this manifest's ranges at `ref`, or None.

    A lockfile in the same directory always counts. A lockfile in a parent
    directory counts when it names the manifest's directory, which is how
    npm, pnpm, yarn, bun and uv workspaces record their members.
    """
    parts = manifest_path.split("/")
    name, directory = parts[-1], parts[:-1]
    if name == "package.json":
        candidates = NPM_LOCKFILES
    elif name == "pyproject.toml" or _is_requirements(name):
        candidates = PY_LOCKFILES
    else:
        return None
    rel_dir = "/".join(directory)
    for depth in range(len(directory), -1, -1):
        prefix = "/".join(directory[:depth])
        for lock in candidates:
            lock_path = f"{prefix}/{lock}" if prefix else lock
            text = file_at_ref(ref, lock_path)
            if text is None:
                continue
            if depth == len(directory) or (rel_dir and rel_dir[len(prefix):].lstrip("/") in text):
                return lock_path
    return None


# ----------------------------------------------------------------------------
# Dispatch on filename (used by scan_new_repos full scans)
# ----------------------------------------------------------------------------

def parse_file(path: str, text: str) -> tuple[str, dict[str, str]]:
    name = path.rsplit("/", 1)[-1]
    if name == "package.json":
        return ("npm-spec", parse_npm_package_json(text))
    if name == "pyproject.toml":
        return ("pypi-spec", parse_pyproject(text))
    if _is_requirements(name):
        return ("pypi-spec", parse_requirements_txt(text))
    if name in LOCKFILE_PARSERS:
        eco, parser = LOCKFILE_PARSERS[name]
        try:
            return (eco, _pairs_to_dict(parser(text).pairs))
        except Exception:
            return (eco, {})
    return ("unknown", {})


# ----------------------------------------------------------------------------
# Registry lookups (concurrent, batched)
# ----------------------------------------------------------------------------

def _parse_ts(ts: str | None) -> dt.datetime | None:
    """ISO 8601 from any registry, as an aware UTC datetime. None if unparseable."""
    if not ts:
        return None
    text = ts.strip().replace("Z", "+00:00")
    text = re.sub(r"(\.\d{6})\d+", r"\1", text)  # Go proxy returns nanoseconds
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def npm_publish_time(pkg: str, version: str) -> dt.datetime | None:
    data = fetch_json(f"{NPM_REGISTRY}/{pkg}")
    if not data:
        return None
    return _parse_ts((data.get("time") or {}).get(version))


def cargo_publish_time(crate: str, version: str) -> dt.datetime | None:
    data = fetch_json(f"{CRATES_API}/{urllib.parse.quote(crate)}/{urllib.parse.quote(version)}")
    if not data:
        return None
    return _parse_ts((data.get("version") or {}).get("created_at"))


def _go_escape(path: str) -> str:
    """Go module proxy case encoding: uppercase becomes '!' + lowercase."""
    return "".join("!" + c.lower() if c.isupper() else c for c in path)


def go_publish_time(module: str, version: str) -> dt.datetime | None:
    if not version.startswith("v"):
        version = "v" + version
    data = fetch_json(f"{GO_PROXY}/{_go_escape(module)}/@v/{_go_escape(version)}.info")
    if not data:
        return None
    return _parse_ts(data.get("Time"))


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
    # PyPI lets a maintainer add new files to an old release, so judge the
    # release by its NEWEST file: a late upload cannot ride on an old date.
    stamps = [_parse_ts(f.get("upload_time_iso_8601") or f.get("upload_time")) for f in files]
    stamps = [t for t in stamps if t is not None]
    return max(stamps) if stamps else None


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
    if ecosystem == "cargo":
        return version_or_spec, cargo_publish_time(pkg, version_or_spec)
    if ecosystem == "go":
        return version_or_spec, go_publish_time(pkg, version_or_spec)
    return version_or_spec, None


# ----------------------------------------------------------------------------
# Age check (shared by the PR check below and scan_new_repos.py)
# ----------------------------------------------------------------------------

def age_check_packages(
    pairs: dict[str, Any],
    cooldown_days: int,
    allowed_scopes: set[str],
) -> list[dict[str, Any]]:
    """Fan out registry lookups and return one result dict per package with
    age/young/skipped fields. `pairs` maps ecosystem to either
    {pkg: version_or_spec} or an iterable of (pkg, version) tuples (lockfiles
    can hold several versions of one package). A result with
    "unresolved": True had no readable publish date after retries."""
    now = dt.datetime.now(dt.timezone.utc)
    threshold = dt.timedelta(days=cooldown_days)

    def check_one(ecosystem: str, pkg: str, ver: str) -> dict[str, Any]:
        if ecosystem.startswith("npm") and pkg.startswith("@") and "/" in pkg:
            scope = "@" + pkg.split("/")[0].lstrip("@")
            if scope in allowed_scopes:
                return {"pkg": pkg, "version": ver, "skipped": "allowlisted scope"}
        resolved, publish_time = lookup_publish_time(ecosystem, pkg, ver)
        if publish_time is None:
            return {"pkg": pkg, "version": ver, "resolved": resolved,
                    "publish_time": None, "age_days": None, "ecosystem": ecosystem,
                    "unresolved": True}
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
            for pkg, ver in (sorted(items.items()) if isinstance(items, dict) else sorted(items))
        ]
        return list(ex.map(lambda t: check_one(*t), tasks))


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------

def main() -> int:
    base_ref = env("BASE_REF", "main")
    cooldown_days = int(env("COOLDOWN_DAYS", "7"))
    allowed_scopes = {s.strip() for s in env("ALLOWED_SCOPES").split(",") if s.strip()}
    override_label = env("OVERRIDE_LABEL", "security/cooldown-override")
    # Labels from the (possibly stale) event payload...
    payload_labels = {s.strip() for s in env("PR_LABELS").split(",") if s.strip()}
    # ...unioned with a live API read so an override added after the PR
    # opened (or applied between re-runs) is honoured immediately. See
    # live_pr_labels() for why the payload alone is not enough.
    pr_labels = payload_labels | live_pr_labels()

    log(f"[cooldown] base_ref={base_ref}  cooldown_days={cooldown_days}")
    log(f"[cooldown] allowed_scopes={sorted(allowed_scopes) if allowed_scopes else '(none)'}")
    log(f"[cooldown] override_label={override_label}  PR labels={sorted(pr_labels)} "
        f"(payload={sorted(payload_labels)})")

    if override_label in pr_labels:
        log(f"[cooldown] override label {override_label!r} present - passing without check")
        write_summary("⚠️ Cooldown check **bypassed** via override label `" + override_label + "`. Document the justification in the PR description.")
        return 0

    paths = changed_files(base_ref)
    log(f"[cooldown] changed dep files: {len(paths)}")
    if not paths:
        write_summary("✅ No dependency files changed.")
        return 0

    # Private-registry tripwire. Runs on every changed lockfile even when no
    # package version changed: a host-only URL edit is exactly the diff shape
    # this check exists to catch.
    private_hosts = [
        h.strip()
        for h in env("PRIVATE_REGISTRY_HOSTS", DEFAULT_PRIVATE_REGISTRY_HOSTS).split(",")
        if h.strip()
    ]
    registry_findings = private_registry_findings(paths, base_ref, private_hosts)
    if registry_findings:
        log(f"[registry] {len(registry_findings)} private-registry URL(s) introduced")

    # Build the set of package versions this PR introduces.
    #
    # Lockfiles (and == pins in requirements files): pairs resolved at HEAD
    # that are in neither the base tip nor the merge base.
    # Manifests (package.json, pyproject.toml, requirements ranges): only when
    # no lockfile covers them (lockfile-first); then each new or changed range
    # resolves to its newest registry match, as before.
    merge_base = merge_base_ref(base_ref)
    old_refs = [f"origin/{base_ref}"] + ([merge_base] if merge_base else [])
    pairs, lockfile_warnings = collect_pairs(paths, old_refs)
    lockfile_warnings += [
        f"`{p}` changed, but this lockfile format is not parsed: package ages NOT checked."
        for p in changed_unparsed_lockfiles(base_ref)
    ]
    for w in lockfile_warnings:
        print(f"::warning::{w}", flush=True)
    warnings_md = ("\n\n### Warnings\n\n" + "\n".join(f"- {w}" for w in lockfile_warnings)) if lockfile_warnings else ""

    if not pairs:
        if registry_findings:
            report = private_registry_report(registry_findings)
            write_summary(report + warnings_md)
            post_pr_comment(report)
            return 1
        write_summary("✅ Dependency files touched but no new or version-changed packages detected." + warnings_md)
        return 0

    total_to_check = sum(len(v) for v in pairs.values())
    log(f"[cooldown] checking {total_to_check} new/changed package(s) across {len(pairs)} ecosystem(s)")

    results = age_check_packages(pairs, cooldown_days, allowed_scopes)

    young = [r for r in results if r.get("young")]
    unresolved = [r for r in results if r.get("unresolved")]

    if not young and not unresolved:
        msg = f"✅ {len(results)} new/changed package(s) checked, none younger than {cooldown_days} days."
        log(msg)
        if registry_findings:
            report = private_registry_report(registry_findings)
            write_summary(msg + "\n\n" + report + warnings_md)
            post_pr_comment(report)
            return 1
        write_summary(msg + warnings_md)
        return 0

    # We have a finding. Build the report.
    young.sort(key=lambda r: r["age_days"])
    report_lines = [
        f"# 🚨 Supply-chain cooldown check failed",
        f"",
    ]
    if young:
        report_lines += [
            f"**{len(young)} package(s) below the {cooldown_days}-day cooldown threshold.**",
            f"",
            f"This guards against supply-chain attacks (e.g. Mini Shai-Hulud) where a malicious version is published and exfiltrates within hours. Wait until the version ages out, pin to an older known-good version, or add the `{override_label}` label after manual review of the package's publish history.",
            f"",
            f"| Ecosystem | Package | Version | Published | Age | Eligible (UTC) |",
            f"|---|---|---|---|---|---|",
        ]
        for r in young:
            days = r["age_days"]
            age_str = f"{days*24:.1f} hours" if days < 1 else f"{days:.1f} days"
            eligible = dt.datetime.fromisoformat(r["publish_time"]) + dt.timedelta(days=cooldown_days)
            report_lines.append(
                f"| {r['ecosystem']} | `{r['pkg']}` | `{r['resolved']}` | {r['publish_time'][:19]} "
                f"| **{age_str}** | {eligible:%Y-%m-%d %H:%M} |"
            )
        report_lines.append("")
    if unresolved:
        report_lines += [
            f"**{len(unresolved)} package version(s) could not be verified.** The registry gave no "
            f"publish date after {FETCH_ATTEMPTS} attempts (registry down, version not published, or "
            f"a private package). The check fails closed: re-run it once the registry answers, or add "
            f"the `{override_label}` label after checking each package by hand.",
            f"",
            f"| Ecosystem | Package | Version |",
            f"|---|---|---|",
        ]
        for r in sorted(unresolved, key=lambda r: (r["ecosystem"], r["pkg"])):
            report_lines.append(f"| {r['ecosystem']} | `{r['pkg']}` | `{r['resolved']}` |")
        report_lines.append("")
    report_lines += [
        f"## How to unblock",
        f"",
        f"1. **Wait it out.** Most safe choice. The package will pass the check in {cooldown_days} days minus its current age.",
        f"2. **Pin to an older version.** Update your spec or lockfile to a version published > {cooldown_days} days ago.",
        f"3. **Override.** Add the `{override_label}` label after manually verifying the package's npm/PyPI history, maintainer, and changelog. The override is logged in PR history; reviewers can audit.",
        f"",
        f"_Generated by [supply-chain-guard](https://github.com/Semianalysis/supply-chain-guard)._",
    ]
    report = "\n".join(report_lines)
    if registry_findings:
        report += "\n\n" + private_registry_report(registry_findings)

    write_summary(report + warnings_md)
    post_pr_comment(report)
    return 1


def collect_pairs(paths: list[str], old_refs: list[str]) -> tuple[dict[str, Any], list[str]]:
    """ecosystem -> new pairs (set of (pkg, version)) or {pkg: spec} for
    manifest ranges, plus warnings for files that could not be parsed."""
    pairs: dict[str, Any] = {}
    warnings: list[str] = []
    for path in paths:
        after_text = file_at_ref("HEAD", path)
        if after_text is None:
            continue  # deleted by the PR
        name = path.rsplit("/", 1)[-1]

        # 1. Lockfile-resolved versions (lockfiles, requirements == pins).
        try:
            parsed = lockfile_pairs(path, after_text)
        except LockfileError as e:
            warnings.append(f"`{path}` could not be parsed ({e}): package ages NOT checked.")
            parsed = None
        if parsed is not None:
            eco, after = parsed
            before: set[tuple[str, str]] = set()
            for ref in old_refs:
                old_text = file_at_ref(ref, path)
                if old_text is None:
                    continue
                try:
                    old = lockfile_pairs(path, old_text)
                except LockfileError:
                    continue  # an unreadable old version only makes the check stricter
                if old is not None:
                    before |= old[1].pairs
            new = after.pairs - before
            if new:
                pairs.setdefault(eco, set()).update(new)
            log(f"  {path} [{eco}]: {len(new)} new version(s), {len(after.skipped)} non-registry entr(y/ies) skipped")

        # 2. Manifest ranges, only when no lockfile resolves them.
        if name not in ("package.json", "pyproject.toml") and not _is_requirements(name):
            continue
        lock = covering_lockfile(path)
        if lock is not None:
            log(f"  {path}: ranges resolved by {lock}; judging lockfile versions only")
            continue
        if name == "package.json":
            eco, parse = "npm-spec", parse_npm_package_json
        elif name == "pyproject.toml":
            eco, parse = "pypi-spec", parse_pyproject
        else:
            eco, parse = "pypi-spec", requirements_ranges
        after_specs = parse(after_text)
        before_specs: dict[str, str] = {}
        for ref in old_refs[:1]:
            before_specs = parse(file_at_ref(ref, path) or "")
        changed = {pkg: spec for pkg, spec in after_specs.items() if before_specs.get(pkg) != spec}
        if changed:
            pairs.setdefault(eco, {}).update(changed)
        log(f"  {path} [{eco}, no lockfile]: {len(changed)} new/changed range(s)")
    return pairs, warnings


def write_summary(text: str) -> None:
    out = env("GITHUB_STEP_SUMMARY")
    if not out:
        return
    try:
        with open(out, "a", encoding="utf-8") as f:
            f.write(text + "\n")
    except OSError:
        pass


def live_pr_labels() -> set[str]:
    """Fetch the PR's labels *live* from the GitHub API.

    Why this exists: the action passes labels in via ``PR_LABELS`` from
    ``github.event.pull_request.labels`` — but that payload is a snapshot
    frozen when the triggering event fired. Two common cases leave it
    stale, so an override label the PR *currently* carries is invisible:

      1. The label is added *after* the PR opened. Re-running the check
         (the "Re-run jobs" button) replays the ORIGINAL event payload —
         GitHub does not refresh ``github.event.*`` on a re-run — so the
         freshly-added label never shows up no matter how many times you
         retry.
      2. Cross-repo Required Workflows are not re-dispatched on every PR
         activity type (e.g. ``labeled``), so no fresh run with the new
         label may ever be produced on its own.

    Reading labels live from ``/issues/{n}`` sidesteps both: the override
    is honoured the instant it's on the PR, without needing a new commit
    or a re-run. Returns an empty set (caller falls back to payload
    labels) if the token/PR context is missing or the request fails —
    never blocks the check on a transient API hiccup.
    """
    pr_num = env("PR_NUMBER")
    repo_full = env("REPO_FULL")
    token = env("GH_TOKEN")
    if not (pr_num and repo_full and token):
        return set()
    url = f"https://api.github.com/repos/{repo_full}/issues/{pr_num}"
    req = urllib.request.Request(url)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            data = json.loads(r.read().decode("utf-8"))
    except Exception as e:
        log(f"  could not fetch live PR labels: {e}")
        return set()
    labels = set()
    for lab in data.get("labels") or []:
        name = lab.get("name") if isinstance(lab, dict) else lab
        if name:
            labels.add(name.strip())
    return labels


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
