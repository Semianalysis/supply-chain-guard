"""main-promotion-guard: decide whether a PR may target `main`.

Each repo keeps a small workflow, `.github/workflows/main-promotion-guard.yml`
(canonical copy: templates/main-promotion-guard.yml). Its job is named
`main-promotion-guard`, because repo rulesets require a check with that exact
name. The job checks out this repo and runs this script, so the rules live in
one place.

A same-repo PR into main passes when ONE of these is true:

1. Promotion: the head branch is `staging`.
2. Dependabot: the author is `dependabot[bot]`. GitHub raises security updates
   against the default branch only.
3. Security hotfix: the author is a dependabot-autopilot app, OR the PR has the
   `security/hotfix` label, AND every changed file is a dependency file:
   - lockfiles (package-lock.json, pnpm-lock.yaml, yarn.lock, bun.lock,
     uv.lock, poetry.lock, Pipfile.lock, Cargo.lock, go.sum, ...), and
     requirements*.txt / constraints*.txt;
   - package.json and pyproject.toml, but only their dependency fields may
     change (scripts, build settings and everything else must stay equal).
   No file may be removed or renamed.
4. Guard update: the only change is this workflow file, and its new content is
   exactly one of the canonical templates. This lets the guard itself be rolled out.

Everything else fails, as before. Forks never pass. The usual required checks
(CI, cooldown-check) still apply to every PR; this script only decides the
route into main.

Standard library only. Needs GITHUB_TOKEN (contents: read, pull-requests: read),
GITHUB_EVENT_PATH and GITHUB_API_URL, as set by GitHub Actions.
"""

from __future__ import annotations

import base64
import fnmatch
import json
import os
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

HOTFIX_LABEL = "security/hotfix"
GUARD_PATH = ".github/workflows/main-promotion-guard.yml"
TEMPLATES = [Path(__file__).resolve().parent / "templates" / n
             for n in ("main-promotion-guard.yml", "main-promotion-guard-target.yml")]

AUTOPILOT_APPS = {
    "sa-dependabot-autopilot[bot]",
    "sa-dependabot-autopilot-capital[bot]",
    "sa-dependabot-autopilot-ai[bot]",
    "sa-dependabot-autopilot-citrini[bot]",
}

# Files that only pin or lock dependency versions. Matched on the basename.
LOCK_PATTERNS = [
    "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock",
    "bun.lock", "bun.lockb", "uv.lock", "poetry.lock", "Pipfile.lock", "pdm.lock",
    "Cargo.lock", "go.sum", "Gemfile.lock", "composer.lock",
    "requirements*.txt", "requirements*.in", "constraints*.txt",
]
# Manifests where only the dependency fields may change.
MANIFESTS = {"package.json", "pyproject.toml"}

PACKAGE_JSON_DEP_KEYS = {
    "dependencies", "devDependencies", "optionalDependencies", "peerDependencies",
    "overrides", "resolutions",
}

Fetch = Callable[[str], Any]


class GuardError(Exception):
    pass


# --------------------------------------------------------------------------
# GitHub access
# --------------------------------------------------------------------------
def make_fetch(token: str, api: str) -> Fetch:
    def fetch(path: str) -> Any:
        req = urllib.request.Request(
            api.rstrip("/") + path,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "main-promotion-guard"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            raise GuardError(f"GitHub API {exc.code} on {path}") from exc
    return fetch


def list_files(fetch: Fetch, repo: str, number: int) -> list[dict]:
    files: list[dict] = []
    for page in range(1, 31):  # GitHub returns at most 3000 files
        batch = fetch(f"/repos/{repo}/pulls/{number}/files?per_page=100&page={page}") or []
        files.extend(batch)
        if len(batch) < 100:
            return files
    raise GuardError("too many changed files to check")


def file_text(fetch: Fetch, repo: str, path: str, ref: str) -> str | None:
    data = fetch(f"/repos/{repo}/contents/{urllib.parse.quote(path)}?ref={ref}")
    if data is None:
        return None
    if not isinstance(data, dict) or data.get("encoding") != "base64":
        raise GuardError(f"cannot read {path} at {ref[:12]}")
    return base64.b64decode(data["content"]).decode("utf-8")


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------
def is_lock(path: str) -> bool:
    name = path.rsplit("/", 1)[-1]
    return any(fnmatch.fnmatchcase(name, p) for p in LOCK_PATTERNS)


def _strip_package_json(doc: Any) -> Any:
    if not isinstance(doc, dict):
        return doc
    out = {k: v for k, v in doc.items() if k not in PACKAGE_JSON_DEP_KEYS}
    pnpm = out.get("pnpm")
    if isinstance(pnpm, dict):
        rest = {k: v for k, v in pnpm.items() if k != "overrides"}
        if rest:
            out["pnpm"] = rest
        else:
            out.pop("pnpm")
    return out


def _strip_pyproject(doc: dict) -> dict:
    doc = json.loads(json.dumps(doc))  # deep copy
    project = doc.get("project")
    if isinstance(project, dict):
        project.pop("dependencies", None)
        project.pop("optional-dependencies", None)
    doc.pop("dependency-groups", None)
    uv = (doc.get("tool") or {}).get("uv")
    if isinstance(uv, dict):
        for key in ("constraint-dependencies", "override-dependencies", "dev-dependencies"):
            uv.pop(key, None)
    poetry = (doc.get("tool") or {}).get("poetry")
    if isinstance(poetry, dict):
        poetry.pop("dependencies", None)
        poetry.pop("dev-dependencies", None)
        groups = poetry.get("group")
        if isinstance(groups, dict):
            for group in groups.values():
                if isinstance(group, dict):
                    group.pop("dependencies", None)
    return _prune_empty(doc)


def _prune_empty(value: Any) -> Any:
    """Drop tables left empty once the dependency keys are gone, so adding a new
    [tool.uv] table that holds only constraints counts as a dependency change."""
    if isinstance(value, dict):
        out = {k: _prune_empty(v) for k, v in value.items()}
        return {k: v for k, v in out.items() if not (isinstance(v, dict) and not v)}
    return value


def manifest_only_deps_changed(path: str, before: str | None, after: str | None) -> str | None:
    """None when only dependency fields differ, else the reason."""
    if before is None or after is None:
        return f"{path}: added or removed"
    name = path.rsplit("/", 1)[-1]
    try:
        if name == "package.json":
            a, b = _strip_package_json(json.loads(before)), _strip_package_json(json.loads(after))
        else:
            a, b = _strip_pyproject(tomllib.loads(before)), _strip_pyproject(tomllib.loads(after))
    except (ValueError, tomllib.TOMLDecodeError) as exc:
        return f"{path}: cannot parse ({exc})"
    if a != b:
        return f"{path}: fields other than dependencies changed"
    return None


def canonical_templates() -> list[str]:
    """The `pull_request` template and the hardened `pull_request_target` one."""
    return [t.read_text(encoding="utf-8").replace("\r\n", "\n") for t in TEMPLATES]


def canonical_template() -> str:
    return canonical_templates()[0]


def decide(pr: dict, repo: str, fetch: Fetch) -> tuple[bool, str]:
    head = pr.get("head") or {}
    base = pr.get("base") or {}
    head_repo = (head.get("repo") or {}).get("full_name")
    base_repo = (base.get("repo") or {}).get("full_name")
    if not head_repo or head_repo != base_repo:
        return False, "PRs from forks cannot target main."

    if head.get("ref") == "staging":
        return True, "Allowed: same-repo staging -> main promotion PR."

    author = (pr.get("user") or {}).get("login") or ""
    if author == "dependabot[bot]":
        return True, "Allowed: Dependabot security update (cannot target staging by design)."

    files = list_files(fetch, repo, pr["number"])
    paths = [f.get("filename", "") for f in files]

    if paths == [GUARD_PATH] and files[0].get("status") == "modified":
        new = file_text(fetch, repo, GUARD_PATH, head["sha"])
        if new is not None and new.replace("\r\n", "\n") in canonical_templates():
            return True, "Allowed: update of this guard to the canonical template."
        return False, "This PR changes the guard, and the new file is not the canonical template."

    labels = {(lab or {}).get("name") for lab in pr.get("labels") or []}
    if author not in AUTOPILOT_APPS and HOTFIX_LABEL not in labels:
        return False, ("PRs into `main` must be promotions from the shared `staging` branch, "
                       f"or dependency-only security hotfixes with the `{HOTFIX_LABEL}` label.")

    if not files:
        return False, "Security hotfix with no changed files."
    problems: list[str] = []
    for f in files:
        path, status = f.get("filename", ""), f.get("status")
        name = path.rsplit("/", 1)[-1]
        if path.startswith(".github/"):
            problems.append(f"{path}: workflow and repo settings files are not allowed")
        elif status in ("removed", "renamed"):
            problems.append(f"{path}: {status}")
        elif is_lock(path):
            continue
        elif name in MANIFESTS:
            if status != "modified":
                problems.append(f"{path}: {status}")
                continue
            reason = manifest_only_deps_changed(
                path, file_text(fetch, repo, path, base["sha"]), file_text(fetch, repo, path, head["sha"]))
            if reason:
                problems.append(reason)
        else:
            problems.append(f"{path}: not a dependency file")
    if problems:
        return False, "Security hotfix may change dependency files only:\n- " + "\n- ".join(problems)
    who = "dependabot-autopilot" if author in AUTOPILOT_APPS else f"`{HOTFIX_LABEL}` label"
    return True, f"Allowed: dependency-only security hotfix ({who}, {len(files)} file(s))."


def main() -> int:
    event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
    pr = event.get("pull_request")
    if not pr:
        print("::error::Expected a pull_request event.")
        return 1
    repo = os.environ.get("GITHUB_REPOSITORY") or pr["base"]["repo"]["full_name"]
    fetch = make_fetch(os.environ["GITHUB_TOKEN"], os.environ.get("GITHUB_API_URL", "https://api.github.com"))
    try:
        ok, message = decide(pr, repo, fetch)
    except GuardError as exc:
        ok, message = False, f"Guard could not check this PR: {exc}"
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(f"## main-promotion-guard\n\n{'PASS' if ok else 'FAIL'}: {message}\n")
    if ok:
        print(message)
        return 0
    for line in message.splitlines():
        print(f"::error::{line}")
    print("Retarget this PR to `staging` (gh pr edit --base staging), or open a promotion PR with head `staging`.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
