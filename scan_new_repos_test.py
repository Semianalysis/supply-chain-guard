"""Unit tests for scan_new_repos.py's pure functions.

Registry and GitHub API calls are exercised in check_test.py / live runs;
these tests cover the full-scan aggregation logic that has no PR-diff
equivalent in check.py.

Run with: pytest -v scan_new_repos_test.py
"""
from __future__ import annotations

import json

import scan_new_repos


# ─── is_dep_file ─────────────────────────────────────────────────────────────


def test_is_dep_file_matches_known_names_at_any_depth() -> None:
    assert scan_new_repos.is_dep_file("package.json") is True
    assert scan_new_repos.is_dep_file("frontend/package-lock.json") is True
    assert scan_new_repos.is_dep_file("a/b/c/uv.lock") is True
    assert scan_new_repos.is_dep_file("requirements-gpu.txt") is True


def test_is_dep_file_rejects_non_dep_files() -> None:
    assert scan_new_repos.is_dep_file("README.md") is False
    assert scan_new_repos.is_dep_file("src/main.py") is False
    assert scan_new_repos.is_dep_file("requirements.md") is False
    # Substring lookalikes must not match.
    assert scan_new_repos.is_dep_file("not-package.json.bak") is False


# ─── full_scan_pairs ─────────────────────────────────────────────────────────


def test_full_scan_pairs_treats_every_package_as_new() -> None:
    package_json = json.dumps(
        {"dependencies": {"express": "^4.18.0", "@local/db": "workspace:*"}}
    )
    requirements = "requests==2.31.0\nflask>=2.0\n"
    pairs = scan_new_repos.full_scan_pairs(
        [("package.json", package_json), ("requirements.txt", requirements)]
    )
    assert pairs == {
        "npm-spec": {"express": "^4.18.0"},
        "pypi-spec": {"requests": "==2.31.0", "flask": ">=2.0"},
    }


def test_full_scan_pairs_merges_same_ecosystem_across_files() -> None:
    pairs = scan_new_repos.full_scan_pairs(
        [
            ("requirements.txt", "requests==2.31.0\n"),
            ("api/requirements.txt", "numpy==1.26.0\n"),
        ]
    )
    assert pairs == {
        "pypi-spec": {"requests": "==2.31.0", "numpy": "==1.26.0"}
    }


def test_full_scan_pairs_skips_unknown_files() -> None:
    assert scan_new_repos.full_scan_pairs([("Gemfile.lock", "gem stuff")]) == {}
