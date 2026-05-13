"""Unit tests for check.py's spec-aware version resolvers.

These tests are the regression net for the bug fixed in this PR:
the npm and pypi resolvers used to ignore the `spec` argument and
unconditionally return the registry's `dist-tags.latest` /
`info.version`, which produced false-positive cooldown failures
whenever a fresh release dropped outside the PR's pinned range.

Run with: pytest -v check_test.py

External calls (`subprocess.run` for npm, `fetch_json` for PyPI)
are mocked so the suite stays offline-clean and deterministic.
"""
from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

import check


# ─── npm: _is_non_registry_npm_spec ─────────────────────────────────────────


@pytest.mark.parametrize(
    "spec",
    [
        "workspace:*",
        "workspace:^1.0.0",
        "file:./local",
        "link:../sibling",
        "git+https://github.com/foo/bar.git",
        "git://github.com/foo/bar.git",
        "http://example.com/pkg.tgz",
        "https://example.com/pkg.tgz",
        "npm:@other/alias@^1.0.0",
        "portal:../pkg",
        "catalog:default",
        "*",
        "  *  ",
    ],
)
def test_non_registry_spec_detected(spec: str) -> None:
    assert check._is_non_registry_npm_spec(spec) is True


@pytest.mark.parametrize(
    "spec",
    [
        "^1.0.0",
        "~4.21.0",
        "0.69.0",
        ">=2.0.0 <3.0.0",
        "1.x",
        "latest",
        "^0.69.0",
    ],
)
def test_registry_spec_accepted(spec: str) -> None:
    assert check._is_non_registry_npm_spec(spec) is False


# ─── npm: parse_npm_package_json strips non-registry specs ──────────────────


def test_parse_npm_package_json_filters_workspace_and_file_deps() -> None:
    text = json.dumps(
        {
            "dependencies": {
                "@anthropic-ai/sdk": "^0.69.0",
                "@local/db": "workspace:*",
                "@local/config": "workspace:^0.0.0",
                "esbuild": "^0.27.0",
                "tarball": "file:./vendor/x.tgz",
            },
            "devDependencies": {
                "vitest": "^4.1.5",
                "@my/git-dep": "git+https://github.com/x/y.git",
            },
        },
    )
    parsed = check.parse_npm_package_json(text)
    assert parsed == {
        "@anthropic-ai/sdk": "^0.69.0",
        "esbuild": "^0.27.0",
        "vitest": "^4.1.5",
    }


# ─── npm: _parse_npm_view_output handles every shape npm emits ──────────────


def test_parse_npm_view_output_single_string() -> None:
    assert check._parse_npm_view_output('"4.21.0"\n') == "4.21.0"


def test_parse_npm_view_output_array_picks_highest() -> None:
    # Mirrors the real output: `npm view esbuild@^0.27.0 version --json`.
    raw = json.dumps(["0.27.0", "0.27.1", "0.27.2", "0.27.7"])
    assert check._parse_npm_view_output(raw) == "0.27.7"


def test_parse_npm_view_output_array_semver_aware_max() -> None:
    # Lexical sort would put 0.27.10 < 0.27.2; semver-aware sort must
    # pick 0.27.10.
    raw = json.dumps(["0.27.2", "0.27.10", "0.27.5"])
    assert check._parse_npm_view_output(raw) == "0.27.10"


def test_parse_npm_view_output_stable_outranks_prerelease() -> None:
    # SemVer 2.0.0 §11: 1.0.0 > 1.0.0-rc.1.
    raw = json.dumps(["1.0.0", "1.0.0-rc.1", "1.0.0-beta.2"])
    assert check._parse_npm_view_output(raw) == "1.0.0"


def test_parse_npm_view_output_empty_returns_none() -> None:
    assert check._parse_npm_view_output("") is None
    assert check._parse_npm_view_output("\n") is None


def test_parse_npm_view_output_non_json_passthrough() -> None:
    # If npm somehow emits a bare version string (older versions did
    # this without --json), fall back to treating it as the value.
    assert check._parse_npm_view_output("4.21.0\n") == "4.21.0"


# ─── npm: npm_resolve_range_latest (the function the bug lived in) ──────────


def _mock_subprocess_run(stdout: str, returncode: int = 0):
    """Helper: returns a CompletedProcess-shaped object."""
    return subprocess.CompletedProcess(
        args=[], returncode=returncode, stdout=stdout, stderr=""
    )


def test_npm_resolver_caret_zero_returns_floor_not_latest() -> None:
    """The bug case: ^0.69.0 must resolve to 0.69.x, not dist-tags.latest.

    semver-0 caret rules cap the range at 0.70.0, so even if the
    registry tags 0.96.0 as latest, that version is unreachable from
    a ^0.69.0 spec. The pre-fix code unconditionally returned
    dist-tags.latest and produced false cooldown failures.
    """
    with patch.object(check, "subprocess") as mock_subprocess:
        mock_subprocess.run.return_value = _mock_subprocess_run('"0.69.0"\n')
        result = check.npm_resolve_range_latest("@anthropic-ai/sdk", "^0.69.0")
        assert result == "0.69.0"
        # Confirm we actually invoked `npm view` with the spec, not
        # just hit the registry's dist-tags shortcut.
        call_args = mock_subprocess.run.call_args[0][0]
        assert call_args[0] == "npm"
        assert call_args[1] == "view"
        assert "@anthropic-ai/sdk@^0.69.0" in call_args


def test_npm_resolver_tilde_resolves_within_minor_band() -> None:
    with patch.object(check, "subprocess") as mock_subprocess:
        # `npm view tsx@~4.21.0 version --json` returns the highest
        # 4.21.x release (real output: just "4.21.0" since 4.21.x
        # has no patch bumps yet).
        mock_subprocess.run.return_value = _mock_subprocess_run('"4.21.0"\n')
        assert check.npm_resolve_range_latest("tsx", "~4.21.0") == "4.21.0"


def test_npm_resolver_open_range_picks_highest() -> None:
    # `^0.27.0` should resolve to whatever the highest published
    # 0.27.x is (since this is sub-major caret rules), but for the
    # mock we treat it as an unbounded range with multiple matches.
    with patch.object(check, "subprocess") as mock_subprocess:
        mock_subprocess.run.return_value = _mock_subprocess_run(
            json.dumps(["0.27.0", "0.27.5", "0.27.7"])
        )
        assert check.npm_resolve_range_latest("esbuild", "^0.27.0") == "0.27.7"


def test_npm_resolver_unresolvable_returns_none() -> None:
    """`npm view tsx@^99.0.0 version` exits 1 with no stdout."""
    with patch.object(check, "subprocess") as mock_subprocess:
        mock_subprocess.run.return_value = _mock_subprocess_run("", returncode=1)
        assert check.npm_resolve_range_latest("tsx", "^99.0.0") is None


def test_npm_resolver_workspace_spec_skipped() -> None:
    """Workspace deps must be skipped without calling npm at all."""
    with patch.object(check, "subprocess") as mock_subprocess:
        result = check.npm_resolve_range_latest("@local/db", "workspace:*")
        assert result is None
        mock_subprocess.run.assert_not_called()


def test_npm_resolver_falls_back_when_npm_cli_missing() -> None:
    """If the runner doesn't have `npm` (unusual), fall back to
    dist-tags.latest so we don't silently pass."""
    with patch.object(check, "subprocess") as mock_subprocess, patch.object(
        check, "fetch_json"
    ) as mock_fetch:
        mock_subprocess.run.side_effect = FileNotFoundError("npm not found")
        mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
        mock_fetch.return_value = {"dist-tags": {"latest": "9.9.9"}}
        result = check.npm_resolve_range_latest("foo", "^1.0.0")
        assert result == "9.9.9"


def test_npm_resolver_falls_back_on_timeout() -> None:
    with patch.object(check, "subprocess") as mock_subprocess, patch.object(
        check, "fetch_json"
    ) as mock_fetch:
        mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
        mock_subprocess.run.side_effect = subprocess.TimeoutExpired(
            cmd="npm view", timeout=20
        )
        mock_fetch.return_value = {"dist-tags": {"latest": "9.9.9"}}
        assert check.npm_resolve_range_latest("foo", "^1.0.0") == "9.9.9"


# ─── pypi: pypi_resolve_spec_latest ─────────────────────────────────────────


def _pypi_registry_payload(versions: list[str], latest: str | None = None) -> dict:
    """Build a minimal PyPI /json response from a version list."""
    return {
        "info": {"version": latest or (versions[-1] if versions else "")},
        "releases": {v: [{"upload_time_iso_8601": "2025-01-01T00:00:00Z"}] for v in versions},
    }


def test_pypi_resolver_compatible_release() -> None:
    """~=2.0 means >=2.0, <3.0 (PEP 440 compatible release operator)."""
    payload = _pypi_registry_payload(
        ["1.5.0", "2.0.0", "2.5.3", "3.0.0"], latest="3.0.0"
    )
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_resolve_spec_latest("foo", "~=2.0") == "2.5.3"


def test_pypi_resolver_exact_pin() -> None:
    payload = _pypi_registry_payload(["1.0.0", "1.5.0", "2.0.0"])
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_resolve_spec_latest("foo", "==1.5.0") == "1.5.0"


def test_pypi_resolver_range_with_upper_bound() -> None:
    payload = _pypi_registry_payload(
        ["1.0.0", "1.5.0", "1.9.9", "2.0.0", "2.5.0"]
    )
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_resolve_spec_latest("foo", ">=1,<2") == "1.9.9"


def test_pypi_resolver_star_returns_registry_latest() -> None:
    payload = _pypi_registry_payload(["1.0.0", "2.0.0"], latest="2.0.0")
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_resolve_spec_latest("foo", "*") == "2.0.0"


def test_pypi_resolver_unparseable_spec_falls_back_to_latest() -> None:
    payload = _pypi_registry_payload(["1.0.0", "2.0.0"], latest="2.0.0")
    with patch.object(check, "fetch_json", return_value=payload):
        # PEP 440 doesn't recognise npm-style ^/~ specs.
        assert check.pypi_resolve_spec_latest("foo", "^1.0.0") == "2.0.0"


def test_pypi_resolver_skips_prereleases_unless_explicit() -> None:
    payload = _pypi_registry_payload(["1.0.0", "1.1.0rc1", "1.1.0", "2.0.0a1"])
    with patch.object(check, "fetch_json", return_value=payload):
        # No prerelease marker in the spec — pip wouldn't install one,
        # so neither do we.
        assert check.pypi_resolve_spec_latest("foo", ">=1,<2") == "1.1.0"


def test_pypi_resolver_no_match_returns_none() -> None:
    payload = _pypi_registry_payload(["1.0.0", "2.0.0"])
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_resolve_spec_latest("foo", ">=99,<100") is None


def test_pypi_resolver_fetch_failure_returns_none() -> None:
    with patch.object(check, "fetch_json", return_value=None):
        assert check.pypi_resolve_spec_latest("foo", "==1.0.0") is None
