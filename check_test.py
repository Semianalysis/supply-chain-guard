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


# --- live_pr_labels: the override-visibility fix -----------------------------
#
# Regression net for the stale-payload bug: an override label added after
# a PR opened (or between re-runs, which replay the original event payload)
# was invisible because the action only read github.event.*.labels. These
# tests pin the live API read that fixes it.

import io  # noqa: E402  (test-local import, kept next to its users)
import os  # noqa: E402
from contextlib import contextmanager  # noqa: E402


@contextmanager
def _label_env(pr="78", repo="Semianalysis/llm-api-test", token="tok"):
    """Set the env live_pr_labels() reads, restoring prior values after."""
    prev = {k: os.environ.get(k) for k in ("PR_NUMBER", "REPO_FULL", "GH_TOKEN")}
    for k, v in {"PR_NUMBER": pr, "REPO_FULL": repo, "GH_TOKEN": token}.items():
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    try:
        yield
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _issue_response(*label_names):
    body = json.dumps(
        {"labels": [{"name": n} for n in label_names]}
    ).encode("utf-8")
    return io.BytesIO(body)


def test_live_pr_labels_reads_current_labels() -> None:
    with _label_env(), patch.object(check.urllib.request, "urlopen") as mock_open:
        mock_open.return_value.__enter__.return_value = _issue_response(
            "security/cooldown-override", "dependencies"
        )
        assert check.live_pr_labels() == {
            "security/cooldown-override",
            "dependencies",
        }


def test_live_pr_labels_empty_without_context() -> None:
    # No token/PR context -> empty set (caller falls back to payload).
    with _label_env(token=None):
        assert check.live_pr_labels() == set()


def test_live_pr_labels_empty_on_api_error() -> None:
    with _label_env(), patch.object(
        check.urllib.request, "urlopen", side_effect=Exception("boom")
    ):
        # A transient API failure must never block the check.
        assert check.live_pr_labels() == set()


def test_live_pr_labels_strips_and_ignores_blank_names() -> None:
    with _label_env(), patch.object(check.urllib.request, "urlopen") as mock_open:
        mock_open.return_value.__enter__.return_value = _issue_response(
            "  spaced  ", ""
        )
        assert check.live_pr_labels() == {"spaced"}


# --- private-registry tripwire ------------------------------------------------
#
# Lockfiles must stay canonical-public: URLs on the org's Socket Firewall
# proxy 401 for every credential-less environment (Dependabot, Vercel, CI).
# The check is diff-based - it fails only URLs the PR *introduces*, so the
# repos whose lockfiles still carry legacy sfw entries aren't blocked on
# unrelated PRs.

SFW = ["sfw.semianalysis.com"]

LOCK_BEFORE = json.dumps({
    "packages": {
        "node_modules/express": {
            "version": "4.22.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.22.2.tgz",
        },
    }
})

LOCK_AFTER_SFW = json.dumps({
    "packages": {
        "node_modules/express": {
            "version": "4.22.2",
            "resolved": "https://registry.npmjs.org/express/-/express-4.22.2.tgz",
        },
        "node_modules/shell-quote": {
            "version": "1.8.4",
            "resolved": "https://sfw.semianalysis.com/npm/shell-quote/-/shell-quote-1.8.4.tgz",
        },
    }
})


def test_private_registry_urls_extraction() -> None:
    urls = check._private_registry_urls(LOCK_AFTER_SFW, SFW)
    assert urls == {
        "https://sfw.semianalysis.com/npm/shell-quote/-/shell-quote-1.8.4.tgz"
    }


def test_private_registry_urls_matches_port_variant() -> None:
    text = '"resolved": "https://sfw.semianalysis.com:8443/npm/foo/-/foo-1.0.0.tgz"'
    urls = check._private_registry_urls(text, SFW)
    assert urls == {"https://sfw.semianalysis.com:8443/npm/foo/-/foo-1.0.0.tgz"}


def test_private_registry_urls_ignores_public_hosts() -> None:
    assert check._private_registry_urls(LOCK_BEFORE, SFW) == set()


def test_private_registry_urls_does_not_match_subdomain_prefix() -> None:
    # `notsfw.semianalysis.com` must not match `sfw.semianalysis.com`...
    # it does contain the substring, but the regex requires the scheme
    # directly before the host, so only a genuine URL host matches.
    text = '"resolved": "https://notsfw.semianalysis.com/npm/foo/-/foo-1.0.0.tgz"'
    assert check._private_registry_urls(text, SFW) == set()


def _mock_file_at_ref(files: dict[tuple[str, str], str]):
    """Return a file_at_ref stand-in backed by {(ref, path): text}."""
    def fake(ref: str, path: str) -> str | None:
        return files.get((ref, path))
    return fake


def test_findings_only_for_introduced_urls() -> None:
    files = {
        ("origin/main", "package-lock.json"): LOCK_BEFORE,
        ("HEAD", "package-lock.json"): LOCK_AFTER_SFW,
    }
    with patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files)):
        findings = check.private_registry_findings(
            ["package-lock.json"], "main", SFW
        )
    assert findings == [{
        "path": "package-lock.json",
        "url": "https://sfw.semianalysis.com/npm/shell-quote/-/shell-quote-1.8.4.tgz",
    }]


def test_preexisting_urls_are_not_findings() -> None:
    # The sfw URL exists at base and head: legacy stock, not this PR's delta.
    files = {
        ("origin/main", "package-lock.json"): LOCK_AFTER_SFW,
        ("HEAD", "package-lock.json"): LOCK_AFTER_SFW,
    }
    with patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files)):
        assert check.private_registry_findings(
            ["package-lock.json"], "main", SFW
        ) == []


def test_removing_urls_is_not_a_finding() -> None:
    # The normalization PRs themselves (sfw -> npmjs rewrite) must pass.
    files = {
        ("origin/main", "package-lock.json"): LOCK_AFTER_SFW,
        ("HEAD", "package-lock.json"): LOCK_BEFORE,
    }
    with patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files)):
        assert check.private_registry_findings(
            ["package-lock.json"], "main", SFW
        ) == []


def test_new_lockfile_with_sfw_urls_is_a_finding() -> None:
    # File absent at base (file_at_ref returns None) -> every URL is new.
    files = {("HEAD", "pnpm-lock.yaml"): (
        "tarball: https://sfw.semianalysis.com/npm/foo/-/foo-2.0.0.tgz"
    )}
    with patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files)):
        findings = check.private_registry_findings(
            ["pnpm-lock.yaml"], "main", SFW
        )
    assert [f["url"] for f in findings] == [
        "https://sfw.semianalysis.com/npm/foo/-/foo-2.0.0.tgz"
    ]


def test_manifest_files_are_not_scanned() -> None:
    # package.json / requirements.txt never carry resolved URLs; a doc
    # string mentioning the proxy host must not fail the PR.
    files = {
        ("HEAD", "package.json"): '{"comment": "https://sfw.semianalysis.com/npm/"}',
    }
    with patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files)):
        assert check.private_registry_findings(
            ["package.json"], "main", SFW
        ) == []


def test_empty_hosts_disables_check() -> None:
    with patch.object(check, "file_at_ref") as mock_ref:
        assert check.private_registry_findings(["package-lock.json"], "main", []) == []
        mock_ref.assert_not_called()


def test_report_contains_fix_oneliner_and_urls() -> None:
    findings = [{
        "path": "package-lock.json",
        "url": "https://sfw.semianalysis.com/npm/shell-quote/-/shell-quote-1.8.4.tgz",
    }]
    report = check.private_registry_report(findings)
    # Exact-match the paved-road fix line (equality, not substring: CodeQL's
    # py/incomplete-url-substring-sanitization heuristic misreads hostname
    # substring-membership asserts as URL sanitization).
    sed_lines = [ln for ln in report.splitlines() if ln.startswith("sed -i")]
    assert sed_lines == [
        r"sed -i 's|https://sfw\.semianalysis\.com\(:[0-9]*\)\?/npm/"
        r"|https://registry.npmjs.org/|g' package-lock.json"
    ]
    assert "shell-quote-1.8.4.tgz" in report
    assert "replace-registry-host" in report
