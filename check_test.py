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


# --- lockfile parsers --------------------------------------------------------
#
# Each parser returns the exact (name, version) pairs a lockfile resolves to,
# so the check judges what a build installs, never a manifest range. Entries
# that do not come from the public registry are skipped (no public publish
# date exists to judge), except the sfw proxy, which fronts the public ones.

NPM_LOCK_V3 = json.dumps({
    "lockfileVersion": 3,
    "packages": {
        "": {"name": "app"},
        "node_modules/next": {"version": "16.4.3", "resolved": "https://registry.npmjs.org/next/-/next-16.4.3.tgz"},
        "node_modules/semver": {"version": "6.3.1", "resolved": "https://registry.npmjs.org/semver/-/semver-6.3.1.tgz"},
        "node_modules/next/node_modules/semver": {"version": "7.7.2", "resolved": "https://registry.npmjs.org/semver/-/semver-7.7.2.tgz"},
        "node_modules/string-width-cjs": {"name": "string-width", "version": "4.2.3", "resolved": "https://registry.npmjs.org/string-width/-/string-width-4.2.3.tgz"},
        "node_modules/via-proxy": {"version": "1.0.0", "resolved": "https://sfw.semianalysis.com/npm/via-proxy/-/via-proxy-1.0.0.tgz"},
        "node_modules/@acme/private": {"version": "1.0.0", "resolved": "https://npm.pkg.github.com/download/@acme/private/1.0.0/abc"},
        "node_modules/local-lib": {"resolved": "packages/local-lib", "link": True},
        "packages/local-lib": {"version": "0.0.1"},
        "node_modules/from-git": {"version": "1.0.0", "resolved": "git+ssh://git@github.com/acme/from-git.git#abc"},
    },
})


def test_lock_npm_keeps_every_version_and_real_alias_name() -> None:
    result = check.lock_npm(NPM_LOCK_V3)
    assert result.pairs == {
        ("next", "16.4.3"),
        ("semver", "6.3.1"),
        ("semver", "7.7.2"),  # nested copy: both versions are checked
        ("string-width", "4.2.3"),  # alias resolves to the real package
        ("via-proxy", "1.0.0"),  # sfw fronts the public registry
    }
    assert any("@acme/private" in s for s in result.skipped)
    assert any("from-git" in s for s in result.skipped)


def test_lock_npm_v1_nested_dependencies() -> None:
    text = json.dumps({"lockfileVersion": 1, "dependencies": {
        "a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz",
              "dependencies": {"b": {"version": "2.0.0", "resolved": "https://registry.npmjs.org/b/-/b-2.0.0.tgz"}}},
        "c": {"version": "github:acme/c#abc"},
    }})
    assert check.lock_npm(text).pairs == {("a", "1.0.0"), ("b", "2.0.0")}


def test_npm_shrinkwrap_uses_npm_parser() -> None:
    eco, result = check.lockfile_pairs("app/npm-shrinkwrap.json", NPM_LOCK_V3)
    assert eco == "npm" and ("next", "16.4.3") in result.pairs


PNPM_V9 = """lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      next:
        specifier: ^16.4.0
        version: 16.4.3(react@19.0.0)

packages:

  '@next/env@16.4.3':
    resolution: {integrity: sha512-aaa}

  next@16.4.3:
    resolution: {integrity: sha512-bbb}

  my-git-dep@https://codeload.github.com/acme/dep/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/acme/dep/tar.gz/abc}

snapshots:

  next@16.4.3(react@19.0.0):
    dependencies:
      '@next/env': 16.4.3
"""

PNPM_V6 = """lockfileVersion: '6.0'

packages:

  /@next/env@16.4.3:
    resolution: {integrity: sha512-aaa}
    dev: false

  /next@16.4.3(react@19.0.0):
    resolution: {integrity: sha512-bbb}
    dev: false
"""

PNPM_V5 = """lockfileVersion: 5.4

packages:

  /@next/env/12.3.4:
    resolution: {integrity: sha512-aaa}

  /next/12.3.4_react@18.2.0:
    resolution: {integrity: sha512-bbb}
"""


@pytest.mark.parametrize(
    "text, expected",
    [
        (PNPM_V9, {("next", "16.4.3"), ("@next/env", "16.4.3")}),
        (PNPM_V6, {("next", "16.4.3"), ("@next/env", "16.4.3")}),
        (PNPM_V5, {("next", "12.3.4"), ("@next/env", "12.3.4")}),
    ],
)
def test_lock_pnpm_versions(text: str, expected: set) -> None:
    assert check.lock_pnpm(text).pairs == expected


def test_lock_pnpm_skips_git_and_rejects_garbage() -> None:
    assert any("my-git-dep" in s for s in check.lock_pnpm(PNPM_V9).skipped)
    with pytest.raises(check.LockfileError):
        check.lock_pnpm("not a lockfile")


YARN_CLASSIC = """# yarn lockfile v1


"@babel/core@^7.20.0":
  version "7.26.10"
  resolved "https://registry.yarnpkg.com/@babel/core/-/core-7.26.10.tgz#abc"
  integrity sha512-aaa
  dependencies:
    debug "^4.1.0"

"string-width-cjs@npm:string-width@^4.2.0":
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#ghi"

"my-dep@git+https://github.com/acme/my-dep.git":
  version "1.0.0"
  resolved "git+https://github.com/acme/my-dep.git#abc"
"""

YARN_BERRY = """__metadata:
  version: 8
  cacheKey: 10c0

"@babel/core@npm:^7.20.0":
  version: 7.26.10
  resolution: "@babel/core@npm:7.26.10"
  dependencies:
    debug: "npm:^4.1.0"
  languageName: node
  linkType: hard

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."

"left-pad@patch:left-pad@npm%3A1.3.0#~/.yarn/patches/left-pad.patch":
  version: 1.3.0
  resolution: "left-pad@patch:left-pad@npm%3A1.3.0#~/.yarn/patches/left-pad.patch::version=1.3.0"
"""


def test_lock_yarn_classic() -> None:
    result = check.lock_yarn(YARN_CLASSIC)
    assert result.pairs == {("@babel/core", "7.26.10"), ("string-width", "4.2.3")}
    assert any("my-dep" in s for s in result.skipped)


def test_lock_yarn_berry() -> None:
    result = check.lock_yarn(YARN_BERRY)
    assert result.pairs == {("@babel/core", "7.26.10")}
    assert len(result.skipped) == 2  # workspace and patch entries


BUN_LOCK = """{
  "lockfileVersion": 1,
  "workspaces": {
    "": {"name": "app", "dependencies": {"next": "^16.4.0",},},
  },
  "packages": {
    "@next/env": ["@next/env@16.4.3", "", {}, "sha512-aaa"],
    "next": ["next@16.4.3", "", {}, "sha512-bbb"],
    "local": ["local@workspace:packages/local"],
    "privpkg": ["privpkg@2.0.0", "https://npm.pkg.github.com/", {}, "sha512-ccc"],
  }
}
"""


def test_lock_bun_text_format() -> None:
    result = check.lock_bun(BUN_LOCK)
    assert result.pairs == {("next", "16.4.3"), ("@next/env", "16.4.3")}
    assert len(result.skipped) == 2


UV_LOCK = """version = 1

[[package]]
name = "app"
version = "0.1.0"
source = { virtual = "." }

[[package]]
name = "PyYAML"
version = "6.0.3"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "torch"
version = "2.5.1+cu121"
source = { registry = "https://download.pytorch.org/whl/cu121" }
"""


def test_lock_uv_skips_non_pypi_registries() -> None:
    result = check.lock_uv(UV_LOCK)
    assert result.pairs == {("pyyaml", "6.0.3")}
    assert any("torch" in s for s in result.skipped)
    # Back-compat dict wrapper used by scan_new_repos.
    assert check.parse_uv_lock(UV_LOCK) == {"pyyaml": "6.0.3"}


def test_lock_poetry_and_pipfile_skip_private_sources() -> None:
    poetry = """[[package]]
name = "requests"
version = "2.32.3"

[[package]]
name = "internal-lib"
version = "1.0.0"

[package.source]
type = "legacy"
url = "https://pypi.internal.example.com/simple"
"""
    assert check.lock_poetry(poetry).pairs == {("requests", "2.32.3")}
    pipfile = json.dumps({
        "_meta": {"sources": [{"name": "pypi", "url": "https://pypi.org/simple"},
                              {"name": "internal", "url": "https://pypi.internal.example.com/simple"}]},
        "default": {"flask": {"index": "pypi", "version": "==3.1.0"},
                    "secret": {"index": "internal", "version": "==1.0.0"},
                    "editable-pkg": {"editable": True, "path": "."}},
        "develop": {"pytest": {"version": "==8.3.4"}},
    })
    assert check.lock_pipfile(pipfile).pairs == {("flask", "3.1.0"), ("pytest", "8.3.4")}


REQUIREMENTS = """# pinned by pip-compile
-r base.txt
Django==5.1.4 \\
    --hash=sha256:aaa \\
    --hash=sha256:bbb
requests[socks]==2.32.3 ; python_version >= "3.8"  # via app
numpy>=1.26,<3
torch==2.5.1+cu121
mylib @ https://example.com/mylib-1.0.tar.gz
attrs===24.2.0
"""


def test_requirements_pins_and_ranges_are_split() -> None:
    pins = check.lock_requirements_pins(REQUIREMENTS)
    assert pins.pairs == {("django", "5.1.4"), ("requests", "2.32.3"), ("attrs", "24.2.0")}
    assert check.requirements_ranges(REQUIREMENTS) == {"numpy": ">=1.26,<3"}


def test_requirements_private_index_skips_whole_file() -> None:
    result = check.lock_requirements_pins("--index-url https://pypi.internal.example.com/simple\nfoo==1.0.0\n")
    assert result.pairs == set() and result.skipped


def test_lock_cargo_and_go_sum() -> None:
    cargo = """version = 4

[[package]]
name = "app"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.215"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.42.0"
source = "sparse+https://index.crates.io/"

[[package]]
name = "forked"
version = "0.3.0"
source = "git+https://github.com/acme/forked?branch=main#abc"
"""
    assert check.lock_cargo(cargo).pairs == {("serde", "1.0.215"), ("tokio", "1.42.0")}
    go_sum = (
        "github.com/BurntSushi/toml v1.4.0 h1:aaa=\n"
        "github.com/BurntSushi/toml v1.4.0/go.mod h1:bbb=\n"
        "golang.org/x/text v0.21.0/go.mod h1:eee=\n"
        "github.com/Semianalysis/internal-go v0.1.0 h1:fff=\n"
    )
    result = check.lock_go(go_sum)
    assert result.pairs == {("github.com/BurntSushi/toml", "v1.4.0")}  # go.mod-only lines skipped
    assert any("internal-go" in s for s in result.skipped)


def test_parse_file_still_serves_scan_new_repos() -> None:
    assert check.parse_file("Cargo.lock", 'version = 4\n') == ("cargo", {})
    assert check.parse_file("pnpm-lock.yaml", PNPM_V6)[1] == {"next": "16.4.3", "@next/env": "16.4.3"}
    assert check.parse_file("package.json", '{"dependencies": {"a": "^1.0.0"}}') == ("npm-spec", {"a": "^1.0.0"})


# --- lockfile-first ----------------------------------------------------------
#
# A manifest range is judged only when no lockfile resolves it. Treating a
# range as its newest registry match fails PRs for versions they never install.

def _refs(files: dict[tuple[str, str], str]):
    return patch.object(check, "file_at_ref", side_effect=_mock_file_at_ref(files))


def test_covering_lockfile_same_directory() -> None:
    with _refs({("HEAD", "web/package-lock.json"): "{}"}):
        assert check.covering_lockfile("web/package.json") == "web/package-lock.json"
        assert check.covering_lockfile("api/package.json") is None


def test_covering_lockfile_parent_workspace_must_name_the_member() -> None:
    files = {("HEAD", "pnpm-lock.yaml"): "importers:\n  packages/ui:\n    dependencies: {}\n"}
    with _refs(files):
        assert check.covering_lockfile("packages/ui/package.json") == "pnpm-lock.yaml"
        assert check.covering_lockfile("tools/script/package.json") is None


def test_covering_lockfile_python() -> None:
    with _refs({("HEAD", "svc/uv.lock"): "version = 1\n"}):
        assert check.covering_lockfile("svc/pyproject.toml") == "svc/uv.lock"
        assert check.covering_lockfile("svc/requirements.txt") == "svc/uv.lock"


def test_collect_pairs_judges_lockfile_not_manifest_range() -> None:
    old_lock = json.dumps({"packages": {"node_modules/next": {"version": "16.2.9"}}})
    new_lock = json.dumps({"packages": {
        "node_modules/next": {"version": "16.4.3"},
        "node_modules/@next/env": {"version": "16.4.3"},
    }})
    files = {
        ("HEAD", "package.json"): '{"dependencies": {"next": "^16.4.0"}}',
        ("origin/main", "package.json"): '{"dependencies": {"next": "^16.2.0"}}',
        ("HEAD", "package-lock.json"): new_lock,
        ("origin/main", "package-lock.json"): old_lock,
    }
    with _refs(files):
        pairs, warnings = check.collect_pairs(["package.json", "package-lock.json"], ["origin/main"])
    assert pairs == {"npm": {("next", "16.4.3"), ("@next/env", "16.4.3")}}
    assert warnings == []


def test_collect_pairs_falls_back_to_ranges_without_lockfile() -> None:
    files = {
        ("HEAD", "package.json"): '{"dependencies": {"next": "^16.4.0", "react": "^19.0.0"}}',
        ("origin/main", "package.json"): '{"dependencies": {"next": "^16.2.0", "react": "^19.0.0"}}',
    }
    with _refs(files):
        pairs, _ = check.collect_pairs(["package.json"], ["origin/main"])
    assert pairs == {"npm-spec": {"next": "^16.4.0"}}


def test_collect_pairs_merge_base_entries_are_not_new() -> None:
    files = {
        ("HEAD", "requirements.txt"): "a==2.0\nb==1.0\n",
        ("origin/main", "requirements.txt"): "a==3.0\nb==1.0\n",  # main moved on
        ("mb", "requirements.txt"): "a==2.0\nb==1.0\n",
    }
    with _refs(files):
        pairs, _ = check.collect_pairs(["requirements.txt"], ["origin/main", "mb"])
    assert pairs == {}


def test_collect_pairs_unparseable_lockfile_warns() -> None:
    files = {("HEAD", "Cargo.lock"): "[[package]\nname="}
    with _refs(files):
        pairs, warnings = check.collect_pairs(["Cargo.lock"], ["origin/main"])
    assert pairs == {}
    assert len(warnings) == 1 and "Cargo.lock" in warnings[0]


# --- registry lookups: retry, cache, fail closed ------------------------------

def test_fetch_json_retries_then_caches() -> None:
    url = "https://registry.npmjs.org/retry-me"
    check._fetch_cache.pop(url, None)
    calls = []

    def flaky(u):
        calls.append(u)
        if len(calls) < 3:
            raise OSError("connection reset")
        return {"ok": True}

    with patch.object(check, "_fetch_once", side_effect=flaky), patch.object(check.time, "sleep"):
        assert check.fetch_json(url) == {"ok": True}
        assert check.fetch_json(url) == {"ok": True}
    assert len(calls) == 3


def test_fetch_json_gives_none_after_last_attempt() -> None:
    url = "https://registry.npmjs.org/always-down"
    check._fetch_cache.pop(url, None)
    with patch.object(check, "_fetch_once", side_effect=OSError("down")) as mock_once, \
            patch.object(check.time, "sleep"):
        assert check.fetch_json(url) is None
    assert mock_once.call_count == check.FETCH_ATTEMPTS


def test_pypi_publish_time_uses_newest_file() -> None:
    payload = {"releases": {"1.0.0": [
        {"upload_time_iso_8601": "2024-01-01T00:00:00Z"},
        {"upload_time_iso_8601": "2026-11-08T00:00:00.123456Z"},  # wheel added later
    ]}}
    with patch.object(check, "fetch_json", return_value=payload):
        assert check.pypi_publish_time("pkg", "1.0.0").year == 2026


def test_go_and_cargo_publish_time() -> None:
    with patch.object(check, "fetch_json", return_value={"Time": "2024-06-10T10:00:00.123456789Z"}) as m:
        assert check.go_publish_time("github.com/BurntSushi/toml", "1.4.0").year == 2024
    assert m.call_args[0][0] == "https://proxy.golang.org/github.com/!burnt!sushi/toml/@v/v1.4.0.info"
    with patch.object(check, "fetch_json", return_value={"version": {"created_at": "2024-11-11T00:00:00+00:00"}}):
        assert check.cargo_publish_time("serde", "1.0.215").year == 2024


def test_age_check_marks_unknown_dates_unresolved() -> None:
    with patch.object(check, "lookup_publish_time", return_value=("1.0.0", None)):
        results = check.age_check_packages({"npm": {("ghost", "1.0.0")}}, 7, set())
    assert results == [{"pkg": "ghost", "version": "1.0.0", "resolved": "1.0.0", "publish_time": None,
                        "age_days": None, "ecosystem": "npm", "unresolved": True}]


def test_age_check_allowlist_applies_to_npm_scopes_only() -> None:
    with patch.object(check, "lookup_publish_time", return_value=("v1.0.0", None)):
        results = check.age_check_packages(
            {"npm": {("@types/node", "22.0.0")}, "go": {("@types/odd", "v1.0.0")}}, 7, {"@types"})
    by_eco = {r.get("ecosystem", "npm"): r for r in results}
    assert by_eco["npm"]["skipped"] == "allowlisted scope"
    assert by_eco["go"]["unresolved"] is True


# --- main(): fail closed, override still wins ---------------------------------

@contextmanager
def _main_env(tmp_path, labels=""):
    summary = tmp_path / "summary.md"
    keys = {"BASE_REF": "main", "PR_LABELS": labels, "GITHUB_STEP_SUMMARY": str(summary),
            "PR_NUMBER": "", "REPO_FULL": "", "GH_TOKEN": ""}
    prev = {k: os.environ.get(k) for k in keys}
    os.environ.update(keys)
    try:
        yield summary
    finally:
        for k, v in prev.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


def _run_main(files, changed):
    with _refs(files), \
            patch.object(check, "changed_files", return_value=changed), \
            patch.object(check, "_changed_paths", return_value=changed), \
            patch.object(check, "merge_base_ref", return_value=None), \
            patch.object(check, "live_pr_labels", return_value=set()), \
            patch.object(check, "lookup_publish_time", return_value=("9.9.9", None)):
        return check.main()


def test_main_fails_closed_when_publish_date_unknown(tmp_path) -> None:
    files = {("HEAD", "Cargo.lock"): 'version = 4\n\n[[package]]\nname = "ghost"\nversion = "9.9.9"\n'
                                     'source = "registry+https://github.com/rust-lang/crates.io-index"\n'}
    with _main_env(tmp_path) as summary:
        assert _run_main(files, ["Cargo.lock"]) == 1
    text = summary.read_text(encoding="utf-8")
    assert "could not be verified" in text and "`ghost`" in text


def test_main_override_label_still_bypasses(tmp_path) -> None:
    with _main_env(tmp_path, labels="security/cooldown-override") as summary:
        assert _run_main({}, ["Cargo.lock"]) == 0
    assert "bypassed" in summary.read_text(encoding="utf-8")


def test_main_warns_but_passes_on_unparsed_lockfile(tmp_path) -> None:
    with _main_env(tmp_path) as summary, \
            patch.object(check, "changed_unparsed_lockfiles", return_value=["Gemfile.lock"]):
        assert _run_main({("HEAD", "go.sum"): ""}, ["go.sum"]) == 0
    assert "Gemfile.lock" in summary.read_text(encoding="utf-8")
