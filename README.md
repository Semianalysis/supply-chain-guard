# supply-chain-guard

PR-time guardrail that blocks newly-published npm and PyPI packages from being merged into Semianalysis repos within a cooldown window (default 7 days).

## Why

Most supply-chain worms (Mini Shai-Hulud, Shai-Hulud, the original event-stream attack) operate on the same playbook: a maintainer's publish credentials get compromised, a malicious version of a legit package is published, and bots running `npm install` or `pip install` start pulling it within minutes-to-hours. By blocking PRs that introduce package versions younger than 7 days old, we make that window structurally smaller for our codebase.

## What it checks

The action runs on every PR (the workflow has no `paths:` filter — see the comment in `.github/workflows/cooldown.yml` for why). On PRs that don't touch a dependency file the job exits in seconds with a "no dependency files changed" pass.

When a PR does touch a dep file (lockfiles: `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `yarn.lock`, `bun.lock`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `Cargo.lock`, `go.sum`; manifests: `package.json`, `pyproject.toml`, `requirements*.txt`), the action:

1. Diffs each lockfile against the PR's base branch and the merge base.
2. Collects every (package, version) pair the lockfile resolves at the PR head that was not there before (direct and transitive, every copy).
3. For each: queries the npm, PyPI, crates.io or Go module proxy registry for that version's publish time (3 tries per lookup).
4. Fails the check if any version is younger than the cooldown threshold, **or if its publish date cannot be read** (fail closed; the report names each package).

**Lockfile-first.** When a changed manifest has a lockfile in the same directory (or a parent lockfile that names the manifest's directory, as npm, pnpm, yarn, bun and uv workspaces do), only the lockfile-resolved versions are judged and the manifest's ranges are ignored. A range says nothing about what the build installs; judging it as its newest registry match produced false failures on Dependabot PRs. Range resolution (below) is the fallback for manifests with no lockfile.

For unpinned ranges in a manifest with **no** lockfile (e.g. `requests>=2.30`), the check resolves against the registry's **highest version that satisfies the spec** (the same version that would be installed at deploy time) and applies the age test to it.

This means a pin like `"@anthropic-ai/sdk": "^0.69.0"` resolves to the highest `0.69.x` published, not to whatever the registry currently tags as `latest`. Under semver-0 caret rules `^0.69.0` cannot resolve past `0.70.0`, so a fresh `1.0.0` published yesterday is irrelevant to the age check.

Resolution happens via:
  - **npm**: shells out to `npm view <pkg>@<spec> version --json`. The runner's `npm` does all the semver work (caret, tilde, hyphen ranges, `||` unions, X-ranges, prerelease gating).
  - **PyPI**: uses [`packaging`](https://packaging.pypa.io/)'s `SpecifierSet` — the same library `pip` itself uses for PEP 440 specifier evaluation.

## What gets skipped

Some dependency specs aren't resolvable against the public npm registry, so the check has nothing useful to say about them. These are skipped at parse time and never appear in the report:

  - `workspace:*` / `workspace:^x.y.z` — pnpm / yarn / npm workspace links.
  - `file:./local-path` — local tarballs or directories.
  - `link:../sibling` — pnpm symlink-based deps.
  - `git+https://`, `git://` — git URLs.
  - `http://`, `https://` — tarball URLs.
  - `npm:<alias>@<spec>` — package aliases.
  - `portal:...`, `catalog:...` — yarn berry portals, pnpm catalogs.
  - `*` — unbounded ranges with no upper side to age-check.

If you genuinely want a non-registry dep audited, review it manually.

## The initial-commit blind spot (and the daily scan that covers it)

Required workflows only run on pull requests. The push that *creates* a repo's default branch (initial commit, "Add README" auto-init) can never satisfy one — so the org ruleset sets `do_not_enforce_on_create: true` to keep repo creation from being blocked outright. That means a brand-new repo's initial commit is never PR-checked, and since the PR check only diffs against the base branch, packages present at creation are grandfathered forever.

`scan_new_repos.py` (run daily by `.github/workflows/new-repo-scan.yml`) closes the gap after the fact: it finds repos created in the last 2 days and age-checks the **full contents** of every dependency file on their default branch. Violations can't be blocked — the commit already landed — so the job goes red, writes a step summary, and posts to Slack (`SLACK_BOT_TOKEN` secret + `SLACK_CHANNEL_ID` repo variable). The org-repo listing needs the `ORG_SCAN_TOKEN` secret since the default Actions token can't see other repos.

## Override

Add the `security/cooldown-override` label to a PR to bypass the check after manual review. The bypass is logged in PR history and visible to anyone auditing later.

The label is read **live from the GitHub API** at check time (in addition to the event payload), so it takes effect the moment it's on the PR — you do **not** need to push a new commit or re-run the job. (Historically the action only read `github.event.pull_request.labels`, which is a snapshot frozen when the triggering event fired; a label added afterwards was invisible, and "Re-run jobs" replays the original payload rather than refreshing it, so retries never picked it up.) If a stale run is still showing red, a fresh run — via a new push or the "Re-run" button — will now re-read the current labels and pass.

## Cooldown exceptions (security fast lane)

Sometimes a critical or exploited advisory needs its fix merged before the fixed version is 7 days old. A cooldown exception allows that for one exact package version, for a short time.

**What an exception is.** An entry in `exceptions.json` at the root of this repo:

```json
{
  "version": 1,
  "exceptions": [
    {
      "id": "GHSA-xxxx-xxxx-xxxx",
      "ecosystem": "npm",
      "package": "example-pkg",
      "version": "1.2.3",
      "integrity": "sha512-...",
      "published_at": "2026-10-15T18:00:00Z",
      "expires": "2026-10-22T18:00:00Z",
      "approved_by": "Approver Name",
      "approved_at": "2026-10-16T09:00:00Z",
      "request": "..."
    }
  ]
}
```

A young version passes the check only when all of these are true:

- Same ecosystem (`npm`, `pypi`, `cargo`, `go`, `rubygems`, `packagist`), same package, same exact version. PyPI names are compared after PEP 503 normalization.
- The entry is valid and not expired.
- If the entry has an `integrity` and the lockfile records an integrity of the same algorithm (npm `package-lock.json`, `pnpm-lock.yaml`, classic `yarn.lock` and `bun.lock` record `sha512`), the two are equal.

Other young versions in the same PR still fail. The check summary lists every exception it used and every entry it ignored.

**Who approves.** A member of the Entra "IT Team" group, with one click on an approval button that an internal bot posts in Slack. The bot then adds the entry to this file with a PR that it merges at once. Nobody adds entries by hand.

**Entries expire at 7 days.** `expires` is the version's publish time plus 7 days, which is when the version passes the normal cooldown anyway. An entry whose `expires` is more than 8 days after `published_at`, or more than 8 days from now, is invalid.

**Fail closed.** The file is read from this action's own copy of the repo, never from the repo under check, so a PR cannot grant itself an exception. A malformed file, a wrong `version`, or a bad entry (a range instead of one version, an unknown ecosystem, a missing time zone, an email address in `approved_by`) is ignored with a warning, and the normal cooldown applies. Versions whose publish date cannot be read are never excepted.

## Allowlist

Trusted scopes can be pre-allowed via the `allowed_scopes` input. Default: `@types`. Add others (e.g. `@vercel`, `@radix-ui`) by passing the input when calling the workflow.

## How to enable on a repo

### Via org-level required workflow (preferred)

This workflow is configured as a GHAS Required Workflow at the Semianalysis org level. It auto-applies to every repo — no per-repo setup needed.

### Per-repo opt-in (fallback)

Add this file to your repo at `.github/workflows/cooldown.yml`:

```yaml
name: Supply-chain cooldown
on: [pull_request]
jobs:
  call:
    uses: Semianalysis/supply-chain-guard/.github/workflows/cooldown.yml@main
    with:
      cooldown_days: 7
      allowed_scopes: "@types,@vercel"
```

Then enable as a required status check on your protected branch.

## What lockfile shapes are supported

| Ecosystem | File | Mode |
|---|---|---|
| npm | `package-lock.json`, `npm-shrinkwrap.json` (v1/v2/v3) | exact, every nested copy |
| npm | `pnpm-lock.yaml` (v5/v6/v9) | exact |
| npm | `yarn.lock` (classic and berry) | exact |
| npm | `bun.lock` (text format) | exact |
| npm | `package.json` | only when no lockfile covers it: range resolved to registry latest |
| pypi | `uv.lock`, `poetry.lock`, `Pipfile.lock` | exact, PyPI-sourced packages only |
| pypi | `requirements*.txt` | `==` pins exact; ranges only when no lockfile covers the file |
| pypi | `pyproject.toml` | only when no lockfile covers it: range resolved to registry latest |
| crates.io | `Cargo.lock` | exact, crates.io-sourced packages only |
| go | `go.sum` | exact, module code lines only (`/go.mod`-only lines skipped) |

Entries from non-public sources (workspace links, git, local paths, private registries such as GitHub Packages or a private PyPI index, PyPI local versions like `+cu121`, `github.com/Semianalysis/...` Go modules) are skipped: they have no public publish date. The sfw proxy counts as public because it fronts the public registries.

Lockfiles the action knows but cannot parse (`bun.lockb`, `Gemfile.lock`, `composer.lock` and similar) produce a warning in the summary, never a failure. A malformed lockfile does the same.

PyPI publish time is the **newest** upload in the release: PyPI lets maintainers add files to an old release, and the newest file is what a late attack would add.
