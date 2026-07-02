# supply-chain-guard

PR-time guardrail that blocks newly-published npm and PyPI packages from being merged into Semianalysis repos within a cooldown window (default 7 days).

## Why

Most supply-chain worms (Mini Shai-Hulud, Shai-Hulud, the original event-stream attack) operate on the same playbook: a maintainer's publish credentials get compromised, a malicious version of a legit package is published, and bots running `npm install` or `pip install` start pulling it within minutes-to-hours. By blocking PRs that introduce package versions younger than 7 days old, we make that window structurally smaller for our codebase.

## What it checks

The action runs on every PR (the workflow has no `paths:` filter — see the comment in `.github/workflows/cooldown.yml` for why). On PRs that don't touch a dependency file the job exits in seconds with a "no dependency files changed" pass.

When a PR does touch a dep file (`package-lock.json`, `package.json`, `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`), the action:

1. Diffs the file against the PR's base branch.
2. Identifies new or version-changed packages (direct + transitive).
3. For each: queries the npm or PyPI registry for that version's publish time.
4. Fails the check if any version is younger than the cooldown threshold.

For unpinned ranges (e.g. `requests>=2.30` with no lockfile), the check resolves against the registry's **highest version that satisfies the spec** — the same version that would be installed at deploy time — and applies the age test to it.

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
| npm | `package-lock.json` (v2/v3) | exact-pinned, perfect diff |
| npm | `package.json` (no lockfile) | range resolved to registry latest |
| yarn | `yarn.lock` | TODO (not yet parsed) |
| pnpm | `pnpm-lock.yaml` | TODO (not yet parsed) |
| pypi | `uv.lock` | exact-pinned, perfect diff |
| pypi | `poetry.lock` | exact-pinned, perfect diff |
| pypi | `Pipfile.lock` | exact-pinned, perfect diff |
| pypi | `requirements*.txt` | exact (if `==`) or range (resolved to registry latest) |
| pypi | `pyproject.toml` | range resolved to registry latest |

If your repo uses an unsupported lockfile (yarn, pnpm), the action will silently skip those files for now. Open an issue and we'll add support.
