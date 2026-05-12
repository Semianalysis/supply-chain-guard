# supply-chain-guard

PR-time guardrail that blocks newly-published npm and PyPI packages from being merged into Semianalysis repos within a cooldown window (default 7 days).

## Why

Most supply-chain worms (Mini Shai-Hulud, Shai-Hulud, the original event-stream attack) operate on the same playbook: a maintainer's publish credentials get compromised, a malicious version of a legit package is published, and bots running `npm install` or `pip install` start pulling it within minutes-to-hours. By blocking PRs that introduce package versions younger than 7 days old, we make that window structurally smaller for our codebase.

## What it checks

For each PR that touches a dependency file (`package-lock.json`, `package.json`, `requirements.txt`, `pyproject.toml`, `uv.lock`, `poetry.lock`, `Pipfile.lock`, `yarn.lock`, `pnpm-lock.yaml`), the action:

1. Diffs the file against the PR's base branch.
2. Identifies new or version-changed packages (direct + transitive).
3. For each: queries the npm or PyPI registry for that version's publish time.
4. Fails the check if any version is younger than the cooldown threshold.

For unpinned ranges (e.g. `requests>=2.30` with no lockfile), the check resolves against the registry's latest matching version — the same version that would be installed at deploy time — and applies the same age test to it.

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
