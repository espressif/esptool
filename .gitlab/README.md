# GitLab CI

Entry point: [`.gitlab-ci.yml`](../.gitlab-ci.yml). Jobs are split across this directory.

Also keep [`.github/workflows/test_esptool.yml`](../.github/workflows/test_esptool.yml) in sync when changing install or test steps.

## Pipelines

- **MR / branch push** — lint, install checks, tests, coverage report. Docs build/deploy when doc files change.
- **`internal/dev_release` push** — above plus preview package build (manual publish).
- **Nightly schedule** (`STUB_CANARY=1`) — stub canary only; see [Canary](#canary).

Push pipelines are skipped when an open MR already exists for the branch.

## Stages

```
pre-check → check → test → report
```

Optional: `build_docs` → `deploy_docs`, `deploy_development_package`.

Canary adds `canary_prep` before and `canary_post` after.

## Files

| File | Purpose |
|------|---------|
| `checks.yml` | Install smoke tests, stub freshness |
| `host_tests.yml` | Linux + Windows host pytest jobs |
| `target_tests.yml` | Hardware tests per board (`target_<chip>` jobs), Windows smoke on `COM4` |
| `canary.yml` | Nightly stub compatibility |
| `deploy_docs.yml` | Docs build and deploy |
| `internal_release.yml` | Internal preview sdist |

Python images: `PYTHON_IMAGE_MIN` and `PYTHON_IMAGE_LATEST` in `.gitlab-ci.yml`. Canary jobs use `CANARY_IMAGE` (`ubuntu:24.04`).

## What runs where

**pre-check** — Danger MR linter, pre-commit.

**check** — Package installs (`pip install` / `-e` / venv / `--user`), CLI `--help`, stub freshness, UF2 ID test.

**test** — Host tests (`pytest -m host_test` on Linux; `-m "host_test and not linux_host_test"` on Windows — tests marked `linux_host_test` are excluded; see `test/conftest.py`), espefuse matrix, hardware jobs in `target_tests.yml` (`-m "not host_test"` — host-only cases run in `host_tests` instead), Windows `quick_test` smoke on `COM4`.

**report** — `combine_reports` merges coverage from test jobs.

## Canary

Nightly job that builds fresh v2 stubs from **esp-stub-lib** and runs the full test suite against them. All canary jobs use `$CANARY_IMAGE` (`ubuntu:24.04`).

1. `canary_poll` — skip if SHA unchanged (cancels pipeline)
2. `canary_build_stubs` → `canary_patch` — build stubs, patch into tree
3. Normal test jobs (after `canary_prep` via stage order; patched stubs passed as artifacts)
4. `canary_record` — save SHA on success; `canary_on_failure` — open issue on failure

**Quiet nights:** if `LAST_TESTED_STUB_LIB_SHA` is unchanged, `canary_poll` cancels the pipeline before build/tests run. `canary_on_failure` does not run on cancel, so no spurious issues are opened.

**Attribution:** only esp-stub-lib is tracked across runs; esp-flasher-stub is rebuilt from master each night. Issue titles blame esp-stub-lib, but both SHAs appear in the issue body.

**CI variables:** `STUB_CANARY` (on the schedule, not project-wide), `LAST_TESTED_STUB_LIB_SHA` (auto-created by `canary_record`), `GITLAB_API_TOKEN` (api scope, Maintainer+ — cancel on quiet nights and record SHA), optional `MAINTAINERS`.

## Runners

- `host_test` — Linux Docker
- `esptool-*` — per-board hardware (see `target_tests.yml`)
- `windows-target` — Windows
- `dangerjs`, `build_docs`, `deploy` — specialised jobs
