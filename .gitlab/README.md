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

Canary adds `canary_prep` before and `canary_post`, `canary_report` after.

## Files

| File | Purpose |
|------|---------|
| `danger.yml` | Danger MR linter (internal `shared-ci-dangerjs` include + its job override); skipped on `bot/sync-master` (see [Sync to internal](#sync-to-internal)) |
| `checks.yml` | Install smoke tests, stub freshness |
| `host_tests.yml` | Linux + Windows host pytest jobs |
| `target_tests.yml` | Hardware tests per board (`target_<chip>` jobs), Windows smoke on `COM4` |
| `canary.yml` | Nightly stub compatibility |
| `deploy_docs.yml` | Docs build and deploy |
| `internal_release.yml` | Internal preview sdist |
| `sync_to_internal.yml` | On each merge to `master`, open/refresh the review MR syncing `master` → `internal/dev_release` (see [Sync to internal](#sync-to-internal)) |

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
3. Normal test jobs (after `canary_prep` via stage order; patched stubs passed as artifacts), with failed tests rerun to separate stub breakage from other failures
4. `canary_record` — save SHA on success
5. `canary_on_failure` (own last stage `canary_report`) — open or update an issue when a job fails

**Failure reporting:** `canary_on_failure` has no `needs:`. A job with `needs:` reacts only to the jobs it lists and is skipped when one of them is skipped, so it would miss test-job failures and every failure that skips `canary_record`. It sits in a stage after `canary_post` because `when: on_failure` ignores failures in its own stage. The script lists the pipeline's failed jobs through the API and picks the issue title from them: a prep job failed (`canary_poll`, `canary_build_stubs`, `canary_patch`), a test job found stub breakage, a test job ran out of time, a test job failed before the comparison, a check-stage install job's script failed (no stub was tested), or `canary_record` failed. The jobs API does not give a job's exit code, so for each test job whose script failed the reporter downloads the outcome that `canary_pytest.py` writes to the artifact `test/canary-outcome.txt` (see below). The body lists every failed job with its failure reason and, for test jobs, that outcome. When the outcome file exists but cannot be downloaded after a retry, the issue gets the "cause not determined" title unless another test job found breakage, because the job may have found stub breakage. When test jobs only hit CI infrastructure problems (timeouts, missing runners, runner errors), the script logs them and opens no issue: those jobs never compared the stubs, and the same SHA is tested again the next night.

**Test failures:** most canary test failures are serial link errors or offline boards, not stub breakage. In the canary, the host and hardware test jobs run [`ci/canary_pytest.py`](../ci/canary_pytest.py) instead of plain pytest:

| Failure | Rerun with fresh stubs | Rerun with committed stubs | Job result | Outcome |
|---|---|---|---|---|
| Random hardware failure | passes | not run | passes | `pass` |
| Board offline, port busy | fails | fails | exit code 75, allowed failure | `not-the-stubs` |
| Stub breakage | fails | passes | fails, reported as stub breakage | `breakage` |
| Tests too slow for the job time (first run or rerun not finished) | not run or not finished | not run | fails, reported as out of time | `no-time` |
| Failed tests too slow to compare | fails | not run, or not finished with no test passed | fails, reported as out of time | `no-time` |
| `before_script` error | not run | not run | fails, reported as failed before the comparison | no file |
| pytest error (exit 2–5), git or JUnit report error | any | any | fails, reported as failed before the comparison | `error` |

Only the failed tests are rerun (`pytest --lf`). The committed stubs are restored with `git checkout`, which takes effect because the jobs install esptool in editable mode. Exit code 75 is listed in `allow_failure:exit_codes`, so it does not trigger `canary_on_failure`; the pipeline ends green with warnings and `canary_record` saves the SHA. `test/report.xml` holds the last run with the fresh stubs; `test/report-first.xml`, `test/report-committed.xml` and `test/canary-outcome.txt` are kept as artifacts.

A job killed by the 1 h job timeout counts as CI infrastructure and is not reported, and the next night would test the same SHA and time out again. `canary_pytest.py` therefore interrupts each pytest run 5 minutes before the job timeout and fails the job with the outcome `no-time`. The interrupt is repeated every 15 s, because one that arrives while a test runs `esptool.main()` in the pytest process only fails that test; pytest is killed after 60 s. When more than 5 tests fail, the rerun with the fresh stubs is skipped; random failures hit 1–3 tests per job. Before the rerun with the committed stubs, the script estimates its time as twice the sum of the failed tests' durations, taking for each test the longer of its durations in the runs with the fresh stubs; when less time is left, the job fails with `no-time` without the comparison. A test that passes with the committed stubs before an interruption still counts as stub breakage.

Known limits:

- A stub bug that breaks communication only sometimes passes the rerun and is not reported.
- A test that fails twice with the fresh stubs for another reason and then passes with the committed stubs (a random failure, a board that comes back) is reported as stub breakage.
- When more than 5 tests fail, a test that fails once at random with the fresh stubs and passes with the committed stubs is reported as stub breakage.
- The `no-time` outcome does not show that the fresh stubs are at fault: slow boards or runners cause it too.
- A job whose `before_script` runs into GitLab's job timeout is still killed by GitLab and only logged.
- The time limits apply only when GitLab sets `CI_JOB_TIMEOUT` and `CI_JOB_STARTED_AT`.

**Quiet nights:** if `LAST_TESTED_STUB_LIB_SHA` is unchanged, `canary_poll` cancels the pipeline before build/tests run. `canary_on_failure` does not run on cancel, so no spurious issues are opened.

**Attribution:** only esp-stub-lib is tracked across runs; esp-flasher-stub is rebuilt from master each night, so a test failure can come from either. Issue titles name neither repository; both SHAs appear in the issue body.

**CI variables:** `STUB_CANARY` (on the schedule, not project-wide), `LAST_TESTED_STUB_LIB_SHA` (auto-created by `canary_record`), `GITLAB_API_TOKEN` (api scope, Maintainer+ — cancel on quiet nights and record SHA), optional `MAINTAINERS`.

## Sync to internal

`open_sync_mr` (in `sync_to_internal.yml`) runs on every push to `master` — i.e. each MR merge. It keeps a single rolling review MR that brings `internal/dev_release` up to `master`:

- **Clean merge** — prepares the `master` → `internal/dev_release` merge on the unprotected `bot/sync-master` branch, then find-or-creates ONE MR into `internal/dev_release` with `$MAINTAINERS` as reviewers, and links it back on the just-merged `master` MR. A maintainer checks the MR's pipeline and merges it — the only write to `internal/dev_release`.
- **Conflict** — no MR is opened (it would only sit unmergeable); the bot comments on the original `master` MR naming the conflicting files with a bounded hunk preview and cc'ing `$MAINTAINERS`.

The bot never merges the sync MR or pushes to `internal/dev_release`. `bot/sync-master` stays unprotected so it never reaches the GitHub mirror. Logic lives in `ci/sync_to_internal.py`; `SYNC_DRY_RUN=1` logs the intended actions without performing them.

**Danger on the sync MR:** the `danger.yml` include is guarded by `include:rules` and skipped on `bot/sync-master`. That pipeline runs under the sync bot's project access token, which can't read the *internal* `shared-ci-dangerjs` project; resolving the cross-project include under it fails config compilation (`config_error`, 0 jobs). The include and its `run-danger-mr-linter` override live together in `danger.yml` so `include:rules` can skip both at once — guarding only the include would leave the override as a scriptless job (its `script` comes from the include), itself a `config_error`. The guard keys on `CI_COMMIT_REF_NAME` (the source branch on both push and merge-request pipelines, and one of the few variables allowed in `include:rules`). The trade-off is that the sync MR's pipeline no longer runs the Danger linter — acceptable, since it only mirrors already-reviewed `master` MRs.

**CI variables:** `GITLAB_API_TOKEN` (api scope; reuses the shared canary token, but every action here — API calls plus the push to the unprotected `bot/sync-master` — needs only the **Developer** role), optional `MAINTAINERS`, optional `SYNC_DRY_RUN`.

## Runners

- `host_test` — Linux Docker
- `esptool-*` — per-board hardware (see `target_tests.yml`)
- `windows-target` — Windows
- `dangerjs`, `build_docs`, `deploy` — specialised jobs
