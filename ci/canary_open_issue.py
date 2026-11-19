#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Open or update a GitLab issue when the stub canary pipeline fails.

Required environment variables:
  CI_API_V4_URL    - GitLab API base URL (e.g. https://gitlab.com/api/v4)
  CI_PROJECT_ID    - numeric or URL-encoded project id
  CI_PIPELINE_URL  - URL of the failed pipeline (for the issue body)
  CI_PIPELINE_ID   - pipeline id (for the issue body and the jobs query)
  GITLAB_API_TOKEN - personal/project/group token with api scope
  MAINTAINERS      - space-separated GitLab usernames (may include leading @)
  STUB_LIB_SHA     - full SHA of the esp-stub-lib commit under test
                     (optional; defaults to "unknown" if not propagated)
  FLASHER_STUB_SHA - full SHA of the esp-flasher-stub commit under test
                     (optional; defaults to "unknown" if not propagated)

The kind of failure is derived from the pipeline's failed jobs, read from the
GitLab API. Earlier jobs cannot mark the phase themselves: a dotenv value
written by a job is set before the later jobs have run, so it cannot tell
whether they passed.

The test jobs compare the fresh stubs with the committed ones themselves (see
ci/canary_pytest.py). When the failing tests also fail with the committed
stubs, the job exits with a code listed in its allow_failure:exit_codes, so it
neither triggers this script nor appears among the failed jobs it reads. A
test job can still fail without that comparison: its before_script fails,
pytest does not complete a test run, or the job runs out of time. The jobs API
gives the failure_reason but not the exit code, so this script reads the
outcome that ci/canary_pytest.py writes to an artifact of each failed test
job. Only the outcome OUTCOME_BREAKAGE is reported as stub breakage. An
outcome file that exists but cannot be downloaded leaves the cause unknown,
unless another test job found breakage.

A pipeline whose test jobs only hit CI infrastructure problems is logged
without opening an issue: those jobs never compared the fresh stubs with the
committed ones, so they say nothing about the stubs. A test job killed by
GitLab's job timeout is one of them; ci/canary_pytest.py stops the tests
before that timeout, so a slow stub fails the job with OUTCOME_NO_TIME
instead.

Only esp-stub-lib is tracked across runs; esp-flasher-stub master is rebuilt
every run, so a test failure can come from either repository. Both SHAs are
included in the body.
"""

import http.client
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

from canary_pytest import (
    OUTCOME_BREAKAGE,
    OUTCOME_ERROR,
    OUTCOME_FILE,
    OUTCOME_NO_TIME,
    OUTCOME_NOT_THE_STUBS,
    OUTCOME_PASS,
)

# Values that canary_pytest.py writes. A failed job is not expected to have
# OUTCOME_PASS or OUTCOME_NOT_THE_STUBS, but either can be shown in the body.
KNOWN_OUTCOMES = frozenset(
    {
        OUTCOME_BREAKAGE,
        OUTCOME_ERROR,
        OUTCOME_NO_TIME,
        OUTCOME_NOT_THE_STUBS,
        OUTCOME_PASS,
    }
)
# Key under which main() adds the outcome to each failed test job. It is
# present only for the test jobs whose script failed. Its value is None when
# the job has no outcome file, and OUTCOME_UNREADABLE when the file could not
# be downloaded.
OUTCOME_KEY = "canary_outcome"
# Not written by canary_pytest.py. A download error must not be read as a
# missing file: the job may have found stub breakage.
OUTCOME_UNREADABLE = "unreadable"
# A failed download is retried once, because it is usually a passing API or
# network error.
ARTIFACT_ATTEMPTS = 2

# Jobs that fetch and build the stubs and patch them into the tree.
PREP_JOBS = frozenset({"canary_poll", "canary_build_stubs", "canary_patch"})
RECORD_JOB = "canary_record"
# Only jobs in this stage run esptool against the stubs. The check stage
# installs the package and runs --help, which never loads a stub.
TEST_STAGE = "test"

# urlopen() wraps only connection errors in URLError. A read timeout or a
# dropped connection while waiting for the response raises TimeoutError,
# RemoteDisconnected (both OSError) or IncompleteRead (HTTPException).
API_ERRORS = (OSError, http.client.HTTPException, ValueError)

# GitLab's job failure_reason for a script that exited non-zero. Every other
# reason (timeouts, no matching runner, runner system failures, ...) means the
# job did not get to run its script to the end, so it says nothing about the
# stubs.
SCRIPT_FAILURE = "script_failure"

# Failure categories, in reporting priority: when several apply, the issue
# title follows the first one. The body lists every failed job. CATEGORY_INFRA
# is only logged, so it has no title or explanation. CATEGORY_UNKNOWN also
# applies alone when the failed jobs cannot be listed.
CATEGORY_PREP = "prep"
CATEGORY_TEST = "test"
CATEGORY_UNKNOWN = "unknown"
CATEGORY_TEST_NO_TIME = "test-no-time"
CATEGORY_TEST_ERROR = "test-error"
CATEGORY_CHECK = "check"
CATEGORY_INFRA = "infra"
CATEGORY_RECORD = "record"

TITLES = {
    CATEGORY_PREP: "[stub canary] Canary stub build/infra failure",
    CATEGORY_TEST: "[stub canary] esptool tests fail on freshly built stubs",
    CATEGORY_TEST_NO_TIME: (
        "[stub canary] esptool tests ran out of time before the stub comparison "
        "finished"
    ),
    CATEGORY_TEST_ERROR: "[stub canary] Test jobs failed before comparing the stubs",
    CATEGORY_CHECK: "[stub canary] Install checks failed before the tests ran",
    CATEGORY_RECORD: (
        "[stub canary] Post-test bookkeeping failed — "
        "LAST_TESTED_STUB_LIB_SHA not updated"
    ),
    CATEGORY_UNKNOWN: "[stub canary] Canary pipeline failed (cause not determined)",
}

EXPLANATIONS = {
    CATEGORY_PREP: (
        "A canary preparation job failed before the test suite could run. "
        "This is likely a canary-infrastructure or stub-build problem rather "
        "than an esptool incompatibility. Please investigate the build."
    ),
    CATEGORY_TEST: (
        "At least one esptool test job failed on the stubs built from the "
        "esp-stub-lib and esp-flasher-stub commits below. The job log lists "
        "the tests that failed with these stubs and then passed when rerun "
        "with the stubs committed in esptool. Please check which of the two "
        "repositories introduced the incompatibility."
    ),
    CATEGORY_TEST_NO_TIME: (
        "At least one esptool test job ran out of time while testing the "
        "stubs built from the esp-stub-lib and esp-flasher-stub commits "
        "below. Either its tests did not finish with these stubs, or tests "
        "failed and the rerun with the stubs committed in esptool could not "
        "start or did not finish in time. The comparison was not completed, "
        "so the failure is not confirmed to come from these stubs. Stubs that "
        "slow down or hang flash commands cause the first case; a rerun with "
        "the committed stubs that does not finish points to the board or the "
        "runner. The job log shows which run ran out of time."
    ),
    CATEGORY_TEST_ERROR: (
        "At least one esptool test job failed before it compared the freshly "
        "built stubs with the committed ones: a setup step in `before_script` "
        "failed (package install, SoftHSM setup), pytest did not complete a "
        "test run (collection or internal error, no tests collected), or "
        "`ci/canary_pytest.py` failed. This says nothing about the stubs. "
        "The canary outcome listed with each failed test job shows how far it "
        'got; "no canary outcome file" means that `ci/canary_pytest.py` did '
        "not run or wrote no outcome. Please inspect the job logs."
    ),
    CATEGORY_CHECK: (
        "A job outside the test stage failed in its own script, so the test "
        "suite did not run on the freshly built stubs. These jobs install "
        "esptool and do not load the stubs; the cause is most likely "
        "packaging or a package index outage. Please inspect the failed jobs."
    ),
    CATEGORY_RECORD: (
        "The test suite passed but `canary_record` failed to update "
        "`LAST_TESTED_STUB_LIB_SHA`. This is not a stub regression. Without "
        "this update, the next nightly re-tests the same SHA. Please "
        "investigate the GitLab API write path (token scope/expiry, API "
        "availability, project variable permissions)."
    ),
    CATEGORY_UNKNOWN: (
        "The failed jobs of this pipeline, or the canary outcome of a failed "
        "test job, could not be read from the GitLab API, so the cause is not "
        "known. A test job whose outcome could not be read may have found "
        "stub breakage. Please inspect the pipeline."
    ),
}


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"ERROR: environment variable {name!r} is not set or empty", file=sys.stderr
        )
        sys.exit(1)
    return value


def _api_get(url: str, token: str) -> object:
    req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())


def _api_post(url: str, token: str, data: dict) -> dict:
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            "PRIVATE-TOKEN": token,
            "Content-Type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        result: dict = json.loads(resp.read())
        return result


def resolve_user_id(api_base: str, token: str, username: str) -> int | None:
    """Return the numeric GitLab user id for *username*, or None if not found."""
    username = username.lstrip("@")
    url = f"{api_base}/users?username={urllib.parse.quote(username)}"
    try:
        users = _api_get(url, token)
        if isinstance(users, list) and users:
            return int(users[0]["id"])
        print(
            f"WARNING: GitLab user {username!r} not found — skipping", file=sys.stderr
        )
        return None
    except (*API_ERRORS, KeyError) as exc:
        print(
            f"WARNING: could not resolve user {username!r}: {exc} — skipping",
            file=sys.stderr,
        )
        return None


def find_open_canary_issue(api_base: str, project_id: str, token: str) -> dict | None:
    """Return the most-recently-updated open issue labelled 'stub-canary', if any."""
    url = (
        f"{api_base}/projects/{project_id}/issues"
        "?state=opened&labels=stub-canary&order_by=updated_at&sort=desc&per_page=1"
    )
    try:
        issues = _api_get(url, token)
    except API_ERRORS as exc:
        print(
            f"WARNING: could not query existing canary issues: {exc} — "
            "will attempt to create a new one",
            file=sys.stderr,
        )
        return None
    if isinstance(issues, list) and issues:
        first = issues[0]
        if isinstance(first, dict):
            return first
    return None


def fetch_failed_jobs(
    api_base: str, project_id: str, pipeline_id: str, token: str
) -> list[dict] | None:
    """Return the failed jobs of the pipeline that count as a pipeline failure.

    Retried attempts are excluded (only the latest attempt of each job is
    listed), and so are jobs with ``allow_failure``, matching what
    ``when: on_failure`` reacts to. A job that failed with one of its
    ``allow_failure:exit_codes`` is listed with ``allow_failure`` set too.
    Returns None if the API cannot be read.
    """
    jobs: list[dict] = []
    page = 1
    while True:
        url = (
            f"{api_base}/projects/{project_id}/pipelines/{pipeline_id}/jobs"
            f"?scope[]=failed&per_page=100&page={page}"
        )
        try:
            batch = _api_get(url, token)
        except API_ERRORS as exc:
            print(
                f"WARNING: could not list failed jobs of pipeline {pipeline_id}: {exc}",
                file=sys.stderr,
            )
            return None
        if not isinstance(batch, list):
            print(
                f"WARNING: unexpected response listing failed jobs: {batch!r}",
                file=sys.stderr,
            )
            return None
        jobs.extend(j for j in batch if isinstance(j, dict))
        if len(batch) < 100:
            break
        page += 1
    return [j for j in jobs if not j.get("allow_failure")]


def is_test_script_failure(job: dict) -> bool:
    return job.get("stage") == TEST_STAGE and job.get("failure_reason") == (
        SCRIPT_FAILURE
    )


def fetch_outcome(api_base: str, project_id: str, job: dict, token: str) -> str | None:
    """Return the outcome that canary_pytest.py wrote in the job's artifacts.

    Returns None when the job has no outcome file (its before_script failed
    or the script did not get to write it), and OUTCOME_UNREADABLE when the
    file could not be downloaded.
    """
    url = (
        f"{api_base}/projects/{project_id}/jobs/{job.get('id')}/artifacts/"
        f"{OUTCOME_FILE}"
    )
    req = urllib.request.Request(url, headers={"PRIVATE-TOKEN": token})
    for attempt in range(1, ARTIFACT_ATTEMPTS + 1):
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                outcome: str = resp.read().decode(errors="replace").strip()
            break
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            error = f"HTTP {exc.code}"
        except API_ERRORS as exc:
            error = str(exc)
        print(
            f"WARNING: could not read {OUTCOME_FILE} of job {job.get('name')!r} "
            f"(attempt {attempt} of {ARTIFACT_ATTEMPTS}): {error}",
            file=sys.stderr,
        )
    else:
        return OUTCOME_UNREADABLE
    if outcome not in KNOWN_OUTCOMES:
        print(
            f"WARNING: job {job.get('name')!r} has an unknown canary outcome "
            f"{outcome!r}; it does not count as stub breakage",
            file=sys.stderr,
        )
    return outcome


def classify(failed_jobs: list[dict] | None) -> str:
    """Return the failure category for the given failed jobs.

    A test job's script failure counts as stub breakage only when its
    OUTCOME_KEY is OUTCOME_BREAKAGE.
    """
    if not failed_jobs:
        # None: the API could not be read. Empty: on_failure fired but the
        # API lists no failed job, which should not happen.
        return CATEGORY_UNKNOWN
    names = {j.get("name") for j in failed_jobs}
    if names & PREP_JOBS:
        return CATEGORY_PREP
    others = [j for j in failed_jobs if j.get("name") != RECORD_JOB]
    script_failures = [j for j in others if j.get("failure_reason") == SCRIPT_FAILURE]
    test_outcomes = [j.get(OUTCOME_KEY) for j in others if is_test_script_failure(j)]
    if OUTCOME_BREAKAGE in test_outcomes:
        return CATEGORY_TEST
    # Before no-time: a job whose outcome could not be read may have found
    # breakage, and the no-time text says the failure is not confirmed.
    if OUTCOME_UNREADABLE in test_outcomes:
        return CATEGORY_UNKNOWN
    if OUTCOME_NO_TIME in test_outcomes:
        return CATEGORY_TEST_NO_TIME
    if test_outcomes:
        # No outcome, OUTCOME_ERROR, or a value that a failed job should not
        # have: in each case the job did not complete the comparison.
        return CATEGORY_TEST_ERROR
    if script_failures:
        return CATEGORY_CHECK
    if others:
        return CATEGORY_INFRA
    return CATEGORY_RECORD


def format_failed_jobs(failed_jobs: list[dict] | None) -> str:
    if not failed_jobs:
        return "**Failed jobs:** not available"
    lines = ["**Failed jobs:**", ""]
    for job in sorted(failed_jobs, key=lambda j: (j.get("stage", ""), j["name"])):
        reason = job.get("failure_reason") or "unknown"
        url = job.get("web_url")
        name = f"[`{job['name']}`]({url})" if url else f"`{job['name']}`"
        line = f"- {name} (stage `{job.get('stage', '?')}`): `{reason}`"
        if OUTCOME_KEY in job:
            outcome = job[OUTCOME_KEY]
            if outcome is None:
                line += ", no canary outcome file"
            elif outcome == OUTCOME_UNREADABLE:
                line += (
                    ", canary outcome could not be downloaded "
                    "(see the `canary_on_failure` job log)"
                )
            else:
                line += f", canary outcome `{outcome}`"
        lines.append(line)
    return "\n".join(lines)


def build_body(
    headline: str,
    category: str,
    failed_jobs: list[dict] | None,
    pipeline_url: str,
    pipeline_id: str,
    stub_sha: str,
    flasher_sha: str,
) -> str:
    return (
        f"**Category:** {category}\n\n"
        f"{headline}\n\n"
        f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
        f"{format_failed_jobs(failed_jobs)}\n\n"
        f"**esp-stub-lib SHA:** `{stub_sha}`\n\n"
        f"**esp-flasher-stub SHA:** `{flasher_sha}`"
    )


def main() -> None:
    api_base = _env("CI_API_V4_URL").rstrip("/")
    project_id = urllib.parse.quote(_env("CI_PROJECT_ID"), safe="")
    pipeline_url = _env("CI_PIPELINE_URL")
    pipeline_id = _env("CI_PIPELINE_ID")
    token = _env("GITLAB_API_TOKEN")
    maintainers_raw = os.environ.get("MAINTAINERS", "")
    stub_sha = os.environ.get("STUB_LIB_SHA", "").strip() or "unknown"
    flasher_sha = os.environ.get("FLASHER_STUB_SHA", "").strip() or "unknown"

    failed_jobs = fetch_failed_jobs(api_base, project_id, pipeline_id, token)
    for job in failed_jobs or []:
        if is_test_script_failure(job):
            job[OUTCOME_KEY] = fetch_outcome(api_base, project_id, job, token)
    category = classify(failed_jobs)
    print(f"Failure category: {category}")
    if category == CATEGORY_INFRA:
        print(
            "Test jobs did not complete because of the CI infrastructure "
            "(job timeout, missing runner, runner error). They never compared the "
            "fresh stubs with the committed ones, so no issue is opened. "
            "canary_record did not run, so the same esp-stub-lib SHA is "
            "tested again on the next night."
        )
        print(format_failed_jobs(failed_jobs))
        return

    # Resolve maintainer usernames to numeric ids
    usernames = [u.lstrip("@") for u in maintainers_raw.split() if u.strip()]
    assignee_ids = []
    mention_parts = []
    for username in usernames:
        uid = resolve_user_id(api_base, token, username)
        if uid is not None:
            assignee_ids.append(uid)
            mention_parts.append(f"@{username}")

    mention_line = "Assigned to: " + ", ".join(mention_parts) if mention_parts else ""

    title = TITLES[category]
    description = build_body(
        EXPLANATIONS[category],
        category,
        failed_jobs,
        pipeline_url,
        pipeline_id,
        stub_sha,
        flasher_sha,
    )
    if mention_line:
        description += f"\n\n{mention_line}"

    existing = find_open_canary_issue(api_base, project_id, token)
    if existing:
        iid = existing["iid"]
        note_url = f"{api_base}/projects/{project_id}/issues/{iid}/notes"
        note_body = build_body(
            f"Canary pipeline failed again: {title.removeprefix('[stub canary] ')}.",
            category,
            failed_jobs,
            pipeline_url,
            pipeline_id,
            stub_sha,
            flasher_sha,
        )
        if mention_line:
            note_body += f"\n\n{mention_line}"
        try:
            _api_post(note_url, token, {"body": note_body})
            print(
                f"Commented on existing issue: {existing.get('web_url', '(unknown)')}"
            )
            return
        except urllib.error.HTTPError as exc:
            body = exc.read().decode(errors="replace")
            print(
                f"ERROR: failed to comment on issue {iid} (HTTP {exc.code}): {body}",
                file=sys.stderr,
            )
            sys.exit(1)
        except API_ERRORS as exc:
            print(
                f"ERROR: network error commenting on issue {iid}: {exc}",
                file=sys.stderr,
            )
            sys.exit(1)

    issue_url = f"{api_base}/projects/{project_id}/issues"
    payload: dict = {
        "title": title,
        "description": description,
        "labels": "stub-canary",
    }
    if assignee_ids:
        payload["assignee_ids"] = assignee_ids

    try:
        result = _api_post(issue_url, token, payload)
        print(f"Issue created: {result.get('web_url', '(no URL in response)')}")
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        print(
            f"ERROR: failed to create issue (HTTP {exc.code}): {body}",
            file=sys.stderr,
        )
        sys.exit(1)
    except API_ERRORS as exc:
        print(f"ERROR: network error creating issue: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
