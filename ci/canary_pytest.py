#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Run a canary test job and fail it only for tests broken by the fresh stubs.

Usage: python ci/canary_pytest.py <pytest arguments>

Most canary test failures come from the serial link to the test boards or from
offline boards, not from the freshly built stubs. A failure therefore counts
only if the test fails with the fresh stubs and passes with the stubs
committed in esptool:

1. Run pytest with the fresh stubs.
2. Rerun the failed tests (--lf) with the fresh stubs. A test that passes here
   failed at random. Random failures hit at most a few tests per job, so this
   rerun is skipped when more than RANDOM_FAILURE_LIMIT tests failed.
3. Restore the committed stubs and rerun the tests that still fail (--lf).
   A test that passes here is broken by the fresh stubs.

esptool is installed in editable mode, so restoring the files in the stub
directory switches the stubs that the tests load.

A job killed by GitLab's job timeout counts as a CI infrastructure failure and
is not reported, so a stub that makes the tests slow would go unnoticed. Every
pytest run is therefore interrupted TIME_MARGIN_S before the job timeout, and
the job then fails with the outcome OUTCOME_NO_TIME. The exception is an
interrupted step 3 in which a test already passed with the committed stubs:
that counts as OUTCOME_BREAKAGE. Step 3 is estimated to take RUN_TIME_FACTOR
times the durations of the tests it reruns, taking for each test the longer
of its durations in the runs with the fresh stubs (the first run, and the
rerun if there was one). When less time is left, step 3 is not run and the
job fails with OUTCOME_NO_TIME. Both checks use the time left in the job, so
they apply only in CI.

Exit status:
  0   all tests pass with the fresh stubs, at least on the rerun
  1   some test fails with the fresh stubs and passes with the committed
      ones; or the job ran out of time before the comparison finished; also any error
      of this script (git, unreadable JUnit report), which the job log shows
  75  (NOT_THE_STUBS) the failing tests do not pass with the committed stubs
      either; the CI jobs list this code in allow_failure:exit_codes, and
      pytest itself never returns it
  any other: pytest did not complete a test run (usage or internal error,
      collection error, no tests collected); its exit code is passed on

The exit status of a failed job does not reach ci/canary_open_issue.py, so
this script also writes the outcome to OUTCOME_FILE, which the CI jobs keep as
an artifact. It holds one of the OUTCOME_* values below.

JUnit reports: test/report.xml holds the last run with the fresh stubs (the
first run, or the rerun if there was one). test/report-first.xml keeps the
first run when it was rerun; test/report-committed.xml holds the run with the
committed stubs. A run that had to be killed leaves no report.
"""

import datetime
import os
import shutil
import signal
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

STUB_DIR = "esptool/targets/stub_flasher/2/"
REPORT = "test/report.xml"
REPORT_FIRST = "test/report-first.xml"
REPORT_COMMITTED = "test/report-committed.xml"

# Read by ci/canary_open_issue.py from the artifacts of the failed test jobs.
OUTCOME_FILE = "test/canary-outcome.txt"
# All tests pass with the fresh stubs, at least on the rerun.
OUTCOME_PASS = "pass"
# The failing tests fail with the committed stubs too.
OUTCOME_NOT_THE_STUBS = "not-the-stubs"
# Some test fails with the fresh stubs and passes with the committed ones.
OUTCOME_BREAKAGE = "breakage"
# The tests did not finish with the fresh stubs before the job timeout, or the
# rerun of the failed ones with the committed stubs could not start or did not
# finish in time.
OUTCOME_NO_TIME = "no-time"
# pytest did not complete a test run, or this script failed.
OUTCOME_ERROR = "error"

# The replayed canary history had 1-3 random failures per failed target job.
# Rerunning a larger set with the fresh stubs costs time that the job may not
# have, and such a set is far more likely a stub breakage or an offline board.
RANDOM_FAILURE_LIMIT = 5

# A failing test can take less time than the same test passing (an offline
# board fails at once), so the estimate for the committed-stub run doubles the
# durations of the failed tests.
RUN_TIME_FACTOR = 2
# Left for after_script and the artifact upload after the last run.
TIME_MARGIN_S = 300
# How long an interrupted pytest gets to write its JUnit report before it is
# killed. It has to fit in TIME_MARGIN_S.
INTERRUPT_GRACE_S = 60
# A SIGINT that arrives while a test runs esptool.main() or espefuse.main() in
# the pytest process becomes click's Abort and fails only that test, and pytest
# goes on with the next one. The interrupt is therefore repeated after this
# delay. A shorter delay could interrupt pytest while it handles the first
# interrupt and writes the JUnit report, which would lose the report.
INTERRUPT_REPEAT_S = 15

# pytest.ExitCode values; this script does not import pytest so it stays
# independent of the interpreter that runs the tests.
PYTEST_OK = 0
PYTEST_TESTS_FAILED = 1

JOB_FAILED = 1
NOT_THE_STUBS = 75


def run_pytest(
    args: list[str], report: str, deadline: float | None, last_failed: bool = False
) -> tuple[int, bool]:
    """Run pytest and return (exit code, whether it ran out of time).

    *deadline* is a time.monotonic() value, or None for no limit. pytest is
    interrupted at the deadline like Ctrl+C, so it still writes the JUnit
    report for the tests it completed. The interrupt is repeated every
    INTERRUPT_REPEAT_S, and pytest is killed if it has not stopped after
    INTERRUPT_GRACE_S.
    """
    cmd = [sys.executable, "-m", "pytest", *args, f"--junitxml={report}"]
    if last_failed:
        cmd.append("--lf")
    # A killed run writes no report; an old one left in place would be read
    # as the result of this run.
    if os.path.exists(report):
        os.remove(report)
    print(f"=== canary: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(cmd)
    if deadline is None:
        return proc.wait(), False
    try:
        return proc.wait(timeout=max(0.0, deadline - time.monotonic())), False
    except subprocess.TimeoutExpired:
        pass
    print(
        f"=== canary: interrupting pytest {TIME_MARGIN_S} s before the job timeout",
        flush=True,
    )
    kill_at = time.monotonic() + INTERRUPT_GRACE_S
    while True:
        proc.send_signal(signal.SIGINT)
        try:
            proc.wait(timeout=min(INTERRUPT_REPEAT_S, kill_at - time.monotonic()))
            return proc.returncode, True
        except subprocess.TimeoutExpired:
            pass
        if time.monotonic() >= kill_at:
            break
        print("=== canary: pytest still runs; interrupting it again", flush=True)
    print(f"=== canary: pytest still runs after {INTERRUPT_GRACE_S} s; killing")
    proc.kill()
    proc.wait()
    return proc.returncode, True


def read_report(report: str) -> dict[str, tuple[str, float]]:
    """Return {test id: (outcome, seconds)} from a JUnit report.

    The outcome is "failed", "skipped" or "passed". A test that fails in its
    call and errors in teardown has two testcase elements; a failure in
    either counts, and their times add up.
    """
    results: dict[str, tuple[str, float]] = {}
    for case in ET.parse(report).getroot().iter("testcase"):
        test_id = f"{case.get('classname', '')}::{case.get('name', '')}"
        if case.find("failure") is not None or case.find("error") is not None:
            outcome = "failed"
        elif case.find("skipped") is not None:
            outcome = "skipped"
        else:
            outcome = "passed"
        seconds = float(case.get("time") or 0)
        if test_id in results:
            previous, previous_s = results[test_id]
            if previous == "failed":
                outcome = previous
            seconds += previous_s
        results[test_id] = (outcome, seconds)
    return results


def failed_tests(results: dict[str, tuple[str, float]]) -> set[str]:
    return {t for t, (outcome, _) in results.items() if outcome == "failed"}


def seconds_left() -> float | None:
    """Return the seconds left before GitLab kills the job, or None outside CI."""
    timeout = os.environ.get("CI_JOB_TIMEOUT")
    started = os.environ.get("CI_JOB_STARTED_AT")
    if not timeout or not started:
        return None
    # Python 3.10 fromisoformat() does not accept the "Z" suffix GitLab uses.
    start = datetime.datetime.fromisoformat(started.replace("Z", "+00:00"))
    return start.timestamp() + int(timeout) - time.time()


def job_deadline() -> float | None:
    """Return the time.monotonic() value at which the last run has to stop."""
    left = seconds_left()
    if left is None:
        return None
    return time.monotonic() + left - TIME_MARGIN_S


def restore_committed_stubs() -> None:
    # checkout restores the committed files; clean removes stubs built for a
    # chip that has no committed v2 stub, so that chip falls back to v1 as it
    # does outside the canary.
    subprocess.run(["git", "checkout", "HEAD", "--", STUB_DIR], check=True)
    subprocess.run(["git", "clean", "-fq", "--", STUB_DIR], check=True)
    subprocess.run(["git", "status", "--short", "--", STUB_DIR], check=True)


def print_tests(heading: str, tests: set[str]) -> None:
    print(f"=== canary: {heading} ({len(tests)})")
    for test in sorted(tests):
        print(f"  {test}")


def run_canary(args: list[str]) -> tuple[int, str]:
    """Run the steps in the module docstring; return (exit status, outcome)."""
    deadline = job_deadline()
    code, out_of_time = run_pytest(args, REPORT, deadline)
    if out_of_time:
        print("=== canary: the tests did not finish with the fresh stubs in time")
        return JOB_FAILED, OUTCOME_NO_TIME
    if code == PYTEST_OK:
        return code, OUTCOME_PASS
    if code != PYTEST_TESTS_FAILED:
        return code, OUTCOME_ERROR
    results = read_report(REPORT)
    fresh = failed_tests(results)
    if not fresh:
        print("ERROR: pytest reports failures but the JUnit report lists none")
        return JOB_FAILED, OUTCOME_ERROR
    print_tests("failed with the fresh stubs", fresh)

    if len(fresh) <= RANDOM_FAILURE_LIMIT:
        shutil.copyfile(REPORT, REPORT_FIRST)
        code, out_of_time = run_pytest(args, REPORT, deadline, last_failed=True)
        if out_of_time:
            print("=== canary: the rerun with the fresh stubs did not finish in time")
            return JOB_FAILED, OUTCOME_NO_TIME
        if code == PYTEST_OK:
            print("=== canary: the failed tests pass on the rerun; not the stubs")
            return PYTEST_OK, OUTCOME_PASS
        if code != PYTEST_TESTS_FAILED:
            return code, OUTCOME_ERROR
        rerun = read_report(REPORT)
        fresh = failed_tests(rerun)
        if not fresh:
            print("ERROR: pytest reports failures but the JUnit report lists none")
            return JOB_FAILED, OUTCOME_ERROR
        print_tests("failed again on the rerun with the fresh stubs", fresh)
        # A test can fail at once in one run and after its timeouts in the
        # other, so the estimate takes the longer of the two.
        durations = {t: max(results[t][1], rerun[t][1]) for t in fresh}
    else:
        print(
            f"=== canary: more than {RANDOM_FAILURE_LIMIT} tests failed, which "
            "is not a random failure; skipping the rerun with the fresh stubs"
        )
        durations = {t: results[t][1] for t in fresh}

    if deadline is not None:
        left = deadline - time.monotonic()
        needed = sum(durations.values()) * RUN_TIME_FACTOR
        if left < needed:
            print(
                f"=== canary: {left:.0f} s left before the job has to stop, the "
                f"rerun with the committed stubs needs about {needed:.0f} s. "
                "Failing the job without the comparison."
            )
            return JOB_FAILED, OUTCOME_NO_TIME

    restore_committed_stubs()
    code, out_of_time = run_pytest(args, REPORT_COMMITTED, deadline, last_failed=True)
    if out_of_time:
        if not os.path.exists(REPORT_COMMITTED):
            print("=== canary: the rerun with the committed stubs left no report")
            return JOB_FAILED, OUTCOME_NO_TIME
    elif code not in (PYTEST_OK, PYTEST_TESTS_FAILED):
        return code, OUTCOME_ERROR
    # Compare the tests, not the exit code: when some tests fail with both
    # stub sets and others only with the fresh one, the exit code is 1 either
    # way and would hide the breakage. Only a pass counts; a test skipped with
    # the committed stubs says nothing about them. A test that passed before
    # an interruption still counts.
    committed = read_report(REPORT_COMMITTED)
    broken = {t for t in fresh if committed.get(t, ("", 0.0))[0] == "passed"}
    if broken:
        print_tests("pass only with the committed stubs (stub breakage)", broken)
        return JOB_FAILED, OUTCOME_BREAKAGE
    if out_of_time:
        print("=== canary: the rerun with the committed stubs did not finish in time")
        return JOB_FAILED, OUTCOME_NO_TIME
    print_tests("do not pass with the committed stubs either; not the stubs", fresh)
    return NOT_THE_STUBS, OUTCOME_NOT_THE_STUBS


def main(args: list[str]) -> int:
    # An exception (git, unreadable JUnit report) leaves the outcome at error
    # and still shows its traceback.
    outcome = OUTCOME_ERROR
    try:
        code, outcome = run_canary(args)
        return code
    finally:
        print(f"=== canary: outcome {outcome}")
        with open(OUTCOME_FILE, "w") as f:
            f.write(f"{outcome}\n")


if __name__ == "__main__":
    if os.environ.get("STUB_CANARY") != "1":
        sys.exit("ERROR: canary_pytest.py runs only in the stub canary (STUB_CANARY=1)")
    sys.exit(main(sys.argv[1:]))
