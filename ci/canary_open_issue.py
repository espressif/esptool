#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""
Open a GitLab issue when the stub canary pipeline detects a regression.

Required environment variables:
  CI_API_V4_URL    - GitLab API base URL (e.g. https://gitlab.com/api/v4)
  CI_PROJECT_ID    - numeric or URL-encoded project id
  CI_PIPELINE_URL  - URL of the failed pipeline (for the issue body)
  CI_PIPELINE_ID   - pipeline id (for the issue title / body)
  GITLAB_API_TOKEN - personal/project/group token with api scope
  MAINTAINERS      - space-separated GitLab usernames (may include leading @)
  STUB_LIB_SHA     - full SHA of the esp-stub-lib commit under test
  FLASHER_STUB_SHA - full SHA of the esp-flasher-stub commit under test
                     (optional; defaults to "unknown" if not propagated)

Note: only esp-stub-lib is tracked across runs; esp-flasher-stub master is
rebuilt every run. The issue title blames esp-stub-lib, but both SHAs are
included in the body so the reader can spot a coincident esp-flasher-stub
change.
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


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
    except (urllib.error.URLError, KeyError, ValueError) as exc:
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
    except (urllib.error.URLError, ValueError) as exc:
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


def main() -> None:
    api_base = _env("CI_API_V4_URL").rstrip("/")
    project_id = urllib.parse.quote(_env("CI_PROJECT_ID"), safe="")
    pipeline_url = _env("CI_PIPELINE_URL")
    pipeline_id = _env("CI_PIPELINE_ID")
    token = _env("GITLAB_API_TOKEN")
    maintainers_raw = os.environ.get("MAINTAINERS", "")
    stub_sha = os.environ.get("STUB_LIB_SHA", "unknown")
    flasher_sha = os.environ.get("FLASHER_STUB_SHA", "unknown")
    canary_phase = os.environ.get("CANARY_PHASE", "unknown")

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

    if canary_phase == "test":
        title = "[stub canary] esp-stub-lib breaks esptool"
        description = (
            f"**Phase:** test\n\n"
            f"The nightly stub canary pipeline detected a regression.\n\n"
            f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
            f"**esp-stub-lib SHA under test:** `{stub_sha}`\n\n"
            f"**esp-flasher-stub SHA under test:** `{flasher_sha}`\n\n"
            f"Please investigate whether the new `esp-stub-lib` master commit "
            f"introduces an incompatibility with `esptool`."
        )
    elif canary_phase == "record":
        title = (
            "[stub canary] Post-test bookkeeping failed — "
            "LAST_TESTED_STUB_LIB_SHA not updated"
        )
        description = (
            "**Phase:** record\n\n"
            "The nightly stub canary ran the test suite successfully but "
            "`canary_record` failed to update `LAST_TESTED_STUB_LIB_SHA`.\n\n"
            "Tests passed — this is not an esp-stub-lib regression. "
            "Without this bookkeeping update, the next nightly will re-run "
            "the same SHA and may re-report the same failure mode if it "
            "persists. Please investigate the GitLab API write path "
            "(token scope/expiry, API availability, project variable "
            "permissions).\n\n"
            f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
            f"**esp-stub-lib SHA that was tested:** `{stub_sha}`\n\n"
            f"**esp-flasher-stub SHA that was tested:** `{flasher_sha}`"
        )
    else:
        # canary_phase == "build" or "unknown" — do not blame esp-stub-lib
        title = "[stub canary] Canary pipeline build/infra failure"
        description = (
            f"**Phase:** {canary_phase}\n\n"
            "The nightly stub canary pipeline failed during the"
            " **build/infrastructure** phase before tests could run."
            " This is likely a canary-infrastructure issue rather than an"
            " esp-stub-lib regression — please investigate the build.\n\n"
            f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
            f"**Attempted esp-stub-lib SHA:** `{stub_sha}`\n\n"
            f"**Attempted esp-flasher-stub SHA:** `{flasher_sha}`"
        )

    if mention_line:
        description += f"\n\n{mention_line}"

    existing = find_open_canary_issue(api_base, project_id, token)
    if existing:
        iid = existing["iid"]
        note_url = f"{api_base}/projects/{project_id}/issues/{iid}/notes"
        if canary_phase == "test":
            note_body = (
                f"**Phase:** test\n\n"
                f"Canary pipeline failed again.\n\n"
                f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
                f"**esp-stub-lib SHA under test:** `{stub_sha}`\n\n"
                f"**esp-flasher-stub SHA under test:** `{flasher_sha}`"
            )
        elif canary_phase == "record":
            note_body = (
                "**Phase:** record\n\n"
                "Post-test bookkeeping failed again — "
                "`LAST_TESTED_STUB_LIB_SHA` was not updated.\n\n"
                f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
                f"**esp-stub-lib SHA that was tested:** `{stub_sha}`\n\n"
                f"**esp-flasher-stub SHA that was tested:** `{flasher_sha}`"
            )
        else:
            note_body = (
                f"**Phase:** {canary_phase}\n\n"
                "Canary pipeline failed again during the"
                " **build/infrastructure** phase.\n\n"
                f"**Failed pipeline:** {pipeline_url} (id: {pipeline_id})\n\n"
                f"**Attempted esp-stub-lib SHA:** `{stub_sha}`\n\n"
                f"**Attempted esp-flasher-stub SHA:** `{flasher_sha}`"
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
        except urllib.error.URLError as exc:
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
    except urllib.error.URLError as exc:
        print(f"ERROR: network error creating issue: {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
