#!/usr/bin/env python
#
# SPDX-FileCopyrightText: 2026 Espressif Systems (Shanghai) CO LTD
# SPDX-License-Identifier: GPL-2.0-or-later

"""Keep one open review MR bringing ``internal/dev_release`` up to ``master``.

Runs on every merge to ``master``. A clean merge is staged on the unprotected
branch ``bot/sync-master`` and offered as a review MR (maintainers as reviewers);
a conflict is reported as a comment on the merged ``master`` MR instead. The bot
never writes to ``internal/dev_release`` — only a maintainer merging the review MR
does — so it needs no protected-branch rights.

Stdlib only (urllib + subprocess) to avoid a CI install step, mirroring
ci/canary_open_issue.py. Full design and rationale: .gitlab/README.md.

Environment:
  CI_API_V4_URL, CI_PROJECT_ID, CI_COMMIT_SHA, GITLAB_API_TOKEN  (required)
  MAINTAINERS   space-separated usernames -> MR reviewers / conflict cc  (optional)
  SYNC_DRY_RUN  "1" logs the intended actions and performs none          (optional)
"""

import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

# Lets repeat runs find and edit their own MR body / note in place, so retries
# never post duplicates.
MARKER = "<!-- esptool-internal-sync -->"

# Staging branch is unprotected on purpose: pushing it needs no special rights,
# and an unprotected branch never reaches the GitHub mirror (protected-only).
STAGING_BRANCH = "bot/sync-master"
TARGET_REF = "origin/internal/dev_release"
SOURCE_REF = "origin/master"
TARGET_BRANCH = "internal/dev_release"
SOURCE_BRANCH = "master"

# Keep a wide merge from posting a multi-megabyte note / fanning out into hundreds
# of API calls. Both limits truncate loudly rather than silently.
MAX_PREVIEW_CHARS = 4000
MAX_CARRIED_COMMITS = 50


def _log(message: str) -> None:
    print(message, flush=True)


def _env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        print(
            f"ERROR: environment variable {name!r} is not set or empty", file=sys.stderr
        )
        sys.exit(1)
    return value


# --------------------------------------------------------------------------- #
# GitLab API transport
# --------------------------------------------------------------------------- #


class GitLabAPI:
    """Thin urllib wrapper over the GitLab REST API."""

    def __init__(self, api_base: str, project_id: str, token: str) -> None:
        self.base = api_base.rstrip("/")
        self.pid = urllib.parse.quote(project_id, safe="")
        self.token = token

    # -- low-level ---------------------------------------------------------- #

    def _request(self, method: str, url: str, data: dict | None = None) -> object:
        headers = {"PRIVATE-TOKEN": self.token}
        payload = None
        if data is not None:
            payload = json.dumps(data).encode()
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(url, data=payload, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read()
        return json.loads(body) if body else None

    def _project_url(self, path: str) -> str:
        return f"{self.base}/projects/{self.pid}{path}"

    # -- endpoints used by the bot ----------------------------------------- #

    def user_id(self, username: str) -> int | None:
        """Return the numeric GitLab user id for *username*, or None."""
        username = username.lstrip("@")
        url = f"{self.base}/users?username={urllib.parse.quote(username)}"
        try:
            users = self._request("GET", url)
        except (urllib.error.URLError, ValueError) as exc:
            _log(f"WARNING: could not resolve user {username!r}: {exc} — skipping")
            return None
        if isinstance(users, list) and users and isinstance(users[0], dict):
            try:
                return int(users[0]["id"])
            except (KeyError, ValueError):
                pass
        _log(f"WARNING: GitLab user {username!r} not found — skipping")
        return None

    def commit_merge_requests(self, sha: str) -> list:
        """MRs associated with a commit (GET .../commits/:sha/merge_requests)."""
        url = self._project_url(
            f"/repository/commits/{urllib.parse.quote(sha, safe='')}/merge_requests"
        )
        result = self._request("GET", url)
        return result if isinstance(result, list) else []

    def opened_sync_mr(self) -> dict | None:
        """Return the single open bot/sync-master -> internal MR, if any."""
        query = urllib.parse.urlencode(
            {
                "state": "opened",
                "source_branch": STAGING_BRANCH,
                "target_branch": TARGET_BRANCH,
            }
        )
        result = self._request("GET", self._project_url(f"/merge_requests?{query}"))
        if isinstance(result, list) and result and isinstance(result[0], dict):
            return result[0]
        return None

    def create_mr(self, payload: dict) -> dict:
        result = self._request("POST", self._project_url("/merge_requests"), payload)
        return result if isinstance(result, dict) else {}

    def update_mr(self, iid: int, payload: dict) -> dict:
        result = self._request(
            "PUT", self._project_url(f"/merge_requests/{iid}"), payload
        )
        return result if isinstance(result, dict) else {}

    def mr_notes(self, iid: int) -> list:
        result = self._request("GET", self._project_url(f"/merge_requests/{iid}/notes"))
        return result if isinstance(result, list) else []

    def create_note(self, iid: int, body: str) -> dict:
        result = self._request(
            "POST", self._project_url(f"/merge_requests/{iid}/notes"), {"body": body}
        )
        return result if isinstance(result, dict) else {}

    def update_note(self, iid: int, note_id: int, body: str) -> dict:
        result = self._request(
            "PUT",
            self._project_url(f"/merge_requests/{iid}/notes/{note_id}"),
            {"body": body},
        )
        return result if isinstance(result, dict) else {}


# --------------------------------------------------------------------------- #
# git helpers
# --------------------------------------------------------------------------- #


def _git(args: list, cwd: str | None = None) -> "subprocess.CompletedProcess[str]":
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True)


def run_git(*args: str, cwd: str | None = None) -> str:
    """Run git, raising on non-zero exit. Return stripped stdout."""
    proc = _git(list(args), cwd=cwd)
    if proc.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(args)} failed ({proc.returncode}): {proc.stderr.strip()}"
        )
    return proc.stdout.strip()


def run_git_out(*args: str, cwd: str | None = None) -> str:
    """Run git, returning stdout regardless of exit code."""
    return _git(list(args), cwd=cwd).stdout


def try_sync_merge(
    commit_msg: str,
    *,
    staging: str = STAGING_BRANCH,
    target: str = TARGET_REF,
    source: str = SOURCE_REF,
    cwd: str | None = None,
) -> tuple[int, list, str]:
    """Reset *staging* to *target* and merge *source* with --no-ff.

    Returns ``(rc, conflicts, preview)``: on a clean merge ``rc == 0`` and staging
    carries the merge commit; on a content conflict the conflicting paths and a
    bounded hunk preview are captured before aborting. Using the real merge as the
    probe avoids a separate merge-tree pass (and its Git >=2.38 requirement).

    A non-zero exit with NO unmerged paths is a git error (bad ref, empty range),
    not a conflict, so it is raised rather than turned into a misleading empty
    conflict comment; ``retry`` / ``allow_failure`` then handle it.
    """
    run_git("checkout", "-B", staging, target, cwd=cwd)
    proc = _git(["merge", "--no-ff", "-m", commit_msg, source], cwd=cwd)
    rc = proc.returncode
    if rc == 0:
        return rc, [], ""
    conflicts = run_git_out("diff", "--name-only", "--diff-filter=U", cwd=cwd).split()
    if not conflicts:
        # git error, not a content conflict — abort best-effort (nothing may be in
        # progress) and fail loud instead of posting a "- (unknown)" comment.
        _git(["merge", "--abort"], cwd=cwd)
        raise RuntimeError(
            f"git merge failed with no conflicting paths ({rc}): {proc.stderr.strip()}"
        )
    preview = run_git_out("diff", "--diff-filter=U", cwd=cwd)
    run_git("merge", "--abort", cwd=cwd)
    return rc, conflicts, preview


def carried_commit_shas(
    target: str = TARGET_REF, source: str = SOURCE_REF, cwd: str | None = None
) -> list:
    """SHAs on *source* not yet on *target* (target..source), newest first."""
    out = run_git_out("log", "--format=%H", f"{target}..{source}", cwd=cwd)
    return out.split()


# --------------------------------------------------------------------------- #
# Pure logic (no network, no git)
# --------------------------------------------------------------------------- #


def resolve_maintainers(gl: GitLabAPI, maintainers_raw: str) -> tuple[list, str]:
    """Resolve ``$MAINTAINERS`` usernames to (reviewer_ids, mention_line)."""
    usernames = [u.lstrip("@") for u in maintainers_raw.split() if u.strip()]
    ids: list = []
    mentions: list = []
    for username in usernames:
        uid = gl.user_id(username)
        if uid is not None:
            ids.append(uid)
            mentions.append(f"@{username}")
    mention_line = "cc " + " ".join(mentions) if mentions else ""
    return ids, mention_line


def _mr_summary(mr: dict) -> dict:
    """Normalise a GitLab MR object to the fields the templates need."""
    author = mr.get("author") or {}
    return {
        "iid": mr.get("iid"),
        "title": (mr.get("title") or "").strip(),
        "author": author.get("username", ""),
        "web_url": mr.get("web_url", ""),
    }


def merged_mr_for_commit(gl: GitLabAPI, sha: str) -> dict | None:
    """Return the MR whose merge produced *sha* (author + iid), or None.

    Handles both merge-commit and squash strategies; an empty result means the
    push was a direct push to master (not an MR merge) — the caller then still
    refreshes the sync MR but skips the origin-MR link/comment.

    Only MRs targeting ``master`` count: the endpoint lists *every* MR that
    contains the commit, and because ``bot/sync-master`` merges all of master,
    each carried commit also belongs to the open sync MR — which GitLab returns
    first. Without the target filter that sync MR would shadow the real master
    MR (e.g. list itself instead of the change it carries).
    """
    try:
        mrs = gl.commit_merge_requests(sha)
    except (urllib.error.URLError, ValueError) as exc:
        _log(f"WARNING: could not resolve MR for commit {sha[:8]}: {exc}")
        return None
    for mr in mrs:
        if isinstance(mr, dict) and mr.get("target_branch") == SOURCE_BRANCH:
            return _mr_summary(mr)
    return None


def carried_mrs(gl: GitLabAPI, shas: list) -> list:
    """Resolve carried commit SHAs to unique MR summaries, preserving order.

    Bounded by ``MAX_CARRIED_COMMITS``; truncation is logged, not silent.
    """
    if len(shas) > MAX_CARRIED_COMMITS:
        _log(
            f"NOTE: {len(shas)} carried commits exceed the "
            f"{MAX_CARRIED_COMMITS}-commit resolution cap — "
            "listing MRs for the newest commits only."
        )
        shas = shas[:MAX_CARRIED_COMMITS]
    seen: set = set()
    out: list = []
    for sha in shas:
        mr = merged_mr_for_commit(gl, sha)
        if mr is None or mr["iid"] in seen:
            continue
        seen.add(mr["iid"])
        out.append(mr)
    return out


def bound_preview(preview: str, limit: int = MAX_PREVIEW_CHARS) -> str:
    """Truncate *preview* to *limit* chars with an explicit truncation note."""
    if len(preview) <= limit:
        return preview
    return preview[:limit].rstrip() + "\n… (truncated — see the full diff locally)"


def render_sync_mr_description(mrs: list, base_sha: str, master_sha: str) -> str:
    """Sync-MR description body (flow 1). Always carries the MARKER."""
    lines = [
        MARKER,
        "### Sync `master` → `internal/dev_release`",
        "",
        "Automated review MR. **Please check this MR's pipeline is green, then "
        "merge** — merging is the only step that updates `internal/dev_release`.",
        "",
    ]
    if mrs:
        lines.append("Carries these `master` MRs since the last sync:")
        for mr in mrs:
            title = mr["title"] or "(no title)"
            author = f" (@{mr['author']})" if mr["author"] else ""
            lines.append(f"- !{mr['iid']} — {title}{author}")
    else:
        lines.append(
            "No individual `master` MRs resolved for the carried commits "
            "(direct pushes or squash) — see the commit list in the diff."
        )
    lines += [
        "",
        f"<sub>base `{TARGET_BRANCH}` `{base_sha[:7]}` · "
        f"`{SOURCE_BRANCH}` `{master_sha[:7]}`</sub>",
    ]
    return "\n".join(lines)


def render_link_comment(sync_iid: int) -> str:
    """Comment posted on the just-merged master MR (flow 1)."""
    return (
        f"{MARKER}\n"
        f"🔀 Opened sync MR to bring this into `internal/dev_release`: !{sync_iid}\n"
        "Maintainers have been requested as reviewers; they'll check its "
        "pipeline and merge."
    )


def render_conflict_comment(conflicts: list, preview: str, mention_line: str) -> str:
    """Comment posted on the original master MR (flow 2)."""
    files = "\n".join(f"- `{path}`" for path in conflicts) or "- (unknown)"
    body = [
        MARKER,
        "⚠️ **Merge conflict syncing `master` → `internal/dev_release` — "
        "no MR could be opened.**",
        "",
        "Merging this MR's `master` into `internal/dev_release` conflicts in "
        "files it touched. You have the freshest context — please open the "
        "resolving MR:",
        "`git checkout internal/dev_release && git merge origin/master`, "
        "resolve, push a branch, open an MR.",
        "",
        "Conflicting files:",
        files,
        "",
        "<details><summary>Conflicting hunks (preview)</summary>",
        "",
        "```diff",
        bound_preview(preview).rstrip(),
        "```",
        "</details>",
    ]
    if mention_line:
        body += ["", mention_line]
    return "\n".join(body)


def sync_commit_msg(origin_mr: dict | None) -> str:
    """Merge commit message (matches the manual !976 convention)."""
    msg = "change: merge master into internal/dev_release"
    if origin_mr and origin_mr.get("iid"):
        msg += f"\n\nCarries master MR !{origin_mr['iid']}."
    return msg


# --------------------------------------------------------------------------- #
# Side-effecting orchestration built on the pure helpers above
# --------------------------------------------------------------------------- #


def upsert_marker_note(gl: GitLabAPI, iid: int, body: str) -> None:
    """Post *body* on MR *iid*, or edit our existing marker note in place.

    Keeps ``retry: 2`` and repeated runs from double-pinging the author.
    """
    existing_id = None
    try:
        for note in gl.mr_notes(iid):
            if isinstance(note, dict) and MARKER in (note.get("body") or ""):
                existing_id = note.get("id")
                break
    except (urllib.error.URLError, ValueError) as exc:
        _log(f"WARNING: could not read notes on MR !{iid}: {exc}")
    if existing_id is not None:
        gl.update_note(iid, existing_id, body)
        _log(f"Updated existing sync note on MR !{iid}")
    else:
        gl.create_note(iid, body)
        _log(f"Posted sync note on MR !{iid}")


def find_or_create_sync_mr(gl: GitLabAPI, reviewers: list, description: str) -> dict:
    """Find-or-create the single rolling sync MR; (re)assign reviewers."""
    existing = gl.opened_sync_mr()
    if existing:
        iid = existing["iid"]
        payload: dict = {"description": description}
        if reviewers:
            payload["reviewer_ids"] = reviewers
        gl.update_mr(iid, payload)
        _log(f"Refreshed existing sync MR !{iid}")
        return existing
    payload = {
        "source_branch": STAGING_BRANCH,
        "target_branch": TARGET_BRANCH,
        "title": "Sync master into internal/dev_release",
        "description": description,
        "remove_source_branch": False,
        "squash": False,
    }
    if reviewers:
        payload["reviewer_ids"] = reviewers
    mr = gl.create_mr(payload)
    _log(f"Opened sync MR !{mr.get('iid')} ({mr.get('web_url', '')})")
    return mr


def main() -> None:
    api_base = _env("CI_API_V4_URL")
    project_id = _env("CI_PROJECT_ID")
    token = _env("GITLAB_API_TOKEN")
    sha = _env("CI_COMMIT_SHA")
    maintainers_raw = os.environ.get("MAINTAINERS", "")
    dry = os.environ.get("SYNC_DRY_RUN") == "1"

    gl = GitLabAPI(api_base, project_id, token)

    origin_mr = merged_mr_for_commit(gl, sha)
    if origin_mr is None:
        _log(
            "No origin MR resolved for this push (direct push or squash) — "
            "will refresh the sync MR but skip the origin-MR link/comment."
        )
    reviewers, mention_line = resolve_maintainers(gl, maintainers_raw)

    rc, conflicts, preview = try_sync_merge(sync_commit_msg(origin_mr))

    if rc == 0:
        # FLOW 1 — clean merge: publish the staging branch and open/refresh the
        # single review MR. Nothing is written to internal/dev_release here.
        base_sha = run_git("rev-parse", TARGET_REF)
        master_sha = run_git("rev-parse", SOURCE_REF)
        mrs = carried_mrs(gl, carried_commit_shas())
        description = render_sync_mr_description(mrs, base_sha, master_sha)
        if dry:
            _log("[dry-run] would push bot/sync-master and open/refresh the sync MR")
            _log(description)
            return
        run_git("push", "--force-with-lease", "origin", f"HEAD:{STAGING_BRANCH}")
        mr = find_or_create_sync_mr(gl, reviewers, description)
        if origin_mr and mr.get("iid"):
            upsert_marker_note(gl, origin_mr["iid"], render_link_comment(mr["iid"]))
    else:
        # FLOW 2 — conflict: no MR could be opened; route the original author.
        body = render_conflict_comment(conflicts, preview, mention_line)
        if dry:
            _log("[dry-run] would comment the conflict on the origin MR")
            _log(body)
            return
        if origin_mr and origin_mr.get("iid"):
            upsert_marker_note(gl, origin_mr["iid"], body)
        else:
            _log("Conflict, but no origin MR to comment on — nothing posted.")


if __name__ == "__main__":
    main()
