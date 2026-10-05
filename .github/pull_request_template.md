<!-- Follow the contributions guide: https://docs.espressif.com/projects/esptool/en/latest/contributing.html
Write outside the comment markers.
Do not list changed files or functions, and do not restate the diff.
State only facts you verified. -->

## Motivation

<!-- The problem this pull request solves and why it needs solving.
If the change was discussed in an issue, name it, for example #123. -->

## Cause

<!-- A bug fix must state why the bug happens. If you have not confirmed the cause, say that it is a guess.
For other changes, delete the Cause heading and this comment. -->

## Goal

<!-- The behaviour after this change. If the approach is not obvious from the diff, explain why you chose it. -->

## Testing

<!-- The commands you ran, for example `pytest -m host_test`, the operating system, and the chip and board you used, if any.
List only tests that ran. Paste commands and any output as text, not as screenshots.
If you changed chip communication and did not run the hardware tests, say so. -->

## Checklist

- [ ] The maintainers agreed on the goal in an issue, or the contributions guide does not require an issue for this change.
- [ ] The pre-commit hooks are installed and `pre-commit run --all-files` passes.
- [ ] The host tests pass: `pytest -m host_test`, or `pytest -m "host_test and not linux_host_test"` on Windows.
