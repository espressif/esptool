# Agent Instructions

Follow [CONTRIBUTING.rst](CONTRIBUTING.rst) in every change, commit and description you write. In particular:

- Before you open a pull request, check whether [Before You Start](CONTRIBUTING.rst#before-you-start) requires an issue with the maintainers' agreement.
- Before your first commit, install the hooks as in [Development Setup](CONTRIBUTING.rst#development-setup).
- Before every push, pass the checks in [Code and Tests](CONTRIBUTING.rst#code-and-tests) and [Pre-commit Checks](CONTRIBUTING.rst#pre-commit-checks).
- Write commits as in [Commits](CONTRIBUTING.rst#commits), and pull requests as in [Pull Requests](CONTRIBUTING.rst#pull-requests).
- Before you write a bug report, make sure that the problem was reproduced with the latest code on GitHub, as [Before You Start](CONTRIBUTING.rst#before-you-start) requires.
- Write an issue with the fields of the matching form in [.github/ISSUE_TEMPLATE](.github/ISSUE_TEMPLATE) and follow the instructions in the form. Do not create the issue with `gh issue create` or the GitHub API. They skip the form, so GitHub does not check its required fields or add its label. Give the user the text for each field and the link to the form, for example `https://github.com/espressif/esptool/issues/new?template=bug-report-no-hw.yml`.
- Write a pull request description with the sections of [.github/pull_request_template.md](.github/pull_request_template.md) and follow the instructions in its comments.
- Do not run tests on hardware unless the user names a dedicated development board. The warning in [Code and Tests](CONTRIBUTING.rst#code-and-tests) names those tests.
- Do not create an issue or pull request that breaks a rule of the guide, the issue forms or the pull request template. Tell the user which rules it breaks and what must change.
