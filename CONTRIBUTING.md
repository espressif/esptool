## Contributing to esptool.py

### Reporting Issues

Please report bugs in esptool.py if you find them. We're glad to get bug reports, they help us make the tool better.

However, before reporting a bug please check through the following:

* [Troubleshooting Section](https://github.com/themadinventor/esptool/#troubleshooting) - common problems and known issues

* [Existing Open Issues](https://github.com/themadinventor/esptool/issues) - someone might have already encountered this.

If you don't find anything, please [open a new issue](https://github.com/themadinventor/esptool/issues/new). Please include the following in your bug report:

* Your operating system and the ESP8266 hardware (board or module) you're using.

* How the ESP8266 is powered/connected, if it's not a well known board or configuration.

* The full command line to esptool.py and the output it produces.

* Any other details that might be needed to reproduce the problem.

### Sending Feature Requests

Feel free to post feature requests. It's helpful if you can explain exactly why the feature would be useful.

There are usually some outstanding feature requests in the [existing issues list](https://github.com/themadinventor/esptool/issues), feel free to add comments to them.

Please be patient with requests and bugs - esptool.py is developed by volunteers and the community, so changes may not happen until someone can volunteer their time.

### Sending Pull Requests

Pull Requests with changes and fixes are also welcome!

Before submitting your pull request, please run the following two commands locally:

```
python setup.py build
python setup.py flake8
```

... to ensure that the changes build and don't cause problems with the [PEP8 style guide](https://www.python.org/dev/peps/pep-0008/) or the [Pyflakes](https://pypi.python.org/pypi/pyflakes) static checker.

The Travis automated build system runs these checks automatically when you submit the PR and will tell you if they fail, but you might as well check beforehand.

In your pull request, please also mention which OS(es) and configurations you have tested with.

### Updating Pull Requests

You may be asked to change things in your pull request before it is merged. When making tweaks to pull requests, please [squash your commits, as described here](http://eli.thegreenplace.net/2014/02/19/squashing-github-pull-requests-into-a-single-commit/).

Squashing commits helps create a clean git history where each commit is a single change. (Having multiple commits in a single Pull Request is fine, but they should all be separate changes - no commits with names like "fix the stuff", please!)
