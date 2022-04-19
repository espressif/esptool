try:
    import coverage

    coverage.process_startup()
except ModuleNotFoundError:
    print("Coverage.py is not installed, skipping code coverage measurement")

# This file exists to perform arbitrary site-specific customizations.
# This script is executed before every Python process to start coverage measurement.
