# Copilot Instructions for esptool

This document provides essential information for coding agents working on the esptool repository to minimize exploration time and avoid common pitfalls.

## Repository Overview

**What esptool does:** esptool is a Python-based, open-source, platform-independent serial utility for flashing, provisioning, and interacting with Espressif SoCs (ESP32, ESP8266, and variants). It provides four main command-line tools:
- `esptool.py` - Main flashing and chip interaction tool
- `espefuse.py` - eFuse (one-time programmable memory) management
- `espsecure.py` - Security-related operations (signing, encryption)
- `esp_rfc2217_server.py` - RFC2217 serial-over-TCP server

**Project type:** Python 3.10+ package with console entry points, using setuptools build system and Click/rich_click for CLI interfaces. Supports ESP32, ESP32-S2, ESP32-S3, ESP32-C2, ESP32-C3, ESP32-C5, ESP32-C6, ESP32-H2, ESP32-H21, ESP32-H4, ESP32-P4, ESP8266, and other Espressif chips.

**Repository size:** ~200 files, primarily Python code with some binary stub flasher files and YAML configuration files.

## Build and Development Setup

### Essential Commands (always run in this order)

1. **Install dependencies:**
   ```bash
   python -m pip install --upgrade pip
   pip install 'setuptools>=64'
   pip install --extra-index-url https://dl.espressif.com/pypi -e .[dev]
   ```
   **Critical:** Always use the extra index URL for Espressif-specific packages. Installation may take 2-3 minutes due to cryptography compilation.

2. **Build the project:**
   ```bash
   python setup.py build
   ```
   This creates build/ directory with compiled Python packages.

3. **Verify installation works:**
   ```bash
   esptool.py --help
   espefuse.py --help
   espsecure.py --help
   esp_rfc2217_server.py --help
   ```

### Testing

**Quick host-based tests (no hardware required, ~2-3 minutes):**
```bash
pytest -m host_test
```
This runs: test_imagegen.py, test_image_info.py, test_mergebin.py, test_modules.py, test_espsecure.py

**HSM tests (requires SoftHSM2 setup):**
```bash
pytest test/test_espsecure_hsm.py
```

**Virtual eFuse tests (safe, no real hardware affected):**
```bash
pytest test_espefuse.py --chip esp32
```

**Hardware tests (requires real ESP devices, NOT safe for CI):**
```bash
pytest test_esptool.py --port /dev/ttyUSB0 --chip esp32 --baud 230400
```

### Code Quality and Pre-commit

**Install pre-commit hooks:**
```bash
pip install pre-commit
pre-commit install -t pre-commit -t commit-msg
```

**Run all checks:**
```bash
pre-commit run --all-files
```

**Individual checks:**
- `python -m ruff check .` - Linting (replaces flake8)
- `python -m ruff format .` - Code formatting (replaces black)
- `python -m mypy esptool/ espefuse/ espsecure/` - Type checking

## Project Architecture and Layout

### Key Directories
- **Root scripts** (`esptool.py`, `espefuse.py`, etc.) - Thin wrapper scripts for backward compatibility
- **`esptool/`** - Main flashing tool package
  - `targets/` - Chip-specific implementations (ESP32, ESP8266, etc.)
  - `targets/stub_flasher/1/` and `targets/stub_flasher/2/` - Binary flasher stubs for each chip (JSON format)
  - `cmds.py` - Command implementations
  - `loader.py` - Core chip communication logic
- **`espefuse/`** - eFuse management tool
  - `efuse/` - Chip-specific eFuse definitions
  - `efuse_defs/` - YAML eFuse definition files
- **`espsecure/`** - Security operations tool
- **`test/`** - Comprehensive test suite
  - `images/` - Test firmware images and binaries
  - `elf2image/` - ELF to image conversion test cases
- **`ci/`** - CI/CD scripts and helpers
- **`docs/`** - Sphinx documentation

### Configuration Files
- **`pyproject.toml`** - Main project configuration (dependencies, build system, tool settings)
- **`.pre-commit-config.yaml`** - Pre-commit hook configuration
- **`.github/workflows/`** - GitHub Actions CI workflows
- **`.gitlab-ci.yml`** - GitLab CI configuration

### Dependencies
**Runtime:** bitstring, cryptography>=43.0.0, pyserial>=3.3, reedsolo, PyYAML, intelhex, rich_click, click<9
**Development:** pyelftools, coverage, pre-commit, pytest, pytest-rerunfailures, requests, czespressif

## Validation and CI/CD

### GitHub Actions Workflows
- **`test_esptool.yml`** - Main test suite (Python 3.10-3.13 matrix, host tests, pre-commit)
- **`build_esptool.yml`** - Build binaries for multiple platforms
- **`dangerjs.yml`** - PR review automation

### Pre-commit Checks (must pass for PR acceptance)
1. **ruff** - Python linting and formatting
2. **mypy** - Type checking (excludes wrapper scripts)
3. **sphinx-lint** - Documentation linting
4. **codespell** - Spell checking
5. **conventional-precommit-linter** - Commit message format validation

### Common Build Issues and Solutions
- **Network timeouts during pip install:** Use `--timeout 300` flag or retry. The Espressif PyPI index (https://dl.espressif.com/pypi) may be slow.
- **Missing cryptography:** Ensure you have build tools installed (`apt-get install build-essential` on Ubuntu)
- **Import errors:** Always install with `-e .[dev]` for development work
- **Test failures on first run:** Some tests download flasher stubs; retry if network issues occur
- **ModuleNotFoundError for rich_click:** Means dependencies aren't installed; run pip install command above
- **SoftHSM2 errors:** For HSM tests, run `./ci/setup_softhsm2.sh` after installing softhsm2 package

## Code Style and Standards

- **Line length:** 88 characters (Black style)
- **Linting:** ruff (configured in pyproject.toml)
- **Formatting:** ruff format (replaces black)
- **Type hints:** mypy checking enabled (partial coverage)
- **Commit messages:** Conventional Commits format required

## Hardware Testing Notes

**NEVER run hardware tests in CI or on unknown devices.** Hardware tests can:
- Erase flash memory permanently
- Modify eFuses (one-time programmable, irreversible)
- Brick devices if interrupted

Only use `test_esptool.py` and `test_esptool_sdm.py` on dedicated test hardware with explicit `--port`, `--chip`, and `--baud` parameters.

## Performance Considerations

- **esptool operations:** Can take 10-60 seconds for large flash operations
- **cryptography compilation:** 2-3 minutes during initial pip install
- **Host tests:** ~2-3 minutes total runtime
- **Build process:** ~30 seconds for clean build

## Environment Variables

esptool recognizes these environment variables for default behavior:
- **`ESPTOOL_CHIP`** - Default chip type (auto, esp32, esp8266, etc.)
- **`ESPTOOL_PORT`** - Default serial port
- **`ESPTOOL_BAUD`** - Default baud rate
- **`ESPTOOL_FF`** - Default flash frequency
- **`ESPTOOL_FM`** - Default flash mode
- **`ESPTOOL_FS`** - Default flash size
- **`ESPTOOL_BEFORE`** - Default reset mode before operation
- **`ESPTOOL_AFTER`** - Default reset mode after operation

For testing:
- **`ESPTOOL_TEST_USB_OTG`** - Enable USB OTG testing mode
- **`ESPTOOL_TEST_FLASH_SIZE`** - Minimum flash size for large flash tests

## Trust These Instructions

These instructions are current as of the repository state and have been validated against the actual build system, CI/CD workflows, and documentation. Only search for additional information if:
1. Commands fail with errors not covered here
2. You need chip-specific information not in the targets/ directory
3. You encounter new hardware or features not documented

For chip-specific behavior, always check `esptool/targets/` directory first before searching elsewhere.