import json

from conftest import need_to_install_package_err

import pytest

import requests

try:
    from esptool.targets import CHIP_DEFS
except ImportError:
    need_to_install_package_err()


FAMILIES_URL = (
    "https://raw.githubusercontent.com/microsoft/uf2/master/utils/uf2families.json"
)


@pytest.fixture(scope="class")
def uf2_json():
    """Download UF2 family IDs from Microsoft UF2 repo and filter out ESP chips"""
    res = requests.get(FAMILIES_URL)
    assert res.status_code == 200
    uf2_families_json = json.loads(res.content)
    # filter out just ESP chips
    chips = [
        chip
        for chip in uf2_families_json
        if chip["short_name"].upper().startswith("ESP")
    ]
    return chips


def test_check_uf2family_ids(uf2_json):
    """Compare UF2 family IDs from Microsoft UF2 repo and with stored values"""
    # check if all UF2 family ids match
    for chip in uf2_json:
        assert int(chip["id"], 0) == CHIP_DEFS[chip["short_name"].lower()].UF2_FAMILY_ID


def test_check_uf2(uf2_json):
    """Check if all non-beta chip definition has UF2 family id in esptool
    and also in Miscrosoft repo
    """
    # remove beta chip definitions
    esptool_chips = set(
        [chip.upper() for chip in CHIP_DEFS.keys() if "beta" not in chip]
    )
    microsoft_repo_chips = set([chip["short_name"] for chip in uf2_json])
    diff = esptool_chips.symmetric_difference(microsoft_repo_chips)
    if diff:
        out = []
        # there was a difference between the chip support
        for chip in diff:
            if chip in esptool_chips:
                out.append(
                    f"Missing chip definition for '{chip}' in esptool "
                    "which was defined in Microsoft UF2 Github repo."
                )
            else:
                out.append(
                    f"Please consider adding support for chip '{chip}' "
                    f"to the UF2 repository: {FAMILIES_URL}"
                )
        pytest.fail("\n".join(out))
