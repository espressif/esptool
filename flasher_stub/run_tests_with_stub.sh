#!/bin/sh
#
# Run "pytest test/test_esptool.py" using the newly compiled stub, for quick tests
#
# Usage same as "pytest test/test_esptool.py --port <PORT> --chip <CHIP> --baud <BAUD>"

THISDIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

export ESPTOOL_PY="${THISDIR}/esptool_test_stub.py"
pytest ${THISDIR}/../test/test_esptool.py $@
