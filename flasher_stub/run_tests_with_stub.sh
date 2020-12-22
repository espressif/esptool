#!/bin/sh
#
# Run test/test_esptool.py using the newly compiled stub, for quick tests
#
# Usage same as test/test_esptool.py
[ -z $PYTHON ] && PYTHON=python

THISDIR=`realpath -m $(dirname $0)`

export ESPTOOL_PY="${THISDIR}/esptool_test_stub.py"
${PYTHON} ${THISDIR}/../test/test_esptool.py $@
