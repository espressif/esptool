#!/bin/bash

set -euo pipefail
pids=""

for dut in esp32 esp32s2 esp8266; do
    ${CI_PROJECT_DIR}/test/ci/multirun_with_pyenv.sh python ${CI_PROJECT_DIR}/test/test_esptool.py /dev/serial_ports/${dut^^} $dut 115200 &>${CI_PROJECT_DIR}/test/${dut}.out &
    current_pid=$!
    echo "PID of test for chip $dut is $current_pid"
    echo "Output of the proccess $current_pid is redirected to test/${dut}.out"
    pids+=" $current_pid"
done

for p in $pids; do
    if ! wait $p; then
        echo "Test with pid $p failed!"
        exit 1
    fi
done
