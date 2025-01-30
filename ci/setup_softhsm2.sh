#!/bin/bash

# Init tokens for tests
softhsm2-util --init-token --label softhsm-test-token --pin 1234 --so-pin 123456 --slot 0
softhsm2-util --init-token --label softhsm-test-token-1 --pin 1234 --so-pin 123456 --slot 1
softhsm2-util --init-token --label softhsm-test-token-2 --pin 1234 --so-pin 123456 --slot 2
softhsm2-util --init-token --label softhsm-test-token-3 --pin 1234 --so-pin 123456 --slot 3
